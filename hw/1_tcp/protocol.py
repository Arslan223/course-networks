import socket
import enum
import time
import logging
import queue
import threading
from threading import Thread

from consts import *


class PacketFlagPos(enum.Enum):
    CWR = 0
    ECE = 1
    URG = 2
    ACK = 3
    PSH = 4
    RST = 5
    SYN = 6
    FIN = 7


def get_flag_repr(val, pos):
    return val * (1 << pos)


def get_flag_var(payload, pos):
    return (payload & (1 << pos)) != 0


def wait_timeout(val: float):
    time.sleep(val * TIMEOUT_WAIT_COEFFICIENT)


class PacketFlags:
    def __init__(self, cwr=0, ece=0, urg=0, ack=0, psh=0, rst=0, syn=0, fin=0):
        self.cwr = cwr
        self.ece = ece
        self.urg = urg
        self.ack = ack
        self.psh = psh
        self.rst = rst
        self.syn = syn
        self.fin = fin

    def payload(self):
        return sum((
            get_flag_repr(self.cwr, PacketFlagPos.CWR.value),
            get_flag_repr(self.ece, PacketFlagPos.ECE.value),
            get_flag_repr(self.urg, PacketFlagPos.URG.value),
            get_flag_repr(self.ack, PacketFlagPos.ACK.value),
            get_flag_repr(self.psh, PacketFlagPos.PSH.value),
            get_flag_repr(self.rst, PacketFlagPos.RST.value),
            get_flag_repr(self.syn, PacketFlagPos.SYN.value),
            get_flag_repr(self.fin, PacketFlagPos.FIN.value)
        ))

    @staticmethod
    def from_payload(payload):
        return PacketFlags(
            cwr=get_flag_var(payload, PacketFlagPos.CWR.value),
            ece=get_flag_var(payload, PacketFlagPos.ECE.value),
            urg=get_flag_var(payload, PacketFlagPos.URG.value),
            ack=get_flag_var(payload, PacketFlagPos.ACK.value),
            psh=get_flag_var(payload, PacketFlagPos.PSH.value),
            rst=get_flag_var(payload, PacketFlagPos.RST.value),
            syn=get_flag_var(payload, PacketFlagPos.SYN.value),
            fin=get_flag_var(payload, PacketFlagPos.FIN.value)
        )


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg

    def close(self):
        self.udp_socket.close()


class TCPPacket:
    def __init__(
            self,
            data: bytes,
            seq: int,
            ack: int,
            flags: PacketFlags = PacketFlags.from_payload(0),
            window: int = 0
    ):
        self.seq = seq
        self.ack = ack
        self.flags = flags
        self.window = window
        self.data = data
        self.timestamp = time.time()

    def header(self):
        return (
                self.seq.to_bytes(4, "big") +
                self.ack.to_bytes(4, "big") +
                self.flags.payload().to_bytes(2, "big") +
                self.window.to_bytes(2, "big")
        )

    def payload(self):
        return self.header() + self.data

    def update_timestamp(self):
        self.timestamp = time.time()

    @staticmethod
    def from_payload(payload):
        return TCPPacket(
            data=payload[12:],
            seq=int.from_bytes(payload[:4], "big"),
            ack=int.from_bytes(payload[4:8], "big"),
            flags=PacketFlags.from_payload(int.from_bytes(payload[8:10], "big")),
            window=int.from_bytes(payload[10:12], "big")
        )

    def __lt__(self, other):
        return self.seq < other.seq

    def __eq__(self, other):
        return self.seq == other.seq


class MyTCPProtocol(UDPBasedProtocol):
    srtt = None
    rttvar = None
    rto = 0.01

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.logger = logging.getLogger(f"MyTCPProtocol #{id(self)}")

        self.send_base = 0  # oldest unacknowledged sequence number
        self.next_seq_num = 0  # next sequence number to send
        self.ack = 0  # next expected sequence number to receive
        self.window = 2 ** 15

        self._last_rtt = None
        self.is_active = True

        self.packet_queue = queue.PriorityQueue()
        self.unacked_packets = {}  # {seq_num: (packet, timestamp)}
        self.send_lock = threading.Lock()

        self.watchdog_thread = Thread(target=self.receive_watchdog)
        self.watchdog_thread.daemon = True
        self.watchdog_thread.start()

    def update_rto(self, rtt: float):
        is_first = (self._last_rtt is None)
        self._last_rtt = rtt
        if is_first:
            self.srtt = rtt
            self.rttvar = rtt / 2
        else:
            self.rttvar = ((1 - BETA) * self.rttvar) + (BETA * abs(self.srtt - rtt))
            self.srtt = ((1 - ALPHA) * self.srtt) + (ALPHA * rtt)

        self.rto = self.srtt + max(G, K * self.rttvar)
        # self.rto = 0.000001
        return self.rto

    def receive_watchdog(self):
        while self.is_active:
            data = self.recvfrom(MTU_SIZE)
            packet = TCPPacket.from_payload(data)

            if packet.flags.ack:
                with self.send_lock:
                    ack_num = packet.ack
                    if ack_num > self.send_base:
                        self.send_base = ack_num
                    # remove acknowledged packets
                    to_delete = []
                    for seq in list(self.unacked_packets.keys()):
                        pkt, sent_time = self.unacked_packets[seq]
                        if seq + len(pkt.data) <= ack_num:
                            rtt = time.time() - sent_time
                            self.update_rto(rtt)
                            to_delete.append(seq)
                            self.logger.info(f"ACK received for seq {seq}")
                    for seq in to_delete:
                        del self.unacked_packets[seq]
                continue

            if packet.flags.fin:
                self.logger.info("Received FIN. Closing connection.")
                self.is_active = False
                break

            if packet.flags.rst:
                self.logger.critical("Received RST!!! Closing connection.")
                self.is_active = False
                break

            if packet.seq == self.ack:
                self.ack += len(packet.data)
                self.packet_queue.put(packet)

                self.sendto(TCPPacket(
                    data=bytes(),
                    seq=self.next_seq_num,
                    ack=self.ack,
                    flags=PacketFlags(ack=1)
                ).payload())
            elif packet.seq < self.ack:
                # duplicate packet
                self.sendto(TCPPacket(
                    data=bytes(),
                    seq=self.next_seq_num,
                    ack=self.ack,
                    flags=PacketFlags(ack=1)
                ).payload())
            else:
                # strange packet, ignore
                self.sendto(TCPPacket(
                    data=bytes(),
                    seq=self.next_seq_num,
                    ack=self.ack,
                    flags=PacketFlags(ack=1)
                ).payload())

    @staticmethod
    def get_chunks(data: bytes, size: int):
        for i in range(0, len(data), size):
            yield data[i:i + min(size, len(data) - i)]

    def send(self, data: bytes):
        data_offset = 0
        data_length = len(data)
        while data_offset < data_length or len(self.unacked_packets) > 0:
            with self.send_lock:
                while data_offset < data_length and self.next_seq_num - self.send_base < self.window:
                    chunk = data[data_offset:data_offset + MSS_SIZE]
                    packet = TCPPacket(
                        data=chunk,
                        seq=self.next_seq_num,
                        ack=self.ack,
                        window=self.window
                    )
                    self.unacked_packets[self.next_seq_num] = (packet, time.time())
                    self.sendto(packet.payload())
                    data_offset += len(chunk)
                    self.next_seq_num += len(chunk)
            # retransmissions
            with self.send_lock:
                current_time = time.time()
                for seq, (packet, timestamp) in list(self.unacked_packets.items()):
                    if current_time - timestamp >= self.rto:
                        # timeout
                        self.sendto(packet.payload())
                        self.unacked_packets[seq] = (packet, current_time)
            time.sleep(0.0001)
        return data_length

    def recv(self, n: int):
        chunks = bytes()
        byte_counter = 0

        while byte_counter < n:
            current_packet = self.packet_queue.get()
            byte_counter += len(current_packet.data)

            if byte_counter > n:
                self.packet_queue.put(current_packet)
                break

            chunks += current_packet.data
        return chunks

    def close(self):
        self.sendto(TCPPacket(
            data=bytes(),
            seq=self.next_seq_num,
            ack=self.ack,
            flags=PacketFlags(fin=1)
        ).payload())
        self.is_active = False

        super().close()
