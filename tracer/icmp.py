import socket
import struct

class ICMPPacket:
    def __init__(self, pid, seq,packet_size):
        self.pid = pid
        self.seq = seq
        self.packet_size = packet_size

    def _calculate_checksum(self, data):
        # rfc 1071
        s = 0
        for i in range(0, len(data) - 1, 2):
            s += (data[i] << 8) + data[i + 1]
        if len(data) % 2:
            s += data[-1] << 8
        s = (s >> 16) + (s & 0xffff)
        s += (s >> 16)
        return socket.htons(~s & 0xffff)

    def create_request(self):
        payload_size = self.packet_size - 8
        if payload_size < 0:
            payload_size = 0
        payload = b"Z" * payload_size
        hdr = struct.pack("BBHHH", 8, 0, 0, self.pid, self.seq)
        hdr = struct.pack("BBHHH", 8, 0, self._calculate_checksum(hdr + payload), self.pid, self.seq)
        return hdr + payload

    def verify_reply(self, raw_data):
        if len(raw_data) < 28:
            return False
        type = raw_data[20]
        if type == 0:
            got_pid = struct.unpack("H", raw_data[24:26])[0]
            got_seq = struct.unpack("H", raw_data[26:28])[0]
            return got_pid == self.pid and got_seq == self.seq
        if type == 11:
            if len(raw_data) < 56:
                return False
            got_pid = struct.unpack("H", raw_data[52:54])[0]
            got_seq = struct.unpack("H", raw_data[54:56])[0]
            return got_pid == self.pid and got_seq == self.seq
        return False