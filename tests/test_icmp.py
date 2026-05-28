import unittest
import struct
from tracer.icmp import ICMPPacket

class TestIcmp(unittest.TestCase):
    """Тесты для проверки сборки, расчета чексуммы и валидации ICMP пакетов."""

    def test_icmp_packet_init(self):
        """Проверка, что переданные параметры правильно сохраняются при создании объекта."""
        packet = ICMPPacket(pid=1234, seq=5, packet_size=60)
        self.assertEqual(packet.pid, 1234)
        self.assertEqual(packet.seq, 5)
        self.assertEqual(packet.packet_size, 60)

    def test_icmp_packet_create_request_size(self):
        """Проверка сборки пакетов под разные размеры, включая слишком маленькие."""
        packet40 = ICMPPacket(pid=1, seq=1, packet_size=40)
        self.assertEqual(len(packet40.create_request()), 40)

        packet64 = ICMPPacket(pid=1, seq=1, packet_size=64)
        self.assertEqual(len(packet64.create_request()), 64)

        packet_small = ICMPPacket(pid=1, seq=1, packet_size=4)
        self.assertEqual(len(packet_small.create_request()), 8)

    def test_checksum_calculation(self):
        """Проверка ручного расчета контрольной суммы для четного и нечетного количества байт."""
        packet = ICMPPacket(pid=1, seq=1, packet_size=40)
        data_even = b"\x08\x00\x00\x00\x00\x01\x00\x01"
        data_odd = b"\x08\x00\x00\x00\x00\x01\x00\x01\x00"
        self.assertIsInstance(packet._calculate_checksum(data_even), int)
        self.assertIsInstance(packet._calculate_checksum(data_odd), int)

    def test_verify_reply_short_data(self):
        """Проверка, что слишком короткие пакеты из сети сразу отбрасываются."""
        packet = ICMPPacket(pid=1234, seq=5, packet_size=40)
        self.assertFalse(packet.verify_reply(b"\x00" * 20))

    def test_verify_reply_type_0_success(self):
        """Проверка успешного распознавания эхо-ответа (тип 0) с правильными PID и seq."""
        packet = ICMPPacket(pid=1234, seq=5, packet_size=40)
        raw = bytearray(30)
        raw[20] = 0
        raw[24:26] = struct.pack("H", 1234)
        raw[26:28] = struct.pack("H", 5)
        self.assertTrue(packet.verify_reply(bytes(raw)))

    def test_verify_reply_type_0_invalid(self):
        """Проверка отбрасывания пакета типа 0, если у него чужой или неверный PID."""
        packet = ICMPPacket(pid=1234, seq=5, packet_size=40)
        raw = bytearray(30)
        raw[20] = 0
        raw[24:26] = struct.pack("H", 9999)
        raw[26:28] = struct.pack("H", 5)
        self.assertFalse(packet.verify_reply(bytes(raw)))

    def test_verify_reply_type_11_success(self):
        """Проверка распознавания ответа об истечении времени TTL (тип 11) с нашими данными."""
        packet = ICMPPacket(pid=1234, seq=5, packet_size=40)
        raw = bytearray(60)
        raw[20] = 11
        raw[52:54] = struct.pack("H", 1234)
        raw[54:56] = struct.pack("H", 5)
        self.assertTrue(packet.verify_reply(bytes(raw)))

    def test_verify_reply_type_11_short(self):
        """Проверка, что пакет типа 11 отклоняется, если его размер меньше 56 байт."""
        packet = ICMPPacket(pid=1234, seq=5, packet_size=40)
        raw = bytearray(40)
        raw[20] = 11
        self.assertFalse(packet.verify_reply(bytes(raw)))

    def test_verify_reply_unknown_type(self):
        """Проверка, что пакеты со всеми остальными типами ICMP возвращают False."""
        packet = ICMPPacket(pid=1234, seq=5, packet_size=40)
        raw = bytearray(30)
        raw[20] = 3
        self.assertFalse(packet.verify_reply(bytes(raw)))

if __name__ == "__main__":
    unittest.main()