import unittest
from unittest.mock import patch
from tracer.network import IPUtils
from tracer.icmp import ICMPPacket
from tracer.core import Tracer

class TestTracerComponents(unittest.TestCase):
    def test_is_local_private(self):
        self.assertTrue(IPUtils.is_local("192.168.1.1"))
        self.assertTrue(IPUtils.is_local("10.0.0.1"))
        self.assertTrue(IPUtils.is_local("127.0.0.1"))

    def test_is_local_public(self):
        self.assertFalse(IPUtils.is_local("8.8.8.8"))
        self.assertFalse(IPUtils.is_local("142.250.190.46"))

    def test_icmp_packet_init(self):
        packet = ICMPPacket(pid=1234, seq=5, packet_size=60)
        self.assertEqual(packet.pid, 1234)
        self.assertEqual(packet.seq, 5)
        self.assertEqual(packet.packet_size, 60)

    def test_icmp_packet_create_request_size(self):
        packet40 = ICMPPacket(pid=1, seq=1, packet_size=40)
        self.assertEqual(len(packet40.create_request()), 40)

        packet64 = ICMPPacket(pid=1, seq=1, packet_size=64)
        self.assertEqual(len(packet64.create_request()), 64)

        packet_small = ICMPPacket(pid=1, seq=1, packet_size=4)
        self.assertEqual(len(packet_small.create_request()), 8)

    @patch('socket.gethostbyname')
    def test_tracer_init_params(self, mock_gethostbyname):
        mock_gethostbyname.return_value = "127.0.0.1"
        tracer = Tracer(
            target_addr="localhost",
            max_ttl=15,
            timeout=2,
            num_attempts=5,
            interval=4,
            packet_size=50
        )
        self.assertEqual(tracer.max_ttl, 15)
        self.assertEqual(tracer.timeout, 2)
        self.assertEqual(tracer.num_attempts, 5)
        self.assertEqual(tracer.interval, 4)
        self.assertEqual(tracer.packet_size, 50)

if __name__ == "__main__":
    unittest.main()