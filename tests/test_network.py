import unittest
from unittest.mock import patch
from tracer.network import IPUtils, WhoisClient


class TestNetwork(unittest.TestCase):
    """Тесты для проверки IP-адресов и ответов WHOIS."""

    def test_is_local_private(self):
        """Проверка определения серых и локальных IP-адресов."""
        self.assertTrue(IPUtils.is_local("192.168.1.1"))
        self.assertTrue(IPUtils.is_local("10.0.0.1"))
        self.assertTrue(IPUtils.is_local("127.0.0.1"))

    def test_is_local_public(self):
        """Проверка того, что белые адреса не локальные."""
        self.assertFalse(IPUtils.is_local("8.8.8.8"))
        self.assertFalse(IPUtils.is_local("142.250.190.46"))

    @patch('tracer.network.socket.socket')
    def test_whois_client_success(self, mock_socket_cls):
        """Проверка парсинга полей при успешном ответе."""
        mock_socket = mock_socket_cls.return_value
        mock_socket.recv.side_effect = [
            b"refer: whois.ripe.net\n", b"",
            b"netname: MY-NET\norigin: AS999\ncountry: RU\n", b""
        ]
        client = WhoisClient()
        netname, asn, country = client.get_info("8.8.8.8")
        self.assertEqual(netname, "MY-NET")
        self.assertEqual(asn, "999")
        self.assertEqual(country, "RU")

    @patch('tracer.network.socket.socket')
    def test_whois_client_exception(self, mock_socket_cls):
        """Проверка работы WHOIS клиента при сбое сети."""
        mock_socket_cls.side_effect = Exception
        client = WhoisClient()
        netname, asn, country = client.get_info("8.8.8.8")
        self.assertIsNone(netname)
        self.assertIsNone(asn)
        self.assertIsNone(country)


if __name__ == "__main__":
    unittest.main()
