import os
import socket
import struct
import unittest
from unittest.mock import patch
from tracer.core import Tracer


class TestCore(unittest.TestCase):
    """Тесты для проверки главного класса Tracer."""

    @patch('tracer.core.socket.gethostbyname')
    @patch('tracer.core.socket.socket')
    @patch('tracer.core.select.select')
    def test_tracer_run_timeout(self, mock_select, mock_socket_cls,
                                mock_gethostbyname):
        """Проверка работы программы при таймауте ответа сети."""
        mock_gethostbyname.return_value = "127.0.0.1"
        _ = mock_socket_cls.return_value
        mock_select.return_value = ([], [], [])
        tracer = Tracer("localhost", max_ttl=1, num_attempts=1)
        tracer.run()

    @patch('tracer.core.socket.gethostbyname')
    def test_tracer_init_gaierror(self, mock_gethostbyname):
        """Проверка обработки ошибки несуществующего домена."""
        mock_gethostbyname.side_effect = socket.gaierror
        with self.assertRaises(SystemExit):
            Tracer("invalid_host_name_example")

    @patch('tracer.core.socket.gethostbyname')
    @patch('tracer.core.socket.socket')
    def test_tracer_run_permission_error(self, mock_socket,
                                         mock_gethostbyname):
        """Проверка падения программы при запуске без sudo."""
        mock_gethostbyname.return_value = "127.0.0.1"
        mock_socket.side_effect = PermissionError
        tracer = Tracer("localhost", max_ttl=1)
        with self.assertRaises(SystemExit):
            tracer.run()

    @patch('tracer.core.socket.gethostbyname')
    @patch('tracer.core.socket.socket')
    @patch('tracer.core.select.select')
    def test_tracer_run_recv_exception(self, mock_select,
                                       mock_socket_cls,
                                       mock_gethostbyname):
        """Проверка обработки исключений сокета."""
        mock_gethostbyname.return_value = "127.0.0.1"
        mock_socket = mock_socket_cls.return_value
        mock_select.return_value = ([mock_socket], [], [])
        mock_socket.recvfrom.side_effect = Exception
        tracer = Tracer("localhost", max_ttl=1, num_attempts=1)
        tracer.run()

    @patch('tracer.core.socket.gethostbyname')
    @patch('tracer.core.socket.socket')
    @patch('tracer.core.select.select')
    @patch('tracer.core.WhoisClient')
    def test_tracer_run_public_ip_success(self, mock_whois_cls,
                                          mock_select, mock_socket_cls,
                                          mock_gethostbyname):
        """Проверка хопа для внешнего IP с получением WHOIS."""
        mock_gethostbyname.return_value = "8.8.8.8"
        mock_socket = mock_socket_cls.return_value
        mock_whois = mock_whois_cls.return_value
        mock_whois.get_info.return_value = (
            "NETNAME_TEST", "AS12345", "US"
        )
        pid = os.getpid() & 0xFFFF
        raw_reply = bytearray(60)
        raw_reply[20] = 0
        raw_reply[24:26] = struct.pack("H", pid)
        raw_reply[26:28] = struct.pack("H", 100)
        mock_socket.recvfrom.return_value = (
            bytes(raw_reply), ("8.8.8.8", 0)
        )
        mock_select.return_value = ([mock_socket], [], [])
        tracer = Tracer("8.8.8.8", max_ttl=1, num_attempts=1)
        tracer.run()


if __name__ == "__main__":
    unittest.main()
