import os
import sys
import time
import select
import socket
from .icmp import ICMPPacket
from .network import IPUtils, WhoisClient


class Tracer:
    """Класс для управления процессом трассировки маршрута."""

    def __init__(self, target_addr, max_ttl=30, timeout=3,
                 num_attempts=3, interval=1, packet_size=40):
        """Инициализация настроек трассировки."""
        self.target_addr = target_addr
        self.max_ttl = max_ttl
        self.timeout = timeout
        self.num_attempts = num_attempts
        self.interval = interval
        self.packet_size = packet_size
        try:
            self.dest_ip = socket.gethostbyname(target_addr)
        except socket.gaierror:
            print(target_addr + " is invalid")
            sys.exit(1)

        self.pid = os.getpid() & 0xFFFF
        self.whois_client = WhoisClient()

    def _get_hop(self, sock, ttl):
        """Отправка ICMP запросов для одного хопа."""
        ip = None
        for attempt in range(self.num_attempts):
            seq = ttl * 100 + attempt
            packet = ICMPPacket(
                self.pid, seq, packet_size=self.packet_size
            )

            sock.sendto(packet.create_request(), (self.dest_ip, 0))
            deadline = time.time() + self.timeout

            while time.time() < deadline:
                left = deadline - time.time()
                if left <= 0:
                    break
                if not select.select([sock], [], [], left)[0]:
                    break
                try:
                    raw, addr = sock.recvfrom(1024)
                except Exception:
                    break
                if packet.verify_reply(raw):
                    ip = addr[0]
                    break
            if ip:
                break
            if attempt < self.num_attempts - 1 and self.interval > 0:
                time.sleep(self.interval)
        return ip

    def run(self):
        """Запуск основного цикла трассировки."""
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
            )
        except PermissionError:
            print("Недостаточно прав. Запустите через sudo")
            sys.exit(1)

        for ttl in range(1, self.max_ttl + 1):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            ip = self._get_hop(sock, ttl)

            if ip is None:
                print(str(ttl) + ". *")
                print()
                sys.stdout.flush()
                continue

            print(str(ttl) + ". " + ip)
            sys.stdout.flush()

            if IPUtils.is_local(ip):
                print("local")
            else:
                nazvanie, nomer_as, country = (
                    self.whois_client.get_info(ip)
                )
                stroka = ""
                if nazvanie:
                    stroka = nazvanie
                if nomer_as:
                    stroka = (
                        stroka + ", " + nomer_as if stroka
                        else nomer_as
                    )
                if country:
                    stroka = (
                        stroka + ", " + country if stroka
                        else country
                    )
                if stroka:
                    print(stroka)

            print()
            sys.stdout.flush()

            if ip == self.dest_ip:
                break

        sock.close()
