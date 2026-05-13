import os
import sys
import time
import select
import socket
from .icmp import ICMPPacket
from .network import IPUtils, WhoisClient


class Tracer:
    def __init__(self, target_addr):
        self.target_addr = target_addr
        try:
            self.dest_ip = socket.gethostbyname(target_addr)
        except socket.gaierror:
            print(target_addr + " is invalid")
            sys.exit(1)

        self.pid = os.getpid() & 0xFFFF
        self.whois_client = WhoisClient()

    def _get_hop(self, sock, ttl):
        ip = None
        for attempt in range(3):
            seq = ttl * 100 + attempt
            packet = ICMPPacket(self.pid, seq)

            sock.sendto(packet.create_request(), (self.dest_ip, 0))
            deadline = time.time() + 3

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
        return ip

    def run(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            print("Недостаточно прав. Запустите от имени администратора или через sudo")
            sys.exit(1)

        for ttl in range(1, 31):
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
                nazvanie, nomer_as, country = self.whois_client.get_info(ip)
                stroka = ""
                if nazvanie:
                    stroka = nazvanie
                if nomer_as:
                    stroka = stroka + ", " + nomer_as if stroka else nomer_as
                if country:
                    stroka = stroka + ", " + country if stroka else country
                if stroka:
                    print(stroka)

            print()
            sys.stdout.flush()

            if ip == self.dest_ip:
                break

        sock.close()