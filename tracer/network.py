import socket
import re

class IPUtils:
    @staticmethod
    def is_local(ip):
        # rfc 1918
        if ip.startswith("127.") or ip.startswith("10."):
            return True
        if ip.startswith("192.168.") or ip.startswith("169.254."):
            return True
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172":
            try:
                if 16 <= int(parts[1]) <= 31:
                    return True
            except ValueError:
                pass
        return False

class WhoisClient:
    def _query_server(self, server, query):
        # rfc 3912
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((server, 43))
            s.send((query + "\r\n").encode())
            otvet = b""
            while True:
                kusok = s.recv(4096)
                if not kusok:
                    break
                otvet += kusok
            s.close()
            return otvet.decode(errors="ignore")
        except Exception:
            return ""

    def get_info(self, ip):
        text = self._query_server("whois.iana.org", ip)
        m = re.search(r"refer:\s*(\S+)", text, re.I)
        server = m.group(1) if m else "whois.ripe.net"

        text = self._query_server(server, ip)

        ref = re.search(r"ReferralServer:\s*whois://(\S+)", text, re.I)
        if ref:
            tmp = self._query_server(ref.group(1), ip)
            if tmp:
                text = tmp

        nazvanie = nomer_as = country = None

        m = re.search(r"netname:\s*(.+)", text, re.I)
        if m:
            nazvanie = m.group(1).strip()

        for pattern in [r"origin:\s*AS(\d+)", r"OriginAS:\s*AS(\d+)", r"OriginAS:\s*(\d+)"]:
            m = re.search(pattern, text, re.I)
            if m:
                nomer_as = m.group(1)
                break

        m = re.search(r"country:\s*([A-Za-z]{2})", text, re.I)
        if m:
            country = m.group(1).upper()

        return nazvanie, nomer_as, country