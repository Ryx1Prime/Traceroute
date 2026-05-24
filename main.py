import sys
from tracer.core import Tracer

import sys
import argparse
from tracer.core import Tracer


def main():
    parser = argparse.ArgumentParser(description="TRACEROUTE с поддержкой WHOIS")
    parser.add_argument("address", help="домен или IP-адрес (например, vk.com)")
    parser.add_argument("-m", "--max-ttl", type=int, default=30, help="Максимальное число шагов (default: 30)")
    parser.add_argument("-t", "--timeout", type=int, default=3, help="Таймаут ожидания ответа в секундах (default: 3)")
    parser.add_argument("-n", "--attempts", type=int, default=3, help="Количество запросов на каждый шаг (default: 3)")
    parser.add_argument("-i", "--interval", type=int, default=1,
                        help="Интервал между запросами в секундах (default: 1)")
    parser.add_argument("-s", "--size", type=int, default=40, help="Общий размер ICMP-пакета в байтах (default: 40)")
    args = parser.parse_args()
    app = Tracer(
        target_addr=args.address,
        max_ttl=args.max_ttl,
        timeout=args.timeout,
        num_attempts=args.attempts,
        interval=args.interval,
        packet_size=args.size)

    app.run()


if __name__ == "__main__":
    main()