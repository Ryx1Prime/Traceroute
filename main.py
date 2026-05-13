import sys
from tracer.core import Tracer


def main():
    if len(sys.argv) != 2:
        print("usage: sudo python3 main.py <address>")
        sys.exit(1)

    addr = sys.argv[1]

    app = Tracer(addr)
    app.run()


if __name__ == "__main__":
    main()