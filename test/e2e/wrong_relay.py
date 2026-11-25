# SPDX-License-Identifier: GPL-3.0-or-later

import selectors
import socket
import sys
from contextlib import ExitStack


def serve(host, tcp_port, udp_ports):
    with ExitStack() as resources:
        ready = resources.enter_context(selectors.DefaultSelector())
        endpoints = [(tcp_port, socket.SOCK_STREAM)]
        endpoints.extend((port, socket.SOCK_DGRAM) for port in udp_ports)
        for port, kind in endpoints:
            listener = resources.enter_context(socket.socket(socket.AF_INET, kind))
            listener.bind((host, port))
            if kind == socket.SOCK_STREAM:
                listener.listen()
            ready.register(listener, selectors.EVENT_READ, kind)

        print("Wrong relay ready", flush=True)
        while True:
            for event, _ in ready.select():
                listener = event.fileobj
                if event.data == socket.SOCK_STREAM:
                    connection, _ = listener.accept()
                    with connection:
                        try:
                            connection.sendall(b"HTTP/1.0 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                        except OSError:
                            pass
                    print("TCP received", flush=True)
                else:
                    listener.recvfrom(4096)
                    print("UDP received", flush=True)


if __name__ == "__main__":
    serve(sys.argv[1], int(sys.argv[2]), map(int, sys.argv[3:]))
