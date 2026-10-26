#!/usr/bin/env python3
"""
tools/dns_bypass_proxy.py — Local CONNECT proxy that resolves lfs.github.com to real GitHub IPs
"""

import socket
import select
import sys
import threading

HOST = '127.0.0.1'
PORT = 8989

DNS_MAP = {
    'lfs.github.com': '140.82.121.6',
    'api.github.com': '140.82.121.6',
    'github.com': '140.82.121.4',
}


def handle_client(client_sock):
    try:
        req = b""
        while b"\r\n\r\n" not in req:
            chunk = client_sock.recv(4096)
            if not chunk:
                return
            req += chunk

        first_line = req.split(b"\r\n")[0].decode('latin1', 'replace')
        parts = first_line.split(" ")
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            client_sock.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            client_sock.close()
            return

        target = parts[1]
        host, port = target.split(":")
        port = int(port)

        dest_ip = DNS_MAP.get(host, host)

        remote_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote_sock.settimeout(20)
        remote_sock.connect((dest_ip, port))

        client_sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Relay data bidirectionally
        sockets = [client_sock, remote_sock]
        while True:
            r, _, _ = select.select(sockets, [], [], 60)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                if s is client_sock:
                    remote_sock.sendall(data)
                else:
                    client_sock.sendall(data)
    except Exception:
        pass
    finally:
        client_sock.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(128)
    print(f"Proxy listening on {HOST}:{PORT}")
    sys.stdout.flush()

    while True:
        try:
            client, _ = server.accept()
            t = threading.Thread(target=handle_client, args=(client,), daemon=True)
            t.start()
        except KeyboardInterrupt:
            break
        except Exception:
            pass


if __name__ == '__main__':
    main()
