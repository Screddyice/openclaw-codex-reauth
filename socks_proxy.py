#!/usr/bin/env python3
"""Minimal SOCKS5 proxy for residential-IP tunneling.

Binds to 127.0.0.1:<port> (default 1080). No authentication.
Used by codex_reauth_server.py via reverse SSH tunnel from the Mac:

  # On Mac:
  python3 socks_proxy.py &
  ssh -R 1080:127.0.0.1:1080 server-a -N &
  ssh -R 1080:127.0.0.1:1080 server-b -N &

Then on the server, Chrome launched with --proxy-server=socks5://127.0.0.1:1080
exits through the Mac's residential IP.
"""
from __future__ import annotations

import argparse
import select
import socket
import struct
import threading
import sys


def handle_client(client: socket.socket):
    try:
        # SOCKS5 greeting
        data = client.recv(256)
        if not data or data[0] != 0x05:
            client.close(); return
        # No auth required
        client.sendall(b'\x05\x00')

        # SOCKS5 request
        data = client.recv(256)
        if not data or len(data) < 7:
            client.close(); return
        ver, cmd, _, atyp = data[0], data[1], data[2], data[3]
        if ver != 0x05 or cmd != 0x01:
            client.sendall(b'\x05\x07\x00\x01' + b'\x00' * 6)
            client.close(); return

        if atyp == 0x01:  # IPv4
            addr = socket.inet_ntoa(data[4:8])
            port = struct.unpack('!H', data[8:10])[0]
        elif atyp == 0x03:  # Domain
            domain_len = data[4]
            addr = data[5:5 + domain_len].decode()
            port = struct.unpack('!H', data[5 + domain_len:7 + domain_len])[0]
        elif atyp == 0x04:  # IPv6
            addr = socket.inet_ntop(socket.AF_INET6, data[4:20])
            port = struct.unpack('!H', data[20:22])[0]
        else:
            client.sendall(b'\x05\x08\x00\x01' + b'\x00' * 6)
            client.close(); return

        # Connect to target
        try:
            remote = socket.create_connection((addr, port), timeout=15)
        except Exception:
            client.sendall(b'\x05\x05\x00\x01' + b'\x00' * 6)
            client.close(); return

        # Success reply
        bind_addr = remote.getsockname()
        reply = b'\x05\x00\x00\x01'
        reply += socket.inet_aton(bind_addr[0])
        reply += struct.pack('!H', bind_addr[1])
        client.sendall(reply)

        # Relay
        relay(client, remote)
    except Exception:
        pass
    finally:
        try: client.close()
        except: pass


def relay(a: socket.socket, b: socket.socket):
    sockets = [a, b]
    try:
        while True:
            readable, _, errored = select.select(sockets, [], sockets, 60)
            if errored:
                break
            for s in readable:
                data = s.recv(8192)
                if not data:
                    return
                target = b if s is a else a
                target.sendall(data)
    except Exception:
        pass
    finally:
        try: a.close()
        except: pass
        try: b.close()
        except: pass


def main():
    parser = argparse.ArgumentParser(description="Minimal SOCKS5 proxy")
    parser.add_argument("--port", type=int, default=1080)
    parser.add_argument("--bind", default="127.0.0.1")
    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.bind, args.port))
    server.listen(64)
    print(f"SOCKS5 proxy listening on {args.bind}:{args.port}")

    while True:
        client, _ = server.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
