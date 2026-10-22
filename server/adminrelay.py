#!/usr/bin/env python3
"""Forward the admin port onto the OpenLobby Docker network.

An OpenLobby admin panel finds the games beside it on a shared Docker network
called "openlobby", where each game answers under its own short name. The gate
cannot join it: it runs with host networking, because STUN and the match relay
need players' real addresses. So this runs in a small container of its own on
that network, named "ddr", and passes every connection through to the gate's
admin port on the host. It reads nothing and checks nothing; the gate checks
the token.

    python3 adminrelay.py --listen 0.0.0.0:19591 --to host.docker.internal:19591
"""
import argparse
import socket
import threading


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, target):
    try:
        upstream = socket.create_connection(target, timeout=10)
    except OSError as e:
        print('cannot reach %s:%d (%s)' % (target + (e,)), flush=True)
        client.close()
        return
    upstream.settimeout(None)
    threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()
    pipe(client, upstream)
    client.close()
    upstream.close()


def hostport(text):
    host, _, port = text.rpartition(':')
    return host, int(port)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--listen', type=hostport, default=('0.0.0.0', 19591))
    ap.add_argument('--to', type=hostport,
                    default=('host.docker.internal', 19591))
    args = ap.parse_args()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(args.listen)
    srv.listen(16)
    print('admin relay: %s:%d -> %s:%d' % (args.listen + args.to), flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client, args.to),
                         daemon=True).start()


if __name__ == '__main__':
    main()
