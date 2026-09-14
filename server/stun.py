#!/usr/bin/env python3
"""
Classic STUN (RFC 3489) responder for DDR Extreme 2 / SuperNOVA.

The client resolves dx2stun.konamionline.com (Extreme 2) / ddrsnstun (SuperNOVA)
and runs NAT-type discovery against udp/3478 before it will let you online -- the
"Attempting to determine network settings" / "checking UDP port" screen. Its
middleware is `mrdUPnP`, whose debug strings name the classic RFC 3489 test
matrix: mrdUPnP_STUN_TEST_BASIC, _CHG_IP_PORT, _CHG_PORT, _VHOST_* and
_STUN3_EX_CHECK.

RFC 3489, NOT 5389: this is a 2005 title, so there is no magic cookie and the
transaction id is the full 16 bytes. Addresses are plain (never XOR-mapped).

Header (20 bytes, big-endian):
    u16 type, u16 length, u8[16] transaction id
Attributes (TLV, big-endian, padded to 4):
    u16 type, u16 length, value

The NAT-type probe wants to see whether the server can answer from a DIFFERENT
ip/port, so a real deployment needs two addresses. We have one, so we run two
PORTS and answer change-port requests from the alternate socket; change-IP
requests cannot be honoured and are dropped, which is what a real server behind a
single address would look like. Watch the log to see which conclusion the client
draws -- that is the point of the per-test logging.

SOURCE and CHANGED-ADDRESS name this server, so they are chosen per client the
same way the gate chooses what to put in SvrList: a client on the LAN is given
our local address, and one arriving from the internet our public address. See
publicaddr.py.
"""
import argparse
import binascii
import os
import select
import socket
import struct
import sys

import publicaddr

BIND_REQUEST = 0x0001
BIND_RESPONSE = 0x0101
BIND_ERROR = 0x0111

ATTR_MAPPED_ADDRESS = 0x0001
ATTR_RESPONSE_ADDRESS = 0x0002
ATTR_CHANGE_REQUEST = 0x0003
ATTR_SOURCE_ADDRESS = 0x0004
ATTR_CHANGED_ADDRESS = 0x0005
ATTR_USERNAME = 0x0006
ATTR_MESSAGE_INTEGRITY = 0x0008
ATTR_ERROR_CODE = 0x0009
ATTR_UNKNOWN_ATTRIBUTES = 0x000a
ATTR_REFLECTED_FROM = 0x000b

ATTR_NAMES = {
    ATTR_MAPPED_ADDRESS: 'MAPPED-ADDRESS',
    ATTR_RESPONSE_ADDRESS: 'RESPONSE-ADDRESS',
    ATTR_CHANGE_REQUEST: 'CHANGE-REQUEST',
    ATTR_SOURCE_ADDRESS: 'SOURCE-ADDRESS',
    ATTR_CHANGED_ADDRESS: 'CHANGED-ADDRESS',
    ATTR_USERNAME: 'USERNAME',
    ATTR_MESSAGE_INTEGRITY: 'MESSAGE-INTEGRITY',
    ATTR_REFLECTED_FROM: 'REFLECTED-FROM',
}

CHANGE_IP = 0x04
CHANGE_PORT = 0x02


def parse(data):
    """-> (msg_type, transaction_id, {attr_type: value}) or None."""
    if len(data) < 20:
        return None
    msg_type, length, = struct.unpack('>HH', data[:4])
    tid = data[4:20]
    body = data[20:20 + length]
    attrs = {}
    off = 0
    while off + 4 <= len(body):
        atype, alen = struct.unpack('>HH', body[off:off + 4])
        val = body[off + 4:off + 4 + alen]
        attrs[atype] = val
        off += 4 + alen
        off += (-off) % 4          # pad to 4-byte boundary
    return msg_type, tid, attrs


def addr_attr(atype, ip, port):
    packed = socket.inet_aton(ip)
    val = struct.pack('>BBH', 0, 0x01, port) + packed
    return struct.pack('>HH', atype, len(val)) + val


def build_response(tid, mapped_ip, mapped_port, source_ip, source_port,
                   changed_ip, changed_port):
    body = (addr_attr(ATTR_MAPPED_ADDRESS, mapped_ip, mapped_port)
            + addr_attr(ATTR_SOURCE_ADDRESS, source_ip, source_port)
            + addr_attr(ATTR_CHANGED_ADDRESS, changed_ip, changed_port))
    return struct.pack('>HH', BIND_RESPONSE, len(body)) + tid + body


def describe(attrs):
    out = []
    for a, v in attrs.items():
        n = ATTR_NAMES.get(a, '0x%04x' % a)
        if a == ATTR_CHANGE_REQUEST and len(v) >= 4:
            flags = struct.unpack('>I', v[:4])[0]
            bits = []
            if flags & CHANGE_IP:
                bits.append('change-IP')
            if flags & CHANGE_PORT:
                bits.append('change-port')
            n += '(%s)' % (','.join(bits) or 'none')
        out.append(n)
    return ', '.join(out) or 'no attributes'


def local_address():
    """This machine's own address, for SOURCE and CHANGED-ADDRESS.

    Bound to 0.0.0.0 there is no single right answer, and putting 0.0.0.0 in
    those fields is worse than a guess. Opening a UDP socket towards an outside
    address picks whichever interface the routing table would use and costs
    nothing, since UDP connect sends no packets. Falls back to loopback if
    there is no route at all. Override with --advertise when the client should
    be told something else, such as behind a port forward.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('192.0.2.1', 9))
        return s.getsockname()[0]
    except OSError:
        return '127.0.0.1'
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser(description='Classic STUN (RFC 3489) responder')
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=3478)
    ap.add_argument('--alt-port', type=int, default=3479,
                    help='second port, used to answer change-port requests')
    ap.add_argument('--advertise', default=None,
                    help='our address as EVERY client sees it, for '
                         'SOURCE/CHANGED-ADDRESS (default: chosen per client, '
                         'see --public-addr)')
    ap.add_argument('--public-addr', default='auto',
                    help='what to advertise to clients arriving from the '
                         'internet: "auto" looks it up over STUN, "off" gives '
                         'them the local address, or a name or address to '
                         'resolve (default: auto)')
    a = ap.parse_args()

    socks = {}
    for p in (a.port, a.alt_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((a.host, p))
        socks[p] = s
    local = a.host if a.host != '0.0.0.0' else local_address()
    public = publicaddr.PublicAddress(a.public_addr,
                                      log=lambda m: print(m, flush=True))
    print('stun listening on %s:%d (primary) and :%d (alternate)'
          % (a.host, a.port, a.alt_port), flush=True)
    if a.advertise:
        print('advertising %s in SOURCE/CHANGED-ADDRESS\n' % a.advertise,
              flush=True)
    else:
        print('advertising %s in SOURCE/CHANGED-ADDRESS to LAN clients; '
              'internet clients get the public address, %s\n'
              % (local, public.describe()), flush=True)

    while True:
        ready, _, _ = select.select(list(socks.values()), [], [])
        for s in ready:
            try:
                data, src = s.recvfrom(2048)
            except OSError:
                continue
            recv_port = s.getsockname()[1]
            p = parse(data)
            if p is None:
                print('[%s:%d] -> :%d  malformed/short (%d bytes) %s'
                      % (src[0], src[1], recv_port, len(data),
                         binascii.hexlify(data[:32]).decode()), flush=True)
                continue
            msg_type, tid, attrs = p
            if msg_type != BIND_REQUEST:
                print('[%s:%d] -> :%d  non-binding message type 0x%04x (ignored)'
                      % (src[0], src[1], recv_port, msg_type), flush=True)
                continue

            flags = 0
            cr = attrs.get(ATTR_CHANGE_REQUEST)
            if cr and len(cr) >= 4:
                flags = struct.unpack('>I', cr[:4])[0]

            print('[%s:%d] -> :%d  BindingRequest  tid=%s  %s'
                  % (src[0], src[1], recv_port,
                     binascii.hexlify(tid[:6]).decode(), describe(attrs)), flush=True)

            if flags & CHANGE_IP:
                # We only have one address, so this test genuinely cannot be
                # satisfied. Silence is the correct answer -- and it is what the
                # client's NAT-type logic expects to see for a restricted path.
                print('        change-IP requested; we have one address -- no reply',
                      flush=True)
                continue

            out_port = a.alt_port if (flags & CHANGE_PORT) else recv_port
            out_sock = socks[out_port]
            if flags & CHANGE_PORT:
                print('        change-port -> replying from :%d' % out_port, flush=True)

            other_port = a.alt_port if out_port == a.port else a.port
            adv = a.advertise or public.for_client(src[0], local)
            resp = build_response(tid, src[0], src[1], adv, out_port, adv, other_port)
            try:
                out_sock.sendto(resp, src)
                print('        MAPPED-ADDRESS %s:%d  (replied from :%d)'
                      % (src[0], src[1], out_port), flush=True)
            except OSError as e:
                print('        send failed: %s' % e, flush=True)


if __name__ == '__main__':
    main()
