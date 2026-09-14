#!/usr/bin/env python3
"""Our public address, for clients that reach us from the internet.

After the gate phase every client is told an address to dial: the account
server in SvrList, the STUN responder in SOURCE/CHANGED-ADDRESS, a match's
relay port. By default that is the local end of the socket the client came in
on, which is right on a LAN and on a machine that owns its public address. It
is wrong behind a home router. A port-forwarded connection arrives on the LAN
address, and an internet client told to dial 192.168.x.x never comes back.

So the choice is made per client. A client whose own address is not globally
routable (RFC 1918, 100.64/10 which covers CGNAT and tailnets, loopback,
link-local) is on a network that can reach our local address, and gets that.
A client with a global address came in through the router and gets the public
address, if there is one to give. If our local address is already global there
is nothing to look up.

The public address is found lazily, the first time an internet client needs
it, so a server that only ever sees LAN clients never contacts anything
outside. After that it is re-checked in the background every few minutes.
That is what makes a dynamic home IP work without a restart: every session
that starts after a change is given the new address.

Where it comes from (--public-addr):

    auto        ask public STUN servers which address our packets leave from
    off         never; every client gets the address it connected to
    <name|ip>   resolve this name on every refresh, a dynamic DNS name say

Standard library only, like the rest of the server.
"""
import ipaddress
import os
import socket
import struct
import threading
import time

# Modern (RFC 5389) servers. Each answers a plain binding request with
# XOR-MAPPED-ADDRESS, and most with MAPPED-ADDRESS as well.
STUN_SERVERS = (('stun.l.google.com', 19302),
                ('stun.cloudflare.com', 3478),
                ('stun1.l.google.com', 19302))
MAGIC = 0x2112A442

REFRESH = 300               # seconds between re-checks once in use


def is_global(ip):
    """True for an address an arbitrary internet host could have."""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def mapped_address(msg):
    """The address out of a STUN binding response, or None.

    Prefers XOR-MAPPED-ADDRESS, falls back to plain MAPPED-ADDRESS, so it reads
    RFC 5389 servers and this project's own RFC 3489 responder alike. IPv4 only,
    because that is all a PS2 can dial.
    """
    if len(msg) < 20 or struct.unpack_from('>H', msg)[0] != 0x0101:
        return None
    body = msg[20:20 + struct.unpack_from('>H', msg, 2)[0]]
    plain = None
    off = 0
    while off + 4 <= len(body):
        atype, alen = struct.unpack_from('>HH', body, off)
        val = body[off + 4:off + 4 + alen]
        if len(val) >= 8 and val[1] == 0x01:
            if atype == 0x0020:
                ip = struct.unpack_from('>I', val, 4)[0] ^ MAGIC
                return socket.inet_ntoa(struct.pack('>I', ip))
            if atype == 0x0001 and plain is None:
                plain = socket.inet_ntoa(val[4:8])
        off += 4 + alen + (-alen) % 4
    return plain


def stun_query(server, timeout=1.0):
    """Ask one STUN server where our packets come from. -> address or None."""
    tid = os.urandom(12)
    req = struct.pack('>HHI', 0x0001, 0, MAGIC) + tid
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(req, (socket.gethostbyname(server[0]), server[1]))
        while True:
            data, _ = s.recvfrom(2048)
            # An RFC 3489 server echoes all 16 bytes after the length, which
            # is our cookie plus id, so this matches either kind.
            if data[8:20] == tid:
                return mapped_address(data)
    except OSError:
        return None
    finally:
        s.close()


class PublicAddress(object):
    """Which address to hand a client, given where it connected from."""

    def __init__(self, spec='auto', log=None, interval=REFRESH,
                 servers=STUN_SERVERS):
        self.spec = (spec or 'auto').strip()
        self.log = log or (lambda m: None)
        self.interval = interval
        self.servers = servers
        self.addr = None
        self._failing = False
        self._lock = threading.Lock()
        self._started = False

    def describe(self):
        if self.spec == 'off':
            return 'off, every client is given the address it connected to'
        if self.spec == 'auto':
            return 'looked up over STUN when the first one connects'
        return 'resolved from %s' % self.spec

    def lookup(self):
        """One fresh answer, or None."""
        if self.spec == 'off':
            return None
        if self.spec == 'auto':
            for server in self.servers:
                ip = stun_query(server)
                if ip and is_global(ip):
                    return ip
            return None
        try:
            ip = socket.gethostbyname(self.spec)
        except OSError:
            return None
        if not is_global(ip):
            # Most likely split DNS: the name answers with a LAN address from
            # inside the LAN. Handing that to an internet client is useless.
            self.log('!! %s resolves to %s from here, which is not a public '
                     'address; ignoring it' % (self.spec, ip))
            return None
        return ip

    def refresh(self):
        ip = self.lookup()
        if ip is None:
            if not self._failing:
                self._failing = True
                self.log('!! could not work out our public address (%s); %s'
                         % (self.describe(),
                            'keeping %s' % self.addr if self.addr else
                            'internet clients will be given the local '
                            'address, which they cannot reach'))
            return
        self._failing = False
        if ip != self.addr:
            self.log('public address is %s%s'
                     % (ip, ' (was %s)' % self.addr if self.addr else ''))
            self.addr = ip

    def _loop(self):
        while True:
            time.sleep(self.interval)
            self.refresh()

    def get(self):
        """The public address, looked up the first time it is asked for.

        The first caller waits for the lookup, a second or so at worst per
        STUN server; everyone after that gets the cached answer.
        """
        with self._lock:
            if not self._started:
                self._started = True
                self.refresh()
                threading.Thread(target=self._loop, daemon=True).start()
        return self.addr

    def for_client(self, client_ip, local_ip):
        """The address a client at `client_ip` should dial to reach us.

        `local_ip` is the address it reached us on, which is always right for
        a client on our side of the router and is the fallback for everyone.
        """
        if self.spec == 'off' or not is_global(client_ip) or is_global(local_ip):
            return local_ip
        return self.get() or local_ip


if __name__ == '__main__':
    import sys
    p = PublicAddress(sys.argv[1] if len(sys.argv) > 1 else 'auto',
                      log=lambda m: print(m, flush=True))
    print(p.lookup() or 'no answer')
