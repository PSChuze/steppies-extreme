#!/usr/bin/env python3
"""A UDP relay for SuperNOVA's peer-to-peer gameplay.

WHY THIS EXISTS
---------------
Extreme 2 tunnels its whole in-game peer protocol through the server over the
`0x4400` lobby message, so it works anywhere the lobby works. **SuperNOVA does
not.** It dials the opponent directly over UDP:

    FUN_00a4c100  state 0: connect(conn, my_public, their_public, their_local)
                  state 1: poll FUN_0027b900 until != 0
                  state 2: -> the song
    FUN_0027bb30  if (my_public == their_public) dial their_local  : local_port
                  else                           dial their_public : public_port
    FUN_0027c6f0  builds a sockaddr from that address and htons(port)

and `FUN_0027b900` gives up after about 300 ticks. Two consoles under one PCSX2
can never satisfy that: the `Sockets` backend translates outbound UDP but
forwards nothing inbound, so the port a STUN mapping advertises is not
deliverable to the emulated machine. They also share the local address
192.0.2.100, so the hairpin branch would point each console at itself.

The client dials whatever the server tells it to. So tell it to dial US.

HOW IT WORKS
------------
A match gets a PAIR of UDP ports. Each side is told its opponent lives at
`<relay address>:<its own port>`, and whatever arrives on one port is forwarded
out of the other:

    console A  --> relay:portA  ==>  relay:portB --> console B
    console B  --> relay:portB  ==>  relay:portA --> console A

Neither console needs to be reachable from outside, because both connections
are outbound. The relay learns where to send by remembering the source address
of the first datagram on each port, which is the same trick STUN relies on and
needs no configuration.

Nothing here inspects or rewrites the payload -- it is the peer protocol and it
is none of the relay's business.

Pure standard library, like the rest of this server.
"""
import selectors
import socket
import threading
import time


class Pair(object):
    """One match's two ports, and where each side turned out to be."""

    __slots__ = ('a', 'b', 'sock_a', 'sock_b', 'seen_a', 'seen_b',
                 'packets', 'opened')

    def __init__(self, a, b, sock_a, sock_b):
        self.a, self.b = a, b
        self.sock_a, self.sock_b = sock_a, sock_b
        self.seen_a = None          # console A's real source address
        self.seen_b = None
        self.packets = 0
        self.opened = time.time()

    def __repr__(self):
        return ('<relay %d<->%d a=%s b=%s %d pkt>'
                % (self.a, self.b, self.seen_a, self.seen_b, self.packets))


class Relay(object):
    """A pool of UDP port pairs plus one forwarding thread.

    Ports are pre-bound at start-up rather than on demand: binding is the only
    part that can fail, and failing then is far easier to diagnose than failing
    in the middle of a match.
    """

    def __init__(self, host='0.0.0.0', base_port=19600, pairs=8, log=None):
        self.host = host
        self.log = log or (lambda m: None)
        self._lock = threading.Lock()
        self._free = []
        self._by_sock = {}
        self._sel = selectors.DefaultSelector()
        self._stop = threading.Event()
        port = base_port
        for _ in range(pairs):
            sa = self._bind(port)
            sb = self._bind(port + 1)
            if sa is None or sb is None:
                for s in (sa, sb):
                    if s is not None:
                        s.close()
                port += 2
                continue
            pair = Pair(port, port + 1, sa, sb)
            self._free.append(pair)
            self._by_sock[sa] = (pair, 'a')
            self._by_sock[sb] = (pair, 'b')
            self._sel.register(sa, selectors.EVENT_READ)
            self._sel.register(sb, selectors.EVENT_READ)
            port += 2
        self.ports = [(p.a, p.b) for p in self._free]

    def _bind(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((self.host, port))
        except OSError as e:
            self.log('!! relay could not bind UDP %d: %s' % (port, e))
            s.close()
            return None
        s.setblocking(False)
        return s

    def start(self):
        if not self._free:
            self.log('!! relay has no usable ports; SuperNOVA peer play will '
                     'not work')
            return self
        t = threading.Thread(target=self._pump, daemon=True)
        t.start()
        self.log('udp relay on %s ports %s'
                 % (self.host, ', '.join('%d/%d' % p for p in self.ports)))
        return self

    def stop(self):
        self._stop.set()

    def alloc(self):
        """Take a pair for one match, or None if the pool is exhausted."""
        with self._lock:
            if not self._free:
                return None
            pair = self._free.pop(0)
        pair.seen_a = pair.seen_b = None
        pair.packets = 0
        pair.opened = time.time()
        return pair

    def release(self, pair):
        if pair is None:
            return
        with self._lock:
            if pair not in self._free:
                pair.seen_a = pair.seen_b = None
                self._free.append(pair)

    def _pump(self):
        while not self._stop.is_set():
            try:
                events = self._sel.select(timeout=0.5)
            except OSError:
                continue
            for key, _ in events:
                pair, side = self._by_sock.get(key.fileobj, (None, None))
                if pair is None:
                    continue
                try:
                    data, src = key.fileobj.recvfrom(2048)
                except OSError:
                    continue
                # Learn where this console actually is from its first packet.
                # Re-learn on every packet: PCSX2 and real hardware can both
                # change source port mid-session, and the cost of trusting the
                # latest source is one misdirected datagram in a protocol that
                # is already lossy.
                if side == 'a':
                    if pair.seen_a != src:
                        self.log('relay %d: A is %s:%d' % (pair.a, src[0], src[1]))
                    pair.seen_a = src
                    out, dest = pair.sock_b, pair.seen_b
                else:
                    if pair.seen_b != src:
                        self.log('relay %d: B is %s:%d' % (pair.b, src[0], src[1]))
                    pair.seen_b = src
                    out, dest = pair.sock_a, pair.seen_a
                if dest is None:
                    continue        # the other side has not spoken yet
                try:
                    out.sendto(data, dest)
                    pair.packets += 1
                except OSError:
                    pass


def main():
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--base-port', type=int, default=19600)
    ap.add_argument('--pairs', type=int, default=8)
    a = ap.parse_args()
    r = Relay(a.host, a.base_port, a.pairs,
              log=lambda m: print(m, flush=True)).start()
    p = r.alloc()
    print('allocated %r -- point two clients at these ports to test' % (p,))
    try:
        while True:
            time.sleep(5)
            print('  %r' % (p,), flush=True)
    except KeyboardInterrupt:
        r.stop()


if __name__ == '__main__':
    main()
