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
                 'packets', 'opened', 'allow_a', 'allow_b', 'dropped',
                 'from_a', 'from_b', 'sent_a', 'sent_b')

    def __init__(self, a, b, sock_a, sock_b):
        self.a, self.b = a, b
        self.sock_a, self.sock_b = sock_a, sock_b
        self.seen_a = None          # console A's real source address
        self.seen_b = None
        self.allow_a = None         # the only IP allowed to be A, if pinned
        self.allow_b = None
        self.dropped = 0
        self.packets = 0
        self.opened = time.time()
        self.reset_counts()

    def reset_counts(self):
        # Received from each side, and forwarded to each side. A side that
        # sends but is never sent to means the other console never spoke;
        # a side that is sent to but never answers means our packets are not
        # reaching it, which is the one failure the relay cannot see otherwise.
        self.from_a = self.from_b = self.sent_a = self.sent_b = 0

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

    def alloc(self, allow_a=None, allow_b=None):
        """Take a pair for one match, or None if the pool is exhausted.

        allow_a / allow_b pin each side to one IP address, the player's own,
        which the gate knows from their TCP session. On a public server this
        is what stops anyone who sprays the relay ports from taking over a
        live match: without it the relay re-learns a side from whatever packet
        arrived last, so a stranger's datagram would become "A" and receive
        B's traffic. A console's UDP leaves from the same IP as its TCP
        connection, NAT and PCSX2 included. None leaves a side open.
        """
        with self._lock:
            if not self._free:
                return None
            pair = self._free.pop(0)
        pair.seen_a = pair.seen_b = None
        pair.allow_a, pair.allow_b = allow_a, allow_b
        pair.dropped = 0
        pair.packets = 0
        pair.opened = time.time()
        pair.reset_counts()
        return pair

    def release(self, pair):
        if pair is None:
            return
        with self._lock:
            if pair not in self._free:
                self.log('relay %d<->%d closed after %ds: A %s sent %d, got %d;'
                         ' B %s sent %d, got %d; %d dropped'
                         % (pair.a, pair.b, time.time() - pair.opened,
                            pair.seen_a, pair.from_a, pair.sent_a,
                            pair.seen_b, pair.from_b, pair.sent_b,
                            pair.dropped))
                pair.seen_a = pair.seen_b = None
                pair.allow_a = pair.allow_b = None
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
                allow = pair.allow_a if side == 'a' else pair.allow_b
                if allow is not None and src[0] != allow:
                    # Not this side's player. Drop it, and say so once in a
                    # while so a stranger on the port is visible in the log.
                    pair.dropped += 1
                    if pair.dropped in (1, 10, 100) or pair.dropped % 1000 == 0:
                        self.log('relay %d: dropped %d packet(s) from %s:%d, '
                                 'which is not %s'
                                 % (pair.a if side == 'a' else pair.b,
                                    pair.dropped, src[0], src[1], allow))
                    continue
                if side == 'a':
                    if pair.seen_a != src:
                        self.log('relay %d: A is %s:%d' % (pair.a, src[0], src[1]))
                    pair.seen_a = src
                    pair.from_a += 1
                    out, dest = pair.sock_b, pair.seen_b
                else:
                    if pair.seen_b != src:
                        self.log('relay %d: B is %s:%d' % (pair.b, src[0], src[1]))
                    pair.seen_b = src
                    pair.from_b += 1
                    out, dest = pair.sock_a, pair.seen_a
                if dest is None:
                    continue        # the other side has not spoken yet
                try:
                    out.sendto(data, dest)
                    pair.packets += 1
                    if side == 'a':
                        pair.sent_b += 1
                    else:
                        pair.sent_a += 1
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
