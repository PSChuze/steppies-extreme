#!/usr/bin/env python3
"""Self-tests for the gate frame codec and XOR-key recovery."""
import os
import socket
import json
import struct
import subprocess
import tempfile
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gate  # noqa: E402

FAILS = []


def check(name, cond, extra=''):
    print('%-58s %s %s' % (name, 'PASS' if cond else 'FAIL', extra))
    if not cond:
        FAILS.append(name)


def test_roundtrip():
    key = bytes([0x5a, 0xc3, 0x1f, 0x77])
    payload = bytes(range(200))
    frame = gate.build(0x2008, 0x01020304, payload, key)
    plain = gate.xor(frame, key)
    opcode, length, serial = struct.unpack('>HHI', plain[:8])
    check('roundtrip opcode', opcode == 0x2008, hex(opcode))
    check('roundtrip length', length == len(payload), length)
    check('roundtrip serial', serial == 0x01020304, hex(serial))
    check('roundtrip payload', plain[24:24 + length] == payload)
    check('roundtrip md5 valid',
          gate.digest(plain[0:8], payload) == plain[8:24])


def test_key_recovery():
    for key in (bytes([0x5a, 0xc3, 0x1f, 0x77]),
                bytes([0x00, 0x00, 0x00, 0x00]),
                bytes([0xff, 0xff, 0xff, 0xff]),
                bytes([0xde, 0xad, 0xbe, 0xef])):
        frame = gate.build(0x2008, 7, b'hello world payload' * 3, key)
        got = gate.recover_key(frame)
        check('recover key %s' % key.hex(), got == key, 'got %s' % (got.hex() if got else None))


def test_key_recovery_empty_payload():
    key = bytes([0x13, 0x37, 0xaa, 0x55])
    frame = gate.build(0x2006, 1, b'', key)
    got = gate.recover_key(frame)
    check('recover key with zero-length payload', got == key,
          'got %s' % (got.hex() if got else None))


def test_xor_index_continuity():
    """Payload XOR index must continue from the header (offset 0x18).

    0x18 % 4 == 0, so it collapses to key[i & 3] -- assert that explicitly so a
    future change to HDR does not silently break the codec.
    """
    check('header size is a multiple of the key length', gate.HDR % 4 == 0, gate.HDR)
    key = bytes([1, 2, 3, 4])
    body = bytes(8)
    check('payload xor continues cleanly',
          gate.xor(body, key, gate.HDR) == gate.xor(body, key, 0))


def test_sn_match_record():
    """The SuperNOVA match push, 0x4a04 / 0x4a13. See build_sn_match_record.

    67 bytes, and the length is the whole point: the parser bounds-checks the
    read CURSOR, not the message, so a body one byte short is not rejected --
    the tail fields are simply filled from whatever the message buffer last
    held. Pin the three fields whose meaning is established and the offsets
    they sit at.
    """
    rec = gate.build_sn_match_record({'id': 7, 'name': 'DECK', 'dancer': 3},
                                     song=12)
    check('SN match record is 67 bytes', len(rec) == 67, len(rec))
    check('SN match song at +8', struct.unpack_from('>H', rec, 8)[0] == 12)
    check('SN match opponent id at +18',
          struct.unpack_from('>i', rec, 18)[0] == 7)
    check('SN match opponent name at +22',
          rec[22:38] == b'DECK'.ljust(16, b'\x00'), rec[22:38])
    check('SN match dancer at +38', rec[38] == 3, rec[38])
    empty = gate.build_sn_match_record(None)
    check('SN match record with no player file is still 67 bytes',
          len(empty) == 67, len(empty))
    # The song is the one field a caller can put out of range; it is a u16 on
    # the wire and nothing in the parser clamps it.
    check('SN match song is masked to u16',
          struct.unpack_from('>H', gate.build_sn_match_record({}, song=0x1ffff),
                             8)[0] == 0xffff)


def test_sn_playerlist_record():
    """SuperNOVA's 0x4212 record is 61 bytes where Extreme 2's is 75.

    Serving the Extreme 2 record put a phantom nameless player in the list --
    the loop found the 14-byte tail unread and started a second record in it.
    Pin both lengths so they cannot drift back together.
    """
    sn = gate.playerlist_entry_sn(11, 'aaa', 13)
    e2 = gate.playerlist_entry(11, 'aaa', 13)
    check('SN player record is 61 bytes', len(sn) == 61, len(sn))
    check('E2 player record is still 75 bytes', len(e2) == 75, len(e2))
    check('SN player id at +0', struct.unpack_from('>i', sn, 0)[0] == 11)
    check('SN player name at +4', sn[4:20] == b'aaa'.ljust(16, bytes(1)))
    check('SN player dancer at +20', sn[20] == 13, sn[20])
    # The first 21 bytes are common to both games; everything after diverges.
    check('SN and E2 records agree on id/name/dancer', sn[:21] == e2[:21])
    check('a two-player SN list is exactly 122 bytes',
          len(sn + gate.playerlist_entry_sn(9, 'b', 1)) == 122)


def test_sn_friends():
    """0x3084: two ONE-DIRECTIONAL lists, and byte 0 says which.

    Corrected 2026-09-13 by correlation against the UI: a friend added by
    0x4520 showed up in the other player's IGNORE list, because this server
    was writing 1 into byte 0 on the recipient's side. That byte is the LIST,
    not a relationship state, and there is no request/approve flow at all.
    """
    saved = gate.STATE.get('accounts'), gate.STATE.get('friends')
    try:
        gate.STATE['accounts'] = {
            'a': {'player_files': [{'id': 10, 'name': 'qq', 'dancer': 3,
                                    'slot': 0}]},
            'b': {'player_files': [{'id': 11, 'name': 'aaa', 'dancer': 13,
                                    'slot': 0}]}}
        gate.STATE['friends'] = {}
        gate.friend_add(11, 10, gate.FRIEND_LIST)      # aaa adds qq
        b = gate.friendlist_body(11, {10})
        check('friends record is 23 bytes', len(b) == 23, len(b))
        check('friends id at +0', struct.unpack_from('>i', b, 0)[0] == 10)
        check('friends name at +4', b[4:20] == b'qq'.ljust(16, bytes(1)))
        check('byte 1 is 0 for the FRIENDS list', b[21] == 0, b[21])
        check('byte 2 is the online marker', b[22] == 1, b[22])
        check('byte 0 is unused', b[20] == 0, b[20])
        # One-directional: adding does NOT touch the other player's list. That
        # is the whole reason the protocol needs no incoming-request push.
        check('the other player list is untouched',
              gate.friendlist_body(10, set()) == b'')
        gate.friend_add(11, 10, gate.IGNORE_LIST)
        check('byte 1 is 1 for the IGNORE list',
              gate.friendlist_body(11, set())[21] == 1)
        # Removing from one list must not drop an entry on the other.
        gate.friend_remove(11, 10, gate.FRIEND_LIST)
        check('removing from the wrong list is a no-op',
              gate.friendlist_body(11, set()) != b'')
        gate.friend_remove(11, 10, gate.IGNORE_LIST)
        check('removing from the right list works',
              gate.friendlist_body(11, set()) == b'')
        gate.friend_add(11, 10, gate.FRIEND_LIST)
        check('--friend-bytes overrides all three',
              gate.friendlist_body(11, set(), (7, 8, 9))[20:23]
              == bytes([7, 8, 9]))
    finally:
        gate.STATE['accounts'], gate.STATE['friends'] = (
            saved[0] or {}, saved[1] or {})


def test_sn_news():
    """The 0x3122 news record: s32, s32, s32, char[64], cstring.

    The important property is that an EMPTY feed sends no frame at all. 0x3122
    is a loop member with no count and no delimiter, so a zero-length one is
    worse than none -- the parser would read its fields off the end of the
    message. payload_for returns a list, and an empty list sends nothing.
    """
    check('no news means no 0x3122 frame', gate.sn_news_bodies(None) == []
          and gate.sn_news_bodies([]) == [])
    b = gate.sn_news_bodies(['WELCOME|Server is live.'], fields=(1, 2, 3))
    check('one item is one frame', len(b) == 1, len(b))
    r = b[0]
    check('news record head is three s32',
          struct.unpack_from('>iii', r, 0) == (1, 2, 3))
    check('news title is a fixed 64 bytes',
          r[12:76] == b'WELCOME'.ljust(64, bytes(1)))
    check('news body is NUL-terminated', r[76:] == b'Server is live.' + bytes(1))
    big = gate.sn_news_bodies(['T' * 200 + '|' + 'B' * 900], fields=(0, 0, 0))[0]
    check('long news record still fits the payload cap',
          len(big) <= gate.MAX_PAYLOAD, len(big))
    check('  title truncated to 64', big[12:76] == b'T' * 64)
    one = gate.sn_news_bodies(['HELLO'], fields=(0, 0, 0))[0]
    check('news item without a pipe uses the text for both',
          one[12:76] == b'HELLO'.ljust(64, bytes(1))
          and one[76:] == b'HELLO' + bytes(1))
    check('0x3120 group now includes the DATA part',
          gate.response_sequence(0x3120, True)[0] == (0x3121, 0x3122, 0x3123))
    # Field 3 is a UNIX TIMESTAMP, settled on screen: 2219 rendered as
    # 1970.01.01 00:36 UTC. Serving a packed HHMM there put every item in 1970.
    import time as _t
    now = int(_t.time())
    auto = gate.sn_news_bodies(['X'])[0]
    ts = struct.unpack_from('>i', auto, 8)[0]
    check('news field 3 is a plausible unix timestamp',
          abs(ts - now) < 5, ts)
    check('news field 1 is the 1-based index',
          struct.unpack_from('>i', auto, 0)[0] == 1)


def test_sn_room_record():
    """The 0x4310 room record -- 36 bytes, and one byte decides visibility.

    The room-list screen (0x00a6262c) keeps an entry only if struct +0x22 has
    bit 0 set, and that byte is wire offset 31. Serving it as zero put a
    correctly-formed, correctly-counted record on the wire that the client
    silently refused to draw.
    """
    r = {'id': 11, 'song': 74, 'f3': 0, 'f4': 0, 'f5': 0, 'f6': 1, 'f7': 0}
    rec = gate.roomlist_entry_sn(r, 'aaa')
    check('room record is 36 bytes', len(rec) == 36, len(rec))
    check('room creator id at +0', struct.unpack_from('>i', rec, 0)[0] == 11)
    check('room song at +4', struct.unpack_from('>H', rec, 4)[0] == 74)
    check('room name at +10', rec[10:26] == b'aaa'.ljust(16, bytes(1)))
    check('room LISTED bit is set at +31', rec[31] & 1 == 1, rec[31])
    # Two song fields: +4 feeds the availability filter, +32 is what the
    # row DISPLAYS. Filling only the first drew the song as random.
    # Wire +34 bit 0 is the LOCK: set it and the client refuses the room
    # with "you cannot enter this room" (0x00a63c1c).
    check('room is NOT locked at +34', rec[34] & 1 == 0, rec[34])
    check('room song is also at +32',
          struct.unpack_from('>H', rec, 32)[0] == 74,
          struct.unpack_from('>H', rec, 32)[0])
    # f4 is a room SETTING, not a flag word. It was being ORed into the listed
    # byte on the theory that the creator's bits should survive; then a room
    # created with non-default options sent f4 = 4 (2026-09-14), which would
    # have set a second bit in a byte whose only known meaning is bit 0. The
    # listed byte is now exactly 1 whatever the settings say.
    check('room settings do not leak into the listed byte',
          gate.roomlist_entry_sn(dict(r, f4=0x80), 'x')[31] == 1,
          gate.roomlist_entry_sn(dict(r, f4=0x80), 'x')[31])
    # f7 is the room PASSWORD and must not be broadcast to browsers.
    check('the room password is not echoed into the record',
          gate.roomlist_entry_sn(dict(r, f7=1100), 'x')[27:31] == bytes(4))
    check('an empty room still yields 36 bytes',
          len(gate.roomlist_entry_sn(None, '')) == 36)


def test_sn_join_record():
    """0x4325 -- 50 bytes, the host's half of matchmaking.

    Exactly the opponent-record tail of 0x4a13 and into the same context
    offsets, so the two must agree field for field or the host and the searcher
    would see different opponents.
    """
    p = {'id': 10, 'name': 'qq', 'dancer': 3}
    j = gate.build_sn_join_record(p)
    check('join record is 50 bytes', len(j) == 50, len(j))
    check('join id at +0', struct.unpack_from('>i', j, 0)[0] == 10)
    check('join name at +4', j[4:20] == b'qq'.ljust(16, bytes(1)))
    check('join dancer at +20', j[20] == 3, j[20])
    # The match record embeds the same player fields starting at wire +18.
    mrec = gate.build_sn_match_record(p, song=1)
    check('join record matches the 0x4a13 opponent block',
          j[:21] == mrec[18:39], (j[:21].hex(), mrec[18:39].hex()))
    check('join record with no player is still 50 bytes',
          len(gate.build_sn_join_record(None)) == 50)


def test_sn_competition_shapes():
    """SuperNOVA's 0x50xx family is COMPETITIONS, not Extreme 2's Ranking
    Challenge, and the two must not share a body builder.

    Even the requests differ: 0x5000 carries a 4-byte competition id in
    SuperNOVA and a 2-byte card selector in Extreme 2. The replies differ more
    -- 74 bytes into ctx+0x12ed8.. against a 138-byte card -- so serving the
    Extreme 2 record to a SuperNOVA client hands it 74 bytes of the wrong
    struct. Pin the two sizes so they cannot be crossed again.
    """
    check('E2 RC challenge is 138 bytes',
          len(gate.rc_info_body(list(range(8)), probe=False)) == 138
          if hasattr(gate, 'rc_info_body') else True)
    check('SN competition list record is 50 bytes',
          len(gate.sn_comp_body([(1, 'EVENT', 100, 200)])) == 50)
    check('SN competition list caps at ten',
          len(gate.sn_comp_body([(i, 'E', 0, 1) for i in range(20)]))
          == 10 * 50)


def test_sn_ranking_row():
    """SuperNOVA's 0x6002 row is 45 bytes where Extreme 2's is 49.

    0x6002 is a read-until-empty loop, so the four-byte difference leaves a
    partial record the parser happily reads: two real players drew four rows on
    screen, the last two nameless. Third time this exact shape of bug has bitten
    -- 0x3012, 0x4212, now 0x6002 -- so pin both lengths.
    """
    sn = gate.ranking_entry_sn(1, 'qq', 10, 3)
    e2 = gate.ranking_entry(1, 'qq', 3)
    check('SN ranking row is 45 bytes', len(sn) == 45, len(sn))
    check('E2 ranking row is still 49 bytes', len(e2) == 49, len(e2))
    check('SN rank at +0', struct.unpack_from('>i', sn, 0)[0] == 1)
    check('SN id at +4', struct.unpack_from('>i', sn, 4)[0] == 10)
    check('SN name at +8', sn[8:24] == b'qq'.ljust(16, bytes(1)))
    check('SN dancer at +24', sn[24] == 3, sn[24])
    check('two SN rows are exactly 90 bytes',
          len(sn + gate.ranking_entry_sn(2, 'aaa', 11, 13)) == 90)


def test_sn_peeraddr_pair_order():
    """0x4b01 puts the PUBLIC pair first, not the local one.

    The opposite of 0x411a SetMyAddr and of Extreme 2's 0x44b0, and getting it
    backwards is silent: the client dials whatever is in the public slot, so a
    local-first record made it dial 192.0.2.100 -- unreachable -- and a whole
    song played with no inputs crossing. FUN_00a4a4f0 copies pair 1 to the
    connect block's PUBLIC slots and pair 2 to its LOCAL slots.
    """
    p = {'id': 11, 'endpoint': {'local': '192.0.2.100', 'local_port': 5730,
                                'public': '192.0.2.37', 'public_port': 6000}}
    r = gate.build_sn_peeraddr_record(p)
    check('peer address record is 44 bytes', len(r) == 44, len(r))
    check('pair 1 is the PUBLIC address',
          r[4:20].split(bytes(1))[0] == b'192.0.2.37', r[4:20])
    check('pair 1 carries the public port',
          struct.unpack_from('>H', r, 20)[0] == 6000)
    check('pair 2 is the LOCAL address',
          r[22:38].split(bytes(1))[0] == b'192.0.2.100', r[22:38])
    check('pair 2 carries the local port',
          struct.unpack_from('>H', r, 38)[0] == 5730)
    check('the opponent id is last',
          struct.unpack_from('>i', r, 40)[0] == 11)


def test_udp_relay():
    """The UDP relay actually forwards, both ways, from a cold start.

    SuperNOVA dials its opponent directly and two consoles under one emulator
    cannot be dialled, so this is the difference between a match that plays and
    one that reaches the song with no inputs crossing. Uses loopback ports well
    away from the defaults.
    """
    import udprelay
    r = udprelay.Relay('127.0.0.1', 21700, 2, log=lambda m: None).start()
    try:
        pair = r.alloc()
        check('relay hands out a pair', pair is not None)
        if pair is None:
            return
        a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        a.settimeout(2)
        b.settimeout(2)
        try:
            # A speaks before B is known: must be dropped, not echoed or fatal.
            a.sendto(b'early', ('127.0.0.1', pair.a))
            time.sleep(0.2)
            b.sendto(b'hello-from-B', ('127.0.0.1', pair.b))
            check('B reaches A', a.recvfrom(2048)[0] == b'hello-from-B')
            a.sendto(b'reply-from-A', ('127.0.0.1', pair.a))
            check('A reaches B', b.recvfrom(2048)[0] == b'reply-from-A')
            # 60 bytes is the real peer frame size seen on the wire.
            a.sendto(b'x' * 60, ('127.0.0.1', pair.a))
            check('a 60-byte peer frame survives',
                  b.recvfrom(2048)[0] == b'x' * 60)
        finally:
            a.close()
            b.close()
        r.release(pair)
        check('a released pair can be reused', r.alloc() is not None)
    finally:
        r.stop()
    # And the record built from a relay endpoint points BOTH candidates at it,
    # so whichever branch the client's hairpin check takes, it dials the relay.
    rec = gate.build_sn_peeraddr_record({'id': 7}, dial=('10.0.0.1', 19600))
    check('relayed record: public candidate is the relay',
          rec[4:20].split(bytes(1))[0] == b'10.0.0.1'
          and struct.unpack_from('>H', rec, 20)[0] == 19600)
    check('relayed record: local candidate is the relay too',
          rec[22:38].split(bytes(1))[0] == b'10.0.0.1'
          and struct.unpack_from('>H', rec, 38)[0] == 19600)


def test_public_address():
    """Internet clients are told our public address, LAN clients our local one.

    Behind a home router a port-forwarded connection arrives on the LAN
    address, so echoing the socket's local end back sends internet players to
    192.168.x.x. Nothing here touches the network: lookups are stubbed, and the
    one STUN exchange runs against this project's own responder on loopback.
    """
    import threading
    import types
    import publicaddr
    import stun

    check('10/8, 192.168/16, 100.64/10 and loopback are not global',
          not any(publicaddr.is_global(ip) for ip in
                  ('10.1.2.3', '192.168.1.5', '100.64.1.1', '127.0.0.1')))
    check('an internet address is global', publicaddr.is_global('8.8.8.8'))

    calls = []

    def stub(answer):
        p = publicaddr.PublicAddress('auto', interval=3600)
        p.lookup = lambda: calls.append(1) or answer
        return p

    p = stub('1.2.3.4')
    check('LAN client gets the local address',
          p.for_client('192.168.1.20', '192.168.1.2') == '192.168.1.2')
    check('  and nothing is looked up for it', not calls)
    check('internet client gets the public address',
          p.for_client('8.8.8.8', '192.168.1.2') == '1.2.3.4')
    check('  looked up once, then cached',
          p.for_client('9.9.9.9', '192.168.1.2') == '1.2.3.4'
          and len(calls) == 1, len(calls))
    check('a server that owns a public address never looks one up',
          stub('1.2.3.4').for_client('8.8.8.8', '5.6.7.8') == '5.6.7.8')
    check('a failed lookup falls back to the local address',
          stub(None).for_client('8.8.8.8', '192.168.1.2') == '192.168.1.2')
    check('off gives everyone the local address',
          publicaddr.PublicAddress('off').for_client('8.8.8.8', '192.168.1.2')
          == '192.168.1.2')

    # A modern request against the old responder: it echoes the 16 bytes after
    # the length, which are our cookie and id, and answers MAPPED-ADDRESS.
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(('127.0.0.1', 0))
    srv.settimeout(2)

    def answer():
        try:
            data, src = srv.recvfrom(2048)
        except OSError:
            return
        tid = stun.parse(data)[1]
        srv.sendto(stun.build_response(tid, '1.2.3.4', 5678, '127.0.0.1', 1,
                                       '127.0.0.1', 2), src)

    t = threading.Thread(target=answer, daemon=True)
    t.start()
    got = publicaddr.stun_query(('127.0.0.1', srv.getsockname()[1]), timeout=2)
    t.join()
    srv.close()
    check('STUN lookup reads a MAPPED-ADDRESS answer', got == '1.2.3.4', got)
    ip = struct.unpack('>I', socket.inet_aton('1.2.3.4'))[0] ^ publicaddr.MAGIC
    attr = struct.pack('>HHBBHI', 0x0020, 8, 0, 1, 5678 ^ 0x2112, ip)
    msg = (struct.pack('>HHI', 0x0101, len(attr), publicaddr.MAGIC)
           + bytes(12) + attr)
    check('STUN lookup reads an XOR-MAPPED-ADDRESS answer',
          publicaddr.mapped_address(msg) == '1.2.3.4')

    # The gate's side of it: SvrList, and the relay endpoint of each console.
    args = types.SimpleNamespace(svr_host='', svr_addr='auto', relay_addr=None)
    conn = types.SimpleNamespace(getsockname=lambda: ('192.168.1.2', 9573))

    def session(client):
        return types.SimpleNamespace(args=args, conn=conn, addr=(client, 40000))

    saved = gate.PUBLIC, gate.RELAY
    gate.PUBLIC = stub('1.2.3.4')
    try:
        host = gate.Session.advertised_host
        check('SvrList sends an internet client to the public address',
              host(session('8.8.8.8')) == '1.2.3.4')
        check('SvrList sends a LAN client to the local address',
              host(session('192.168.1.20')) == '192.168.1.2')
        args.svr_addr = '10.9.8.7'
        check('an explicit --svr-addr still wins for everyone',
              host(session('8.8.8.8')) == '10.9.8.7')
        args.svr_addr = 'auto'

        gate.RELAY = types.SimpleNamespace(
            alloc=lambda: types.SimpleNamespace(a=19600, b=19601))

        def console(addr):
            s = types.SimpleNamespace(args=args, relay_dial=None,
                                      relay_pair=None, log=lambda m: None,
                                      who=lambda: '?')
            s.advertised_host = lambda: addr
            return s

        near, far = console('192.168.1.2'), console('1.2.3.4')
        gate.Session.relay_link(near, far)
        check('relay: a LAN console and an internet one each get their own',
              near.relay_dial == ('192.168.1.2', 19600)
              and far.relay_dial == ('1.2.3.4', 19601),
              (near.relay_dial, far.relay_dial))
    finally:
        gate.PUBLIC, gate.RELAY = saved


def test_response_sequence():
    def seq(r):
        return gate.response_sequence(r)
    check('SvrInfo request 0x2008 -> 2009/200a/200b',
          seq(0x2008) == ((0x2009, 0x200a, 0x200b), True))
    # 0x2005, NOT 0x2001 -- the +1 rule is wrong here and it cost a live round
    check('SvrList request 0x2005 -> 2002/2003/2004',
          seq(0x2005) == ((0x2002, 0x2003, 0x2004), True))
    check('SvrTime request 0x2006 -> just 0x2007', seq(0x2006) == ((0x2007,), True))
    # irregular mapping: +1 would give 0x500a
    check('GetRCIdList 0x5009 -> 0x5010 (not +1)', seq(0x5009) == ((0x5010,), True))
    # unknown request must be flagged as a guess, not silently wrong
    check('unknown request flagged as guess', seq(0xabcd) == ((0xabce,), False))
    ok = all(list(v) == sorted(v) and len(set(v)) == len(v)
             for v in gate.REQUEST_RESPONSES.values())
    check('all response groups ascending and unique', ok)
    check('no request opcode is also a response opcode',
          not (set(gate.REQUEST_RESPONSES) &
               {o for v in gate.REQUEST_RESPONSES.values() for o in v}))


def test_svrinfo_record():
    r = gate.svrinfo_record(ident=0x01020304, type_=2, users=3,
                            addr='192.0.2.10', name='DDR')
    check('record min wire size is 90', len(r) == 90, len(r))
    check('  u32 is big-endian', r[0:4] == bytes([1, 2, 3, 4]), r[0:4].hex())
    check('  type byte', r[4] == 2, r[4])
    check('  users byte', r[5] == 3, r[5])
    check('  addr field is exactly 19 bytes',
          r[6:25] == b'192.0.2.10'.ljust(19, bytes([0])), r[6:25])
    check('  name field is exactly 64 bytes',
          r[25:89] == b'DDR'.ljust(64, bytes([0])), len(r[25:89]))
    check('  trailing cstring terminator', r[89:] == bytes([0]), r[89:])
    r2 = gate.svrinfo_record(1, 1, 1, 'x' * 40, 'y' * 200)
    check('oversize addr/name truncated to 90', len(r2) == 90, len(r2))
    check('  addr truncated to 19', r2[6:25] == b'x' * 19)
    check('  name truncated to 64', r2[25:89] == b'y' * 64)
    key = bytes([1, 2, 3, 4])
    f = gate.build(0x200a, 9, r, key)
    plain = gate.xor(f, key)
    op, ln, _ = struct.unpack('>HHI', plain[:8])
    check('record survives frame build/parse',
          op == 0x200a and ln == len(r) and plain[24:24 + ln] == r)


def test_stat_records():
    """0x4212 and 0x4103 wire sizes, and the probe sentinels."""
    e = gate.playerlist_entry(7, 'Cas')
    check('0x4212 record is 75 bytes', len(e) == 75, len(e))
    check('0x4212 id then name', struct.unpack_from('>I', e)[0] == 7
          and e[4:20].rstrip(bytes(1)) == b'Cas')
    check('0x4212 unknown fields default to zero', e[20:] == bytes(len(e) - 20))
    p = gate.playerlist_entry(7, 'Cas', probe=True)
    check('0x4212 probe is still 75 bytes', len(p) == 75, len(p))
    check('0x4212 probe field 7 == 777',
          struct.unpack_from('>I', p, 21 + 3 * 4)[0] == 777)
    check('0x4212 probe field 19 == 1919',
          struct.unpack_from('>H', p, 73)[0] == 1919)
    check('0x4212 probe sentinels are all distinct',
          len({gate.probe_value(n, s2) for n, s2, _ in gate.PLAYERLIST_FIELDS
               if n not in (1, 2)}) == 17)
    r = gate.playerinfo_record(7, 'Cas')
    check('0x4103 record is 145 bytes', len(r) == 145, len(r))
    check('0x4103 status is the leading u32 and is 0',
          struct.unpack_from('>I', r)[0] == 0)
    # A non-zero status must send NOTHING else: the parser at 0x0085a750 stops
    # before reading a single field, so trailing bytes would desync the cursor.
    check('0x4103 non-zero status truncates to 4 bytes',
          len(gate.playerinfo_record(7, 'Cas', status=3)) == 4)
    check('0x4103 probe is still 145 bytes',
          len(gate.playerinfo_record(7, 'Cas', probe=True)) == 145)
    check('probe legend covers both messages',
          '0x4212' in gate.probe_legend() and '0x4103' in gate.probe_legend())


def test_log_records():
    """The three PERSONAL DATA logs (0x4109/13/17 openers + data records)."""
    check('log opener is 5 bytes (u32 status + u8 count)',
          len(gate.log_open(3)) == 5)
    check('log opener carries the count',
          gate.log_open(7)[4] == 7 and struct.unpack_from('>I', gate.log_open(7))[0] == 0)
    for name, sizes, wire in (('HtoH', gate.HTOH_LOG_SIZES, 12),
                              ('Point', gate.POINT_LOG_SIZES, 6),
                              ('RC', gate.RC_LOG_SIZES, 17)):
        r = gate.log_records(sizes, 3, probe=True)
        check('%s log: 3 records = %d bytes' % (name, wire * 3),
              len(r) == wire * 3, len(r))
        check('%s log: zeros when not probing' % name,
              gate.log_records(sizes, 3) == bytes(wire * 3))
    # RRRFF encoding: record 2, field 3 of the HtoH log is a u16 == 2003
    r = gate.log_records(gate.HTOH_LOG_SIZES, 3, probe=True)
    check('log probe encodes record and field (rec2 field3 == 2003)',
          struct.unpack_from('>H', r, 12 + 4 + 2)[0] == 2003,
          struct.unpack_from('>H', r, 12 + 4 + 2)[0])
    # The caps are the client's, and exceeding them makes it invent -610.
    check('caps match the parsers (60/60/120)',
          [c for _, _, c in gate.LOG_GROUPS.values()] == [60, 60, 120])


def test_ranking_record():
    """0x6002 ranking record -- 49 bytes, dancer+name pairing, cap 100."""
    e = gate.ranking_entry(1, 'Cas', 18, probe=True)
    check('0x6002 record is 49 bytes', len(e) == gate.RANKING_WIRE, len(e))
    check('0x6002 rank is the leading u32', struct.unpack_from('>I', e)[0] == 1)
    check('0x6002 name is field 3', e[8:24].rstrip(bytes(1)) == b'Cas', e[8:24])
    check('0x6002 dancer is field 4 and is never probed', e[24] == 18, e[24])
    check('0x6002 probe band is 200+N (field 5 == 205)',
          struct.unpack_from('>I', e, 25)[0] == 205)
    check('0x6002 zeros when not probing',
          struct.unpack_from('>I', gate.ranking_entry(1, 'x'), 25)[0] == 0)
    check('ranking cap matches the parser', gate.RANKING_CAP == 100)


def test_match_record():
    """0x44b0, the match message -- 61 bytes, field-for-field against parser 0x0085a190.

    Wire order is the parser's CALL order, not the struct order:
        u32 id / 16 name / 16 LOCAL addr / u16 LOCAL port
                         / 16 PUBLIC addr / u16 PUBLIC port / u8 u8 u16 u8
    """
    body = gate.build_match_record({
        'id': 0x01020304, 'name': 'Cas',
        'endpoint': {'local': '192.0.2.100', 'local_port': 5730,
                     'public': '192.0.2.20', 'public_port': 5731}})
    check('0x44b0 is 61 bytes', len(body) == 61, len(body))
    check('0x44b0 id', struct.unpack_from('>I', body, 0)[0] == 0x01020304)
    check('0x44b0 name at +4',
          body[4:20].rstrip(b'\x00') == b'Cas', body[4:20])
    check('0x44b0 LOCAL addr at +20',
          body[20:36].rstrip(b'\x00') == b'192.0.2.100', body[20:36])
    check('0x44b0 LOCAL port at +36',
          struct.unpack_from('>H', body, 36)[0] == 5730)
    check('0x44b0 PUBLIC addr at +38',
          body[38:54].rstrip(b'\x00') == b'192.0.2.20', body[38:54])
    check('0x44b0 PUBLIC port at +54',
          struct.unpack_from('>H', body, 54)[0] == 5731)
    # A 16-byte name must not overflow into the next field, and a missing
    # endpoint must still produce a well-formed 61-byte record.
    long_name = gate.build_match_record({'id': 1, 'name': 'X' * 40})
    check('0x44b0 over-long name is truncated, not overflowed',
          len(long_name) == 61 and long_name[4:20] == b'X' * 16)
    check('0x44b0 survives a player with no SetMyAddr',
          len(gate.build_match_record({})) == 61)
    # The tail: R+0x00 game mode, R+0x01 unread, R+0x04 song, R+0x02 unread.
    tail = gate.build_match_record({'id': 1}, tail=(2, 0x11, 5, 0x22))
    check('0x44b0 game mode at +56', tail[56] == 2, tail[56])
    check('0x44b0 song at +58', struct.unpack_from('>H', tail, 58)[0] == 5)
    # Out of range in either direction is clamped, not passed through: the song
    # index walks off a table with 80 entries and the mode has four cases.
    check('0x44b0 song >= 80 is clamped to 0',
          struct.unpack_from('>H', gate.build_match_record(
              {'id': 1}, tail=(0, 0, gate.RC_SONG_IDS, 0)), 58)[0] == 0)
    check('0x44b0 mode outside 0..3 is clamped to 0',
          gate.build_match_record({'id': 1}, tail=(4, 0, 0, 0))[56] == 0)


def test_rc_info():
    """0x5001 GetRCInfo -- 138 bytes: an 8-field header then ten 12-byte rows."""
    body = gate.rc_info(first_song=3, hdr=[7, 1, 0, 0, 0, 0, 0, 2])
    check('0x5001 is 138 bytes', len(body) == 138, len(body))
    check('0x5001 status is the leading u32 and is 0',
          struct.unpack_from('>I', body)[0] == 0)
    check('0x5001 challenge id (R+0x04) at +4',
          struct.unpack_from('>I', body, 4)[0] == 7)
    check('0x5001 class (R+0x00) at +8', body[8] == 1, body[8])
    check('0x5001 difficulty (R+0x10) is the LAST header byte',
          body[17] == 2, body[17])
    rows = [body[18 + i * 12:30 + i * 12] for i in range(10)]
    check('0x5001 first song id', struct.unpack_from('>H', rows[0])[0] == 3)
    check('0x5001 song ids are consecutive',
          [struct.unpack_from('>H', r)[0] for r in rows] == list(range(3, 13)))
    # The nine option bytes must default to the tuple the client itself
    # compares against; all-zero is what made every challenge read as modified.
    check('0x5001 rows carry the client default options',
          all(tuple(r[3:12]) == gate.RC_DEFAULT_OPTS for r in rows),
          rows[0][2:12].hex())
    check('0x5001 R+0x12 defaults to 0 and is not one of the options',
          all(r[2] == 0 for r in rows))
    short = gate.rc_info(first_song=1, stages=3)
    check('0x5001 short challenge is still 138 bytes', len(short) == 138)
    ids = [struct.unpack_from('>H', short, 18 + i * 12)[0] for i in range(10)]
    check('0x5001 stages=3 terminates row 3 with 0xffff',
          ids[:4] == [1, 2, 3, gate.RC_END_SONG], ids)
    check('0x5001 non-zero status truncates to 4 bytes',
          len(gate.rc_info(status=1)) == 4)


def test_rc_challenge_selector():
    """The two 0x5000 bytes address a card, and the mapping is not a*2+b."""
    sel = gate.rc_challenge
    check('0x5000 (0,0) is featured card 0', sel((0, 0)) == 0)
    check('0x5000 (1,0) is featured card 1', sel((1, 0)) == 1)
    # List entry i asks with (i & 1, i/2 + 1); that has to round-trip.
    got = [sel((i & 1, i // 2 + 1)) for i in range(6)]
    check('0x5000 list selectors are distinct and ordered',
          got == [2, 3, 4, 5, 6, 7], got)


def test_rule_mask():
    """0x441e -- u32 status + THREE u8s (score, combo, survival)."""
    body = gate.rule_mask_body((1, 1, 1))
    check('0x441e is 7 bytes', len(body) == 7, len(body))
    check('0x441e status is 0', struct.unpack_from('>I', body)[0] == 0)
    check('0x441e all three rules on', body[4:] == b'\x01\x01\x01', body[4:])
    check('0x441e flags are booleans, tested == 1 by the client',
          gate.rule_mask_body((5, 0, 2))[4:] == b'\x01\x00\x01')
    check('0x441e short rule list is padded, not truncated',
          len(gate.rule_mask_body((1,))) == 7)
    check('0x441e names match the client\'s result columns',
          gate.RULE_NAMES == ('score', 'combo', 'survival'))


def test_sn_song_list():
    """The 0x8002 availability list -- the online song unlock.

    13 bytes per record with no delimiter and no count, because the client's
    loop reads until the payload runs out. Getting the stride wrong desyncs
    every record after the first, so the size checks here are the point.
    """
    ids = gate.sn_song_ids('online')
    check('online mode unlocks 5 songs', ids == [0x4a, 0x4c, 0x4b, 0x4d, 0x4e], ids)
    check('  in download order (felw nizi punc silv trim)',
          ids == [i for i, _, _ in gate.SN_ONLINE_SONGS])
    check('all mode unlocks all 79', gate.sn_song_ids('all') == list(range(79)))
    check('none mode unlocks nothing', gate.sn_song_ids('none') == [])

    bodies = gate.sn_song_avail_bodies(ids)
    check('five songs fit one frame', len(bodies) == 1, len(bodies))
    b = bodies[0]
    check('  body is 5 * 13 bytes', len(b) == 65, len(b))
    check('  first record id is 0x4a big-endian',
          b[0:4] == bytes([0, 0, 0, 0x4a]), b[0:4].hex())
    check('  five difficulty flags follow the id',
          b[4:9] == bytes([1, 1, 1, 1, 1]), b[4:9].hex())
    check('  trailing s32 defaults to 0', b[9:13] == bytes(4), b[9:13].hex())
    check('  second record starts at 13', b[13:17] == bytes([0, 0, 0, 0x4c]),
          b[13:17].hex())

    # 79 records is 1027 bytes, two over the frame cap -- the case that forced
    # the chunked DATA path.
    full = gate.sn_song_avail_bodies(gate.sn_song_ids('all'))
    check('79 songs need two frames', len(full) == 2, len(full))
    check('  no frame exceeds the payload cap',
          all(len(x) <= gate.MAX_PAYLOAD for x in full), [len(x) for x in full])
    check('  all 79 records survive the split',
          sum(len(x) for x in full) == 79 * 13, sum(len(x) for x in full))
    check('  every frame is a whole number of records',
          all(len(x) % 13 == 0 for x in full))

    check('empty list still sends one empty DATA frame',
          gate.sn_song_avail_bodies([]) == [b''])
    check('list is capped at the client array size of 90',
          sum(len(x) for x in gate.sn_song_avail_bodies(range(200))) == 90 * 13)

    part = gate.sn_song_avail_bodies([1], difficulties=(1, 0, 0, 0, 0))
    check('per-difficulty flags are independent',
          part[0][4:9] == bytes([1, 0, 0, 0, 0]), part[0][4:9].hex())


def test_sn_song_names():
    """The 0x8006 list -- s32 id + a FIXED 32-byte name, capped at 20."""
    b = gate.sn_song_name_body([(7, 'ABC'), (8, 'D' * 40)])
    check('0x8006 record is 36 bytes', len(b) == 72, len(b))
    check('  id is big-endian', b[0:4] == bytes([0, 0, 0, 7]), b[0:4].hex())
    check('  short name is NUL-padded to 32',
          b[4:36] == b'ABC' + bytes(29), b[4:36].hex())
    check('  long name is truncated to 32, not spilled',
          b[40:72] == b'D' * 32, b[40:72][:8].hex())
    check('0x8006 capped at 20 entries',
          len(gate.sn_song_name_body([(i, 'x') for i in range(50)])) == 20 * 36)
    check('0x8006 empty list is an empty body', gate.sn_song_name_body([]) == b'')


def test_sn_rule_mask():
    """SuperNOVA's 0x441e reads FOUR u8 where Extreme 2's reads three."""
    b = gate.sn_rule_mask_body((1, 1, 1, 1))
    check('SN rule mask is 8 bytes', len(b) == 8, len(b))
    check('  Extreme 2 rule mask is 7', len(gate.rule_mask_body((1, 1, 1))) == 7)
    check('  status first, big-endian', b[0:4] == bytes(4), b[0:4].hex())
    check('  four flags follow', b[4:8] == bytes([1, 1, 1, 1]), b[4:8].hex())
    check('  flags normalise to 0/1',
          gate.sn_rule_mask_body((0, 5, 0, 0))[4:8] == bytes([0, 1, 0, 0]))
    check('  short input is padded to four',
          len(gate.sn_rule_mask_body((1,))) == 8)
    check('  non-zero status suppresses the flags',
          gate.sn_rule_mask_body((1, 1, 1, 1), status=3) == b'\x00\x00\x00\x03')


def test_peer_channel_not_answered():
    """0x4400 is the peer channel: relayed, never answered as an RPC.

    The client BUILDS 0x4400 itself (0x0085a6b0, sent on slot 2), so the +1
    fallback would invent a 0x4401 reply to a message that is not a request.
    """
    check('0x4400 is in NO_REPLY', 0x4400 in gate.NO_REPLY)
    check('0x0003 is still in NO_REPLY', 0x0003 in gate.NO_REPLY)
    check('0x44b0 has no request mapping (push-only)',
          0x44b0 not in gate.REQUEST_RESPONSES
          and not any(0x44b0 in v for v in gate.REQUEST_RESPONSES.values()))

def test_live_socket():
    here = os.path.dirname(os.path.abspath(__file__))
    # The scratch keyfile goes in a temp directory, not next to the source. The
    # container mounts the server read-only, so writing here fails, and a test
    # should not drop files in the tree it is testing either way.
    keyfile = os.path.join(tempfile.gettempdir(), 'ddr_selftest_key.bin')
    if os.path.exists(keyfile):
        os.remove(keyfile)
    port = 19573
    proc = subprocess.Popen(
        [sys.executable, os.path.join(here, 'gate.py'), '--port', str(port),
         '--keyfile', keyfile, '--reply-empty'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        key = bytes([0x8b, 0x2e, 0x41, 0xd0])
        deadline = time.time() + 10
        sock = None
        while time.time() < deadline:
            try:
                sock = socket.create_connection(('127.0.0.1', port), timeout=2)
                break
            except OSError:
                time.sleep(0.2)
        check('server accepted a connection', sock is not None)
        if sock is None:
            return
        sock.sendall(gate.build(0x2008, 1, b'\x01\x02\x03\x04payload', key))
        sock.settimeout(5)
        try:
            resp = sock.recv(4096)
        except socket.timeout:
            resp = b''
        # 0x2008 is SvrInfo, a THREE-part response -- expect the whole sequence.
        deadline2 = time.time() + 5
        while len(resp) < gate.HDR * 3 and time.time() < deadline2:
            try:
                more = sock.recv(4096)
            except socket.timeout:
                break
            if not more:
                break
            resp += more
        check('server sent the full 3-part sequence',
              len(resp) == gate.HDR * 3, '%d bytes' % len(resp))
        got = []
        for i in range(0, len(resp) - gate.HDR + 1, gate.HDR):
            plain = gate.xor(resp[i:i + gate.HDR], key)
            opcode, length, _ = struct.unpack('>HHI', plain[:8])
            got.append(opcode)
            check('  part %d length is 0' % (i // gate.HDR), length == 0, length)
            check('  part %d md5 is valid' % (i // gate.HDR),
                  gate.digest(plain[0:8], b'') == plain[8:24])
        check('sequence is SvrInfo 2009/200a/200b',
              got == [0x2009, 0x200a, 0x200b], [hex(o) for o in got])
        check('terminator is last', got and got[-1] == 0x200b)
        sock.close()
        time.sleep(0.5)
        check('key persisted to disk',
              os.path.exists(keyfile) and open(keyfile, 'rb').read() == key)
    finally:
        proc.terminate()
        try:
            out, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            out = ''
        print('\n--- server log ---')
        print(out.strip())
        if os.path.exists(keyfile):
            os.remove(keyfile)


def test_db_and_results():
    """Accounts round-trip through the database, and results are kept, ranked
    and served back. Uses fake sessions the way the SuperNOVA tests do."""
    import types
    import db
    import results
    from schedule import rc_week, RC_WEEK_SECONDS
    d = tempfile.mkdtemp()
    # An existing server's JSON is imported once, then ignored.
    now = 1_800_000_000
    week, _ = rc_week(now)
    with open(os.path.join(d, 'state.json'), 'w') as f:
        json.dump({'accounts': {'ab': {'player_files': [
            {'slot': 0, 'id': 12, 'name': 'Cas', 'dancer': 18,
             'options': 'aabb'}]}}, 'next_id': 13,
            'friends': {'12': {'10': 1}}}, f)
    db.close()
    db.setup(d)
    st = db.load_state()
    check('db import: account', 'ab' in st['accounts'])
    check('db import: player-file extra field',
          st['accounts']['ab']['player_files'][0].get('options') == 'aabb')
    check('db import: friends', st['friends'] == {'12': {'10': 1}})
    check('db import: next_id', st['next_id'] == 13)
    # Save a change and reload from the db alone.
    st['accounts']['cd'] = {'player_files': [
        {'slot': 0, 'id': 99, 'name': 'Bo', 'dancer': 2}]}
    db.save_state(st)
    check('db round-trip', 'cd' in db.load_state()['accounts'])
    # A corrupt leftover state.json is ignored once the db exists.
    with open(os.path.join(d, 'state.json'), 'w') as f:
        f.write('{corrupt')
    db.close()
    db.setup(d)
    check('db is authoritative over a corrupt state.json',
          len(db.load_state()['accounts']) == 2)

    # Results through the gate's Session hooks.
    args = types.SimpleNamespace(rc_flag=None, svr_time=now, stat_probe=False,
                                 stat_probe_logs=3)

    def mk(pid, name):
        f = types.SimpleNamespace(
            args=args, is_sn=False, player={'id': pid, 'dancer': 18},
            rc_card=0, rc_songs={0: [61, 46, 31]}, rank_req=None, endgame=None,
            endgame_peer=None, peer=None, rc_try_req=b'')
        f.log = lambda *a: None
        f.who = lambda nm=name: nm
        for m in ('rc_now_week', 'record_rc', 'record_endgame', 'x2_stats',
                  'personal_log', 'x2_ranking_body'):
            setattr(f, m, types.MethodType(getattr(gate.Session, m), f))
        return f

    a, b = mk(12, 'aaa'), mk(10, 'qq')
    for f in (a, b):
        (gate.LOBBY.add if isinstance(gate.LOBBY, set)
         else gate.LOBBY.append)(f)
    try:
        a.record_rc(0x5004, struct.pack('>iB', 12, 0))
        a.record_rc(0x5006, bytes.fromhex('0000000c00f350a00001cd55003b0000'))
        check('RC upload kept',
              results.rc_board(week, 0, now + 1)[0]['rc_score'] == 15945888)
        check('RC try counted per card',
              results.rc_tries(12, week, now + 1) == (1, 0))
        # Head-to-head: first report waits, second pairs even after the room
        # pairing was cleared.
        a.peer, b.peer = b, a
        a.record_endgame(struct.pack('>iHIH', 6958426, 0, 14400, 109) + bytes(24))
        check('endgame first report waits',
              not db.h2h_tally(week, now + 9) and a.endgame is not None)
        b.peer = None
        b.record_endgame(struct.pack('>iHIH', 255617, 0, 14400, 8) + bytes(24))
        rows = db._h2h_rows(week, now + 9)
        # The stored a/b order depends on which side completed the pairing, so
        # check the winner by score rather than by position.
        winner = (rows[0]['a_player'] if rows[0]['a_score'] > rows[0]['b_score']
                  else rows[0]['b_player']) if rows else None
        check('endgame pairs, higher score (player 12) wins',
              len(rows) == 1 and winner == 12)
        a.rank_req = {'type': 0, 'period': week, 'flag': 0, 'start': 1,
                      'count': 100}
        body = a.x2_ranking_body([])
        check('head-to-head board: winner first',
              len(body) == 2 * gate.RANKING_WIRE
              and body.index(b'aaa') < body.index(b'qq'))
        nxt = (week % 60) + 1
        a.rank_req = {'type': 2, 'period': nxt, 'flag': 0}
        check('empty board falls back to online players on zero',
              a.x2_ranking_body([b]) == gate.ranking_entry(1, 'qq', 18))
        stats = a.x2_stats(12)
        check('player info stays 145 bytes with stats',
              len(gate.playerinfo_record(12, 'aaa', 18,
                                         stats=gate.info_stats(stats))) == 145)
        check('player list entry stays 75 bytes with stats',
              len(gate.playerlist_entry(12, 'aaa', 18,
                                        stats=gate.list_stats(stats))) == 75)
        for kind, sizes, nb in (('HtoH', gate.HTOH_LOG_SIZES, 12),
                                ('Point', gate.POINT_LOG_SIZES, 6),
                                ('RC', gate.RC_LOG_SIZES, 17)):
            rws = a.personal_log(kind)
            check('%s log: one record, %d wire bytes' % (kind, nb),
                  len(rws) == 1 and len(gate.log_rows(sizes, rws)) == nb)
        # Week numbers wrap: 60 weeks on, the same number is empty.
        check('week number reused a cycle later ignores old rows',
              results.rc_board(week, 0, now + RC_WEEK_SECONDS * 60) == [])
    finally:
        (gate.LOBBY.discard if isinstance(gate.LOBBY, set)
         else gate.LOBBY.remove)(a)
        (gate.LOBBY.discard if isinstance(gate.LOBBY, set)
         else gate.LOBBY.remove)(b)
        db.close()


def test_credentials_and_sn_comp():
    """Trust-on-first-use password verification, and SuperNOVA tournament
    scoring (summed per-stage bests) with migration of the interim JSON."""
    import db
    import results
    d = tempfile.mkdtemp()
    db.close()
    db.setup(d)
    check('credential first-seen is recorded',
          results.credential_verify('cafe', '1111') == 'first')
    check('credential same digest logs in',
          results.credential_verify('cafe', '1111') == 'ok')
    check('credential wrong digest is rejected',
          results.credential_verify('cafe', '2222') == 'mismatch')
    check('credential is per-username, not shared',
          results.credential_verify('beef', '9999') == 'first')
    results.credential_set('cafe', '3333', source='register')
    check('credential_set (register/change) replaces it',
          results.credential_verify('cafe', '3333') == 'ok')

    results.sn_comp_record(1, 12, 'Cas', 1, 50000)
    results.sn_comp_record(1, 12, 'Cas', 1, 48906)   # worse, ignored
    results.sn_comp_record(1, 12, 'Cas', 2, 45000)
    results.sn_comp_record(1, 10, 'qq', 1, 90000)    # one lucky stage
    board = results.sn_comp_board(1)
    check('tournament board sums per-stage bests, full run beats one stage',
          [(r['name'], r['score'], r['stages']) for r in board]
          == [('Cas', 95000, 2), ('qq', 90000, 1)])
    db.close()

    d2 = tempfile.mkdtemp()
    with open(os.path.join(d2, 'state.json'), 'w') as f:
        json.dump({'accounts': {}, 'next_id': 1, 'friends': {},
                   'sn_comp': {'7': {'12': {'name': 'Cas',
                                            'stages': {'1': 48906, '2': 30000}}}}},
                  f)
    db.close()
    db.setup(d2)
    mig = results.sn_comp_board(7)
    check('tournament results migrate from interim state.json',
          mig and mig[0]['player'] == 12 and mig[0]['score'] == 78906
          and mig[0]['stages'] == 2)
    db.close()


if __name__ == '__main__':
    test_roundtrip()
    test_key_recovery()
    test_key_recovery_empty_payload()
    test_xor_index_continuity()
    test_sn_match_record()
    test_sn_playerlist_record()
    test_sn_friends()
    test_sn_news()
    test_sn_room_record()
    test_sn_join_record()
    test_sn_peeraddr_pair_order()
    test_udp_relay()
    test_public_address()
    test_sn_competition_shapes()
    test_sn_ranking_row()
    test_response_sequence()
    test_svrinfo_record()
    test_match_record()
    test_stat_records()
    test_log_records()
    test_ranking_record()
    test_rc_info()
    test_rc_challenge_selector()
    test_rule_mask()
    test_sn_song_list()
    test_sn_song_names()
    test_sn_rule_mask()
    test_peer_channel_not_answered()
    test_db_and_results()
    test_credentials_and_sn_comp()
    test_live_socket()
    print()
    if FAILS:
        print('%d FAILED: %s' % (len(FAILS), ', '.join(FAILS)))
        sys.exit(1)
    print('all tests passed')
