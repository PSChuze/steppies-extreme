#!/usr/bin/env python3
"""Offline checks for the boards: no disc, no network, no running gate.

    python3 boardtest.py

Builds a throwaway state directory with results, a live.json and a tiny
synthetic art bake, then checks the snapshots, the news, the Discord
post-then-edit cycle against a fake webhook, the rendered image, and the HTTP
routes.
"""
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

import boardart
import boardimg
import boards
import db
from schedule import rc_week

FAILS = []


def check(what, ok):
    print('%s  %s' % ('ok  ' if ok else 'FAIL', what))
    if not ok:
        FAILS.append(what)


def fake_art(d):
    """A bake with the real file names and sprite/font layout, every picture
    a flat colour, so the renderer runs end to end without a disc."""
    os.makedirs(d)
    files = list(boardart.SuperNova.IMAGES)
    for f in files:
        w, h = (640, 480) if f in ('bg.png', 'entry.png') else (512, 512)
        with open(os.path.join(d, f), 'wb') as fh:
            fh.write(boardart.png(w, h, bytes((40, 160, 200, 128)) * (w * h)))
    fonts = {n: dict(f, glyphs=boardart.glyph_metrics(
        (512, 512, bytes((0, 0, 0, 128)) * (512 * 512)), f))
        for n, f in boardart.SuperNova.FONTS.items()}
    with open(os.path.join(d, 'board.json'), 'w') as fh:
        json.dump({'game': 'sn', 'files': files, 'sprites': boardart.SuperNova.SPRITES,
                   'fonts': fonts, 'songs': {'74': "Feelings Won't Fade"}}, fh)


def fake_art_e2(d):
    """The same for Extreme 2: its file names and sprites, flat colours, and
    a font of uniform glyphs."""
    os.makedirs(d)
    files = list(boardart.Extreme2.IMAGES) + ['banners.png']
    for f in files:
        w, h = (224, 32 * 74) if f == 'banners.png' else (640, 448)
        with open(os.path.join(d, f), 'wb') as fh:
            fh.write(boardart.png(w, h, bytes((60, 40, 160, 255)) * (w * h)))
    sprites = dict(boardart.Extreme2.SPRITES)
    sprites.update({'song%d' % i: ['banners.png', 0, i * 32, 224, 32] for i in range(74)})
    glyphs = {chr(c): [(c - 32) % 16 * 15, (c - 32) // 16 * 24, 12] for c in range(33, 127)}
    with open(os.path.join(d, 'board.json'), 'w') as fh:
        json.dump({'game': 'e2', 'files': files, 'sprites': sprites, 'songs': {},
                   'fonts': {'sys': {'file': 'font.png', 'ch': 24, 'adv': 10, 'glyphs': glyphs},
                             'digits': {'file': 'digits.png', 'ch': 28, 'adv': 21,
                                        'glyphs': glyphs}}}, fh)


class FakeHook:
    def __init__(self):
        self.calls, self.n = [], 0

    def __call__(self, req, timeout=0):
        self.n += 1
        self.calls.append((req.get_method(), req.full_url, req.data or b''))
        n = self.n

        class R:
            status = 200

            def read(self):
                return json.dumps({'id': 'm%d' % n}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass
        return R()


def main():
    st = tempfile.mkdtemp(prefix='boardtest')
    try:
        run(st)
        run_bot(st)
    finally:
        db.close()
        shutil.rmtree(st, ignore_errors=True)
    print('\n%s' % ('all board checks passed' if not FAILS
                    else '%d FAILED: %s' % (len(FAILS), '; '.join(FAILS))))
    sys.exit(1 if FAILS else 0)


def run(st):
    db.setup(st)
    week, _ = rc_week()
    db.record_rc(1, 'ALICE', 0, week, 0, 800000, 100, 1000, 0, 5)
    db.record_rc(2, 'B*OB', 1, week, 0, 900000, 120, 1000, 0, 5)
    db.record_h2h(week, {'player': 1, 'name': 'ALICE', 'score': 5},
                  {'player': 2, 'name': 'B*OB', 'score': 3})
    db.record_h2h(week, {'player': 3, 'name': 'CAROL', 'score': 9},
                  {'player': 4, 'name': 'DAN', 'score': 1}, game='sn')
    db.sn_comp_record(1, 3, 'CAROL', 1, 400000)
    db.close()
    now = time.time()
    with open(os.path.join(st, 'live.json'), 'w') as fh:
        json.dump({'stamp': now, 'games': {
            'e2': {'count': 0, 'players': []},
            'sn': {'count': 1, 'players': [{'id': 3, 'name': 'CAROL', 'dancer': 0,
                                            'activity': 'lobby', 'vs': None}]},
            'sn2': {'count': 0, 'players': []}},
            # a flag-built competition: start and end move on every write
            'sn_comps': [{'id': 1, 'name': 'OPEN', 'songs': [74],
                          'start': now - 86400, 'end': now + 86400}]}, fh)
    fake_art(os.path.join(st, 'boardart', 'sn'))
    fake_art_e2(os.path.join(st, 'boardart', 'e2'))

    import boarde2
    import boardsn
    import boardsn2
    args = boards.build_parser().parse_args(['--state-dir', st, '--bind', '127.0.0.1'])
    args.poll = 0
    sn, sn2 = boardsn.BOARD, boardsn2.BOARD

    s = boarde2.snapshot(args)
    check('e2 Ranking Challenge board is ranked by score',
          [r['name'] for r in s['rc'][0]['board']] == ['B*OB', 'ALICE'])
    check('e2 weekly points: 3 for the win', s['points_week'][0]['score'] == 3)
    check('a SuperNOVA match stays off the Extreme 2 board',
          [m['a']['name'] for m in s['recent']] == ['ALICE']
          and {r['name'] for r in s['h2h_week']} == {'ALICE', 'B*OB'})
    a = sn.snapshot(args)
    check('sn sees one online player and one open tournament',
          a['online'] == 1 and a['comps'][0]['status'] == 'open')
    check('sn song titles come from the baked art',
          a['comps'][0]['songs'][0]['title'] == "Feelings Won't Fade")
    data = json.load(open(os.path.join(st, 'live.json')))
    for c in data['sn_comps']:
        c['start'] += 7
        c['end'] += 7
    json.dump(data, open(os.path.join(st, 'live.json'), 'w'))
    check('a moving competition window does not change the sig',
          sn.snapshot(args)['sig'] == a['sig'])
    check('sn2 shows no SuperNOVA tournaments', sn2.snapshot(args)['comps'] == [])

    b = json.loads(json.dumps(a))
    b['comps'][0]['status'] = 'ended'
    check('a tournament closing is news',
          any('has ended' in e for e in sn.discord_events(a, b)))
    e1 = boarde2.snapshot(args)
    e2 = json.loads(json.dumps(e1))
    e2['rc'][0]['board'][0] = dict(e2['rc'][0]['board'][0], player=9, name='NEW_GUY')
    news = boarde2.discord_events(e1, e2)
    check('a new #1 is news, with the name escaped',
          news and 'NEW\\_GUY' in news[0])

    payload, files = sn.discord_message(a, args)
    check('the sn Discord message carries a rendered PNG',
          files and files[0][2][:8] == b'\x89PNG\r\n\x1a\n'
          and payload['embeds'][0]['image']['url'] == 'attachment://board.png')
    w, h, _px = boardimg.read_png(files[0][2])
    check('the image is the 640x480 screen', (w, h) == (640, 480))
    payload, files = sn2.discord_message(sn2.snapshot(args), args)
    check('without baked art the message falls back to text', files == [])
    payload, files = boarde2.discord_message(boarde2.snapshot(args), args)
    check('e2 posts both Ranking Challenge cards and the points as images',
          [f[0] for f in files] == ['rc1.png', 'rc2.png', 'points.png']
          and [e['image']['url'] for e in payload['embeds']]
          == ['attachment://rc1.png', 'attachment://rc2.png', 'attachment://points.png'])
    check('e2 images are the 640x432 screen',
          all(boardimg.read_png(f[2])[:2] == (640, 432) for f in files))

    hook = FakeHook()
    path = os.path.join(st, 'boards', 'sn_discord.json')
    d = boards.Discord('sn', 'https://discord.com/api/webhooks/1/x', path, opener=hook)
    boards.watch(sn, args, d, rounds=1)
    d.last_edit = 0
    d.tick('changed', lambda: sn.discord_message(sn.snapshot(args), args))
    methods = [c[0] for c in hook.calls]
    check('posts once, then edits that message', methods == ['POST', 'PATCH']
          and hook.calls[1][1].endswith('/messages/m1'))
    check('every edit replaces the image', all(b'board.png' in c[2] for c in hook.calls))
    check('a restart keeps editing the same message',
          boards.Discord('sn', 'https://discord.com/api/webhooks/1/x', path,
                         opener=hook).msg_id == 'm1')
    check('a different webhook starts fresh',
          boards.Discord('sn', 'https://discord.com/api/webhooks/2/y', path,
                         opener=hook).msg_id is None)

    srv = boards._Server(('127.0.0.1', 0), boards._Handler)
    srv.board, srv.args = sn, args
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = 'http://127.0.0.1:%d' % srv.server_address[1]
    try:
        page = urllib.request.urlopen(base + '/').read()
        state = json.loads(urllib.request.urlopen(base + '/state.json').read())
        art = urllib.request.urlopen(base + '/art/atlas.png').read()
        check('page, state.json and art are served',
              b'id=screen' in page and state['game'] == 'sn' and art[:4] == b'\x89PNG')
        nav = json.loads(urllib.request.urlopen(base + '/nav.json?view=online.1').read())
        view = urllib.request.urlopen(base + '/view/online.1.png').read()
        label = urllib.request.urlopen(base + '/label/teal/RANKING.png').read()
        sprite = urllib.request.urlopen(base + '/sprite/plate1.png').read()
        check('nav.json, a view, a label and a sprite are served',
              nav['view'] == 'online.1' and nav['labels'] == ['teal', 'yellow']
              and all(b[:4] == b'\x89PNG' for b in (view, label, sprite)))
        try:
            urllib.request.urlopen(base + '/art/../ddr.db')
            check('art outside the bake is refused', False)
        except urllib.error.HTTPError as e:
            check('art outside the bake is refused', e.code == 404)
    finally:
        srv.shutdown()


# ── the bot ──────────────────────────────────────────────────────────────────

def _ed_sign(seed, msg):
    """RFC 8032 signing, only here to make signatures the board must accept."""
    import hashlib
    from boardbot import _B, _L, _P, _add, _mul
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254

    def enc(pt):
        zi = pow(pt[2], _P - 2, _P)
        x, y = pt[0] * zi % _P, pt[1] * zi % _P
        return int(y | ((x & 1) << 255)).to_bytes(32, 'little')
    pub = enc(_mul(a, _B))
    r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), 'little') % _L
    big_r = enc(_mul(r, _B))
    k = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), 'little') % _L
    return pub, big_r + ((r + k * a) % _L).to_bytes(32, 'little')


def _fake_server(handler):
    """A one-connection TCP server on localhost running handler(conn)."""
    import socket
    ls = socket.socket()
    ls.bind(('127.0.0.1', 0))
    ls.listen(1)

    def run():
        conn, _ = ls.accept()
        try:
            handler(conn)
        finally:
            conn.close()
            ls.close()
    threading.Thread(target=run, daemon=True).start()
    return ls.getsockname()[1]


def _recv_msg(conn, startup=False):
    import struct
    def exact(n):
        b = b''
        while len(b) < n:
            got = conn.recv(n - len(b))
            if not got:
                raise EOFError
            b += got
        return b
    if startup:
        n = struct.unpack('>I', exact(4))[0]
        return None, exact(n - 4)
    kind = exact(1)
    n = struct.unpack('>I', exact(4))[0]
    return kind, exact(n - 4)


def run_bot(st):
    import struct
    import boardbot
    import boards
    import boardsn
    import polregistry

    # signatures
    pub, sig = _ed_sign(b'\x07' * 32, b'hello')
    check('ed25519: a good signature verifies', boardbot.ed25519_verify(pub, b'hello', sig))
    check('ed25519: a changed message does not',
          not boardbot.ed25519_verify(pub, b'hellp', sig))

    # interactions
    args = boards.build_parser().parse_args(['--state-dir', st])
    seed = b'\x11' * 32
    pk, _ = _ed_sign(seed, b'')
    args.sn_discord_public_key = pk.hex()
    sn = boardsn.BOARD

    def post(obj, signer=seed):
        body = json.dumps(obj).encode()
        ts = '1700000000'
        _, sg = _ed_sign(signer, ts.encode() + body)
        hdr = {'X-Signature-Timestamp': ts, 'X-Signature-Ed25519': sg.hex()}
        code, out = boardbot.interaction(sn, args, hdr, body)
        return code, (json.loads(out) if code == 200 else out)

    check('interactions: a PING is answered', post({'type': 1}) == (200, {'type': 1}))
    check('interactions: a stranger\'s signature is 401',
          post({'type': 1}, signer=b'\x22' * 32)[0] == 401)
    cmd = lambda sub, perms: {'type': 2, 'guild_id': 'G1', 'channel_id': 'C9',   # noqa: E731
                              'member': {'permissions': str(perms)},
                              'data': {'name': 'ddrsnboard', 'options': [{'name': sub}]}}
    _, r = post(cmd('here', 0))
    check('/ddrsnboard here needs Manage Server', 'manage the server' in r['data']['content']
          and not boardbot.channels(args)['chosen'])
    _, r = post(cmd('here', 0x20))
    check('/ddrsnboard here files this channel for this server',
          boardbot.channels(args)['chosen'] == {'ddrsn': {'G1': 'C9'}}
          and r['data']['flags'] == 64)
    _, r = post(cmd('status', 0))
    check('/ddrsnboard status names the channel', '<#C9>' in r['data']['content'])
    post(cmd('stop', 0x8))
    check('/ddrsnboard stop forgets the server', boardbot.channels(args)['chosen'] == {})
    check('the command is /ddrsnboard with here, stop, news, nonews and status',
          [o['name'] for o in boardbot.command_of(sn, 'ddrsn')['options']]
          == ['here', 'stop', 'news', 'nonews', 'status'])
    post(cmd('news', 0x20))
    check('/ddrsnboard news files the news channel',
          boardbot.channels(args)['news'] == {'ddrsn': {'G1': 'C9'}})

    # every view of every board draws, at the game's size
    import boarde2
    for b, views, size in ((sn, ['rank.1.0', 'online.1', 'nonsense'], (640, 480)),
                           (boarde2, ['rc.0.0', 'rc.1.0', 'h2h.week.0', 'h2h.total.0'],
                            (640, 432))):
        sp = b.cached_snapshot(args)
        art = b.art(args)
        ok = all((b.render_view(sp, art, v).w, b.render_view(sp, art, v).h) == size
                 for v in views)
        check('%s: every view draws at %dx%d' % (b.NAME, size[0], size[1]), ok)
    nv = sn.nav(sn.cached_snapshot(args), 'rank.1.0')
    check('nav: sections, tournaments and pages',
          [x['label'] for x in nv['sections']] == ['RANKING', 'ONLINE PLAY']
          and nv['items'][0]['view'] == 'rank.1.0' and nv['prev'] is None)

    # a click on the board message shows that view, from the board's page
    args.sn_url = 'https://ddrsn.example'
    code, r = post({'type': 3, 'guild_id': 'G1', 'channel_id': 'C9',
                    'data': {'custom_id': 's|online.1', 'component_type': 2}})
    img = r['data']['embeds'][0]['image']['url'] if code == 200 and r.get('type') == 7 else ''
    check('a button shows its view in the message (type 7, the page\'s picture)',
          img.startswith('https://ddrsn.example/view/online.1.png?v=')
          and r['data']['attachments'] == [])
    rows = r['data']['components']
    check('the buttons follow the view: ONLINE PLAY is the one lit',
          [c['style'] for c in rows[0]['components']] == [2, 1])
    ids = [c.get('custom_id') for row in rows for c in row['components'] if c.get('custom_id')]
    check('no two buttons share an id (Discord refuses the message)',
          len(ids) == len(set(ids)))

    # news: the first run is silent, then each new event is posted once
    import boardbot as bb
    posted = []

    class FakeCall:
        def __init__(self, *a, **k):
            pass

        def _call(self, method, url, body=None, ctype=None):
            posted.append((method, url))
            return 200, {'id': '1'}
    real_news = sn.news
    items = [{'key': 'old', 'at': time.time() - 99999, 'view': 'rank.1.0', 'text': 'old'}]
    sn.news = lambda snap: list(items)
    bb.run_news(sn, args, 'sn', 'TOK', FakeCall, every=0, rounds=1)
    check('news: nothing is posted for what happened before', posted == [])
    items.append({'key': 'new', 'at': time.time() - 5, 'view': 'online.1',
                  'text': 'Tournament **X** is open.'})
    bb.run_news(sn, args, 'sn', 'TOK', FakeCall, every=0, rounds=1)
    bb.run_news(sn, args, 'sn', 'TOK', FakeCall, every=0, rounds=1)
    check('news: a new event goes to the news channel once',
          posted == [('POST', 'https://discord.com/api/v10/channels/C9/messages')])
    sn.news = real_news

    # posting as the bot
    hook = FakeHook()
    d = boards.Discord('ddrsn', 'https://discord.com/api/v10/channels/C9',
                       os.path.join(st, 'boards', 'bottest.json'), opener=hook, auth='TOK')
    seen = []
    real = hook.__call__

    def opener(req, timeout=0):
        seen.append((req.get_method(), req.full_url, req.get_header('Authorization')))
        return real(req, timeout)
    d.open = opener
    args.sn_url = 'https://ddrsn.example/'
    boards.watch(sn, args, d, rounds=1, message_fn=boardbot.bot_message(sn, args, 'sn'))
    check('a bot posts to the channel with its token',
          seen and seen[0][:3] == ('POST', 'https://discord.com/api/v10/channels/C9/messages',
                                   'Bot TOK'))
    check('a bot\'s post carries a button to the page',
          b'"style": 5' in hook.calls[0][2] and b'ddrsn.example' in hook.calls[0][2])

    # the registry: the seal, SCRAM, the Postgres reader, the Valkey writer
    os.environ['POL_BOT_KEY'] = 'test key'
    sealed = polregistry.seal('abc.def')
    check('registry: a sealed token unseals', polregistry.unseal(sealed) == 'abc.def')
    os.environ['POL_BOT_KEY'] = 'another key'
    check('registry: under another key it is empty', polregistry.unseal(sealed) == '')
    os.environ['POL_BOT_KEY'] = 'test key'

    sc = polregistry._Scram('pencil')          # RFC 7677's example exchange
    sc.nonce, sc.bare = 'rOprNGfwEbeRWgbNEkqO', 'n=user,r=rOprNGfwEbeRWgbNEkqO'
    final = sc.final('r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,'
                     's=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096')
    # The proof is RFC 7677's. Its printed server signature is a known erratum;
    # this is the value SCRAM libraries test against for the same exchange.
    check('SCRAM-SHA-256 matches RFC 7677',
          final.endswith('p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ=')
          and sc.verify('v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4='))

    def pg(conn):
        _, startup = _recv_msg(conn, startup=True)
        assert b'user\0bot\0' in startup
        conn.sendall(b'R' + struct.pack('>II', 12, 5) + b'salt')      # MD5, salt "salt"
        kind, body = _recv_msg(conn)
        import hashlib
        inner = hashlib.md5(b'pw' + b'bot').hexdigest()
        ok = body == b'md5' + hashlib.md5(inner.encode() + b'salt').hexdigest().encode() + b'\0'
        conn.sendall(b'R' + struct.pack('>II', 8, 0) + b'Z' + struct.pack('>I', 5) + b'I')
        kind, body = _recv_msg(conn)
        assert kind == b'Q' and b"name = 'ddrsn'" in body and ok
        cols = [b'name', b'token_sealed', b'app_id', b'public_key', b'url', b'updated_at']
        t = struct.pack('>H', len(cols)) + b''.join(c + b'\0' + bytes(18) for c in cols)
        vals = [b'ddrsn', sealed.encode(), b'123', b'ab' * 32, None, b'1700000000.5']
        d = struct.pack('>H', len(vals)) + b''.join(
            struct.pack('>i', -1) if v is None else struct.pack('>i', len(v)) + v for v in vals)
        for kind, body in ((b'T', t), (b'D', d), (b'C', b'SELECT 1\0'), (b'Z', b'I')):
            conn.sendall(kind + struct.pack('>I', len(body) + 4) + body)
        try:
            _recv_msg(conn)                    # Terminate
        except EOFError:
            pass
    port = _fake_server(pg)
    os.environ['POL_DATABASE_URL'] = 'postgresql://bot:pw@127.0.0.1:%d/registry' % port
    row = polregistry.get('ddrsn')
    check('registry: the Postgres reader gets the row and unseals its token',
          row and row['token'] == 'abc.def' and row['app_id'] == '123'
          and row['url'] is None and row['updated_at'] == '1700000000.5')

    got = []

    def valkey(conn):
        got.append(conn.recv(4096))
        conn.sendall(b'+OK\r\n')
    port = _fake_server(valkey)
    os.environ['POL_VALKEY_URL'] = 'valkey://127.0.0.1:%d/0' % port
    ok = polregistry.applied('ddrsn', 'registry', '123', 1700000000.5)
    check('registry: the admin page is told the bot runs on the registry token',
          ok and got and b'pol:botcreds:applied:ddrsn' in got[0] and b'"registry"' in got[0])
    for k in ('POL_DATABASE_URL', 'POL_VALKEY_URL', 'POL_BOT_KEY'):
        os.environ.pop(k, None)

    # the registry down at startup, then back: restart once it answers
    real_stamp = polregistry.stamp
    for unread, answers, want in ((True, [5.0], 1), (False, [None, 5.0], 1),
                                  (False, [5.0, 5.0], 0)):
        seq = list(answers)
        polregistry.stamp = lambda names, seq=seq: seq.pop(0) if seq else 5.0
        exits = []
        t = polregistry.watch(['ddrsn'], every=0.01, exit_fn=lambda: exits.append(1),
                              unread=unread)
        t.join(0.5) if want else time.sleep(0.1)
        check('registry watch (unread=%s, stamps %s) restarts %d time(s)'
              % (unread, answers, want), len(exits) == want)
    polregistry.stamp = real_stamp


if __name__ == '__main__':
    main()
