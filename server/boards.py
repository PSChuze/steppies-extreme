#!/usr/bin/env python3
"""The boards: each game's live standings, as a web page and a Discord message.

A board is a module (boarde2.py), or a module's BOARD object (boardsn.py,
boardsn2.py), with:

    NAME, TITLE            short key and display name
    PAGE                   the page, one self-contained HTML document
    art(args)              its baked art (boardimg.Art), or None
    art_files(args)        the baked art files the page may fetch
    cached_snapshot(args)  everything the page and Discord show, with a "sig"
                           that changes only when something visible did
    default_view(snap)     the view shown first
    nav(snap, view)        where a viewer can go from a view: its sections,
                           items and pages (the page's tabs, the Discord
                           buttons), and a text description of it
    render_view(snap, art, view) -> boardimg.Canvas
    discord_message(snap, args, view=None) -> (payload, files)
    discord_events(prev, snap)  -> [short status lines]   (optional)
    news(snap)             -> lasting announcements      (optional)
    LABELS                 (font, font when selected) for its tabs' words

EVERY SCREEN IS A PICTURE. A view (a tournament's ranking, a card, the
online lobby) is drawn once, here, at the game's resolution, from the game's
own art, and served as /view/<id>.png: the page shows it, and so does Discord.
There is one renderer, so the page and the post can never disagree.

Each board gets its own port, so each can have its own hostname behind a
reverse proxy or tunnel. Nothing but the standard library. It runs in its own
process and opens the database read-only, so a bug here can never touch a live
session or write a result.

Discord: give a board a webhook and it posts ONE message, then keeps editing
it in place -- when something changed, at most once a minute, and every half
hour regardless so its timestamp stays honest. The message id is kept in the
state directory, so a restart edits the same message instead of posting a
second board, and a message someone deleted is posted again. News (a new week,
a new leader) goes out as short posts that delete themselves after ten
minutes, so the board stays the thing in view.

    python3 boards.py --state-dir /state --e2-port 19581 --sn-port 19582 --sn2-port 19583

Webhooks are secrets, so they come from the environment:
DDR_BOARDS_E2_DISCORD_WEBHOOK, DDR_BOARDS_SN_DISCORD_WEBHOOK and
DDR_BOARDS_SN2_DISCORD_WEBHOOK.

A board can instead run as a Discord BOT (boardbot.py): a token, and the app's
id and public key, from DDR_BOARDS_<GAME>_DISCORD_BOT_TOKEN / _APP_ID /
_PUBLIC_KEY, or from a bot registry (polregistry.py). A bot posts
in whichever channel a server's owner picks with its slash command, one board
per server, and its status reads "Watching 3 players online".
"""
import argparse
import hashlib
import importlib
import json
import os
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import boardbot
import boarddata
import boardimg

#: board name -> module. Each gets --<name>-port; 0 leaves it off.
BOARDS = {'e2': 'boarde2', 'sn': 'boardsn', 'sn2': 'boardsn2'}

ART_TYPES = {'.png': 'image/png', '.json': 'application/json; charset=utf-8',
             '.woff2': 'font/woff2', '.woff': 'font/woff'}


def log(*a):
    print('[boards]', *a, flush=True)


class _Handler(BaseHTTPRequestHandler):
    server_version = 'ddrboards/1'

    def log_message(self, fmt, *a):
        pass

    def _send(self, code, body, ctype, cache='no-store'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', cache)
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        """POST /discord/interactions: a bot's slash command, checked against
        its public key (boardbot.interaction). Nothing else takes a POST."""
        if urllib.parse.urlparse(self.path).path != '/discord/interactions':
            return self._send(404, 'not found', 'text/plain')
        try:
            n = int(self.headers.get('Content-Length') or 0)
        except ValueError:
            n = -1
        if not 0 <= n <= 1 << 20:
            return self._send(413, 'too large', 'text/plain')
        code, body = boardbot.interaction(self.server.board, self.server.args,
                                          self.headers, self.rfile.read(n))
        return self._send(code, body, 'application/json' if code == 200 else 'text/plain')

    def do_GET(self):
        board, args = self.server.board, self.server.args
        u = urllib.parse.urlparse(self.path)
        path = u.path
        q = urllib.parse.parse_qs(u.query)
        if path.startswith(('/view/', '/sprite/', '/label/')) or path == '/nav.json':
            try:
                r = pictures(board, args, path, q)
            except Exception as e:                     # never take the server down
                r = (500, '%s: %s' % (type(e).__name__, e), 'text/plain')
            return self._send(*r)
        if path in ('/', '/index.html'):
            return self._send(200, board.PAGE, 'text/html; charset=utf-8')
        if path == '/state.json':
            try:
                snap = board.cached_snapshot(args)
            except Exception as e:
                return self._send(500, json.dumps({'error': '%s: %s' % (
                    type(e).__name__, e)}), 'application/json')
            return self._send(200, json.dumps(snap, separators=(',', ':')),
                              'application/json; charset=utf-8')
        if path.startswith('/art/'):
            name = path[5:]
            if name not in board.art_files(args):
                return self._send(404, 'no such art', 'text/plain')
            try:
                with open(os.path.join(board.art_dir(args), name), 'rb') as fh:
                    blob = fh.read()
            except OSError:
                return self._send(404, 'missing', 'text/plain')
            ctype = ART_TYPES.get(os.path.splitext(name)[1].lower(),
                                  'application/octet-stream')
            # board.json is the index: revalidate it, or a re-bake stays
            # hidden behind a day-old copy. The images it names can be cached.
            return self._send(200, blob, ctype, 'no-cache' if name.endswith('.json')
                              else 'public, max-age=86400')
        if path == '/healthz':
            return self._send(200, 'ok', 'text/plain')
        return self._send(404, 'not found', 'text/plain')


# ── pictures: views, sprites and words, each drawn from the game's art ──────

_pic_cache, _pic_lock = {}, threading.Lock()


def _cached(key, make):
    """make() once per key. A view's key holds the data's sig and the minute
    (countdowns), so a crowd of pages, and Discord fetching a post's image,
    cost one render."""
    with _pic_lock:
        if key in _pic_cache:
            return _pic_cache[key]
    blob = make()
    with _pic_lock:
        if len(_pic_cache) > 256:
            _pic_cache.clear()
        _pic_cache[key] = blob
    return blob


def view_url(board, args, snap, view):
    """The public address of a view's picture, versioned so Discord fetches
    it afresh when the board changes (it caches an image URL for good)."""
    base = (getattr(args, '%s_url' % board.NAME, '') or '').rstrip('/')
    v = hashlib.sha1(('%s|%d' % (snap['sig'], int(time.time() // 60))).encode()).hexdigest()[:12]
    return '%s/view/%s.png?v=%s' % (base, urllib.parse.quote(view), v)


def pictures(board, args, path, q):
    """(status, body, type[, cache]) for /view/<id>.png, /nav.json,
    /sprite/<name>.png and /label/<font>/<text>.png."""
    art = board.art(args)
    if art is None:
        return 404, 'no art baked', 'text/plain'
    if path == '/nav.json':
        snap = board.cached_snapshot(args)
        view = (q.get('view') or [''])[0] or board.default_view(snap)
        nav = board.nav(snap, view)
        nav.update(default=board.default_view(snap), sig=snap['sig'],
                   labels=list(getattr(board, 'LABELS', ('sys', 'sys'))),
                   online=snap.get('online'), title=board.TITLE,
                   accent=getattr(board, 'ACCENT', '#3cf'),
                   logo='logo' in art.index['sprites'],
                   # when the art was baked: sprite and label URLs carry it,
                   # so a re-bake is never hidden behind a day-old copy
                   art=int(os.path.getmtime(os.path.join(board.art_dir(args), 'board.json'))))
        return 200, json.dumps(nav), 'application/json; charset=utf-8'
    if path.startswith('/view/') and path.endswith('.png'):
        snap = board.cached_snapshot(args)
        view = board.nav(snap, urllib.parse.unquote(path[6:-4]))['view']
        # ?p=1 is the page asking: its header carries the logo, so the screen
        # itself goes without
        brand = (q.get('p') or ['0'])[0] != '1'
        key = ('view', board.NAME, view, brand, snap['sig'], int(time.time() // 60))
        blob = _cached(key, lambda: board.render_view(snap, art, view, brand=brand).png())
        return 200, blob, 'image/png', 'public, max-age=60'
    if path.startswith('/sprite/') and path.endswith('.png'):
        name = urllib.parse.unquote(path[8:-4])
        if name not in art.index['sprites']:
            return 404, 'no such sprite', 'text/plain'

        def make():
            f, sx, sy, w, h = art.index['sprites'][name]
            c = boardimg.Canvas(w, h, transparent=True)
            art.sprite(c, name, 0, 0)
            return c.png()
        return 200, _cached(('sprite', board.NAME, name), make), 'image/png', \
            'public, max-age=86400'
    if path.startswith('/label/') and path.endswith('.png'):
        font, _, text = urllib.parse.unquote(path[7:-4]).partition('/')
        if font not in art.index['fonts'] or not 0 < len(text) <= 48:
            return 404, 'no such label', 'text/plain'

        def make():
            w = max(1, art.text_width(font, text))
            c = boardimg.Canvas(w + 4, art.index['fonts'][font]['ch'] + 2, transparent=True)
            art.text(c, font, text, 2, 1)
            return c.png()
        return 200, _cached(('label', board.NAME, font, text), make), 'image/png', \
            'public, max-age=86400'
    return 404, 'not found', 'text/plain'


class _Server(ThreadingHTTPServer):
    # The default backlog of 5 refuses the burst of art requests a page makes
    # on first load (seen in practice). listen() runs in the
    # constructor, so this has to be a class attribute.
    request_queue_size = 128
    daemon_threads = True


def serve(board, args, port):
    srv = _Server((args.bind, int(port)), _Handler)
    srv.board, srv.args = board, args
    threading.Thread(target=srv.serve_forever, name='board-' + board.NAME,
                     daemon=True).start()


# ── Discord ──────────────────────────────────────────────────────────────────

_UA = 'DiscordBot (https://github.com/PSChuze/steppies-extreme, 1) ddrboards'


def multipart(payload, files):
    """payload_json plus files[i], each (filename, content type, bytes)."""
    boundary = 'ddrboards' + uuid.uuid4().hex
    parts = [('--%s\r\nContent-Disposition: form-data; name="payload_json"\r\n'
              'Content-Type: application/json\r\n\r\n' % boundary).encode()
             + json.dumps(payload).encode('utf-8') + b'\r\n']
    for i, (fn, ctype, blob) in enumerate(files):
        parts.append(('--%s\r\nContent-Disposition: form-data; name="files[%d]"; '
                      'filename="%s"\r\nContent-Type: %s\r\n\r\n'
                      % (boundary, i, fn, ctype)).encode() + blob + b'\r\n')
    parts.append(('--%s--\r\n' % boundary).encode())
    return b''.join(parts), 'multipart/form-data; boundary=%s' % boundary


class Discord:
    """One board's message, through a webhook, or with `auth` (a bot token)
    into a channel, `url` then being the API's /channels/<id>. Network errors
    are logged and survived. The URL and token are secrets and never printed."""

    def __init__(self, name, url, state, every=60.0, ttl=600.0, refresh=1800.0,
                 opener=None, auth=None):
        self.name = name
        self.auth = (auth or '').strip() or None
        self.url = (url or '').strip().rstrip('/')
        self.path = state
        self.every = max(10.0, float(every))
        self.refresh = max(60.0, float(refresh))
        self.ttl = max(0.0, float(ttl))
        self.open = opener or urllib.request.urlopen
        self.events = []        # [{"id", "t"}]: status posts still up
        self.swept = False      # the first sweep clears the last run's posts
        self.msg_id = self._load()
        self.last_sig = None
        self.last_edit = 0.0
        self.hold_until = 0.0

    def _log(self, text):
        log('%s discord: %s' % (self.name, text))

    def _hook(self):
        return hashlib.sha1(self.url.encode()).hexdigest()

    def _load(self):
        try:
            with open(self.path, encoding='utf-8') as fh:
                d = json.load(fh) or {}
            # an id belongs to ONE webhook; a new webhook starts fresh
            if d.get('hook') == self._hook():
                self.events = [{'id': str(e['id']), 't': float(e.get('t') or 0)}
                               for e in (d.get('events') or []) if e.get('id')]
                return str(d.get('message_id') or '') or None
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return None

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.path) or '.', exist_ok=True)
            tmp = '%s.tmp' % self.path
            with open(tmp, 'w', encoding='utf-8') as fh:
                json.dump({'hook': self._hook(), 'message_id': self.msg_id,
                           'events': self.events}, fh)
            os.replace(tmp, self.path)
        except OSError as e:
            self._log('could not save the message id (%s); a restart will '
                      'post a second board' % e)

    def _call(self, method, url, body=None, ctype=None):
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header('User-Agent', _UA)
        if self.auth:
            req.add_header('Authorization', 'Bot %s' % self.auth)
        if ctype:
            req.add_header('Content-Type', ctype)
        try:
            with self.open(req, timeout=20) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            try:
                raw = e.read()
                return e.code, (json.loads(raw) if raw else {})
            except (OSError, ValueError):
                return e.code, {}
        except (urllib.error.URLError, OSError, ValueError) as e:
            return 0, {'error': str(e)}

    def _limited(self, status, data):
        if status != 429:
            return False
        try:
            wait = float(data.get('retry_after', 5))
        except (TypeError, ValueError, AttributeError):
            wait = 5.0
        self.hold_until = time.time() + wait
        self._log('rate limited, holding %.0f s' % wait)
        return True

    def _refused(self, what, status, data):
        """400/401/403 are the operator's to fix (a revoked webhook, a bot
        that may not post in the channel), so wait a minute rather than
        repeat the same failure every poll."""
        self._log('%s failed (%s %s)' % (what, status, json.dumps(data)[:160]))
        if status in (400, 401, 403):
            self.hold_until = time.time() + 60
            if status == 403 and self.auth:
                self._log('the bot may not post here: it needs View Channel, Send '
                          'Messages, Embed Links and Attach Files in this channel')

    def _post_url(self):
        """A webhook returns the message only when asked (?wait=true); a bot
        posts to its channel's messages."""
        return self.url + ('/messages' if self.auth else '?wait=true')

    def clear(self):
        """Delete the board message and any status posts, and forget them:
        for a board that moves to another channel. Returns how many went."""
        gone = 0
        for mid in ([self.msg_id] if self.msg_id else []) + [e['id'] for e in self.events]:
            st, _data = self._call('DELETE', '%s/messages/%s' % (self.url, mid))
            gone += st in (200, 204, 404)
        self.msg_id, self.events = None, []
        self._save()
        return gone

    def tick(self, sig, build, now=None, force=False):
        """Edit (or first post) the board message when `sig` changed, at most
        once per `every`, or every `refresh` regardless. build() returns
        (payload, files)."""
        now = time.time() if now is None else now
        if not self.url or now < self.hold_until:
            return None
        self.sweep(now)
        if not force:
            if now - self.last_edit < self.every:
                return None
            if sig == self.last_sig and now - self.last_edit < self.refresh:
                return None
        body, ctype = multipart(*build())
        did = None
        if self.msg_id:
            st, data = self._call('PATCH', '%s/messages/%s' % (self.url, self.msg_id),
                                  body, ctype)
            if st == 200:
                did = 'edited'
            elif st == 404:
                self._log('the board message is gone; posting a new one')
                self.msg_id = None
            elif self._limited(st, data):
                return 'limited'
            else:
                self._refused('edit', st, data)
                return 'failed'
        if not self.msg_id:
            st, data = self._call('POST', self._post_url(), body, ctype)
            if st in (200, 201) and data.get('id'):
                self.msg_id = str(data['id'])
                self._save()
                did = 'posted'
                self._log('board message posted (id %s)' % self.msg_id)
            elif self._limited(st, data):
                return 'limited'
            else:
                self._refused('post', st, data)
                return 'failed'
        self.last_sig, self.last_edit = sig, now
        return did

    def say(self, text):
        """One short status post. ?wait=true returns its id, which is how
        sweep() deletes it later."""
        if not self.url or time.time() < self.hold_until:
            return False
        body = json.dumps({'content': text[:1900],
                           'allowed_mentions': {'parse': []}}).encode('utf-8')
        st, data = self._call('POST', self._post_url(), body, 'application/json')
        if st in (200, 201, 204):
            if data.get('id'):
                self.events.append({'id': str(data['id']), 't': time.time()})
                self._save()
            return True
        if not self._limited(st, data):
            self._log('status post failed (%s)' % st)
        return False

    def sweep(self, now=None):
        """Delete status posts older than the TTL, and on the first call after
        a restart every one the last run left behind. A 404 counts as done."""
        now = time.time() if now is None else now
        if not self.url or now < self.hold_until:
            return 0
        first, self.swept = not self.swept, True
        doomed = [e for e in self.events
                  if first or (self.ttl > 0 and now - e['t'] >= self.ttl)]
        gone = 0
        for e in doomed:
            st, data = self._call('DELETE', '%s/messages/%s' % (self.url, e['id']))
            if st in (200, 204, 404):
                self.events = [x for x in self.events if x['id'] != e['id']]
                gone += 1
            elif self._limited(st, data):
                break
        if gone:
            self._save()
        return gone


def watch(board, args, discord, rounds=None, message_fn=None, stop=None):
    """The board's Discord side: status posts for what discord_events calls
    news, then the board message. `rounds` bounds the loop for tests; stop()
    ends it (a bot's board that moved channel)."""
    news = getattr(board, 'discord_events', None)
    message = message_fn or board.discord_message
    prev, last_err, n = None, 0.0, 0
    while (rounds is None or n < rounds) and not (stop and stop()):
        n += 1
        try:
            snap = board.cached_snapshot(args)
            events = list(news(prev, snap) or []) if prev is not None and news else []
            prev = snap
            for text in events[:5]:
                log('%s: %s' % (discord.name, text.replace('**', '')))
                if args.discord_events == 'on':
                    discord.say(text)
            discord.tick(snap['sig'], lambda: message(snap, args), force=bool(events))
        except Exception as e:
            if time.time() - last_err > 300:
                last_err = time.time()
                log('%s discord watcher error (%s); still running' % (discord.name, e))
                traceback.print_exc()
        if rounds is None or n < rounds:
            time.sleep(args.poll)


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--state-dir', default='/state',
                    help='the gate\'s state directory: ddr.db, live.json, '
                         'content.json and the baked art')
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--poll', type=float, default=5.0, metavar='S',
                    help='how often Discord checks the board for changes')
    ap.add_argument('--discord-every', type=float, default=60.0, metavar='S',
                    help='at most one edit of a board message per S seconds')
    ap.add_argument('--discord-refresh', type=float, default=1800.0, metavar='S',
                    help='re-edit an unchanged board this often, for its timestamp')
    ap.add_argument('--discord-event-ttl', type=float, default=600.0, metavar='S',
                    help='delete a status post after S seconds (0 = keep them)')
    ap.add_argument('--discord-events', choices=('on', 'off'), default='on',
                    help='post the short status messages at all')
    for name in BOARDS:
        env = 'DDR_BOARDS_%s_' % name.upper()
        ap.add_argument('--%s-port' % name, type=int, default=0, metavar='PORT',
                        help='serve the %s board on this port (0 = off)' % name)
        ap.add_argument('--%s-discord-webhook' % name, metavar='URL',
                        default=os.environ.get(env + 'DISCORD_WEBHOOK', ''),
                        help='post the %s board to this webhook (env %sDISCORD_'
                             'WEBHOOK; a secret, so prefer the env)' % (name, env))
        ap.add_argument('--%s-url' % name, metavar='URL',
                        default=os.environ.get(env + 'URL', ''),
                        help='the board\'s public page, linked from Discord')
        ap.add_argument('--%s-discord-bot-token' % name, metavar='TOKEN',
                        default=os.environ.get(env + 'DISCORD_BOT_TOKEN', ''),
                        help='run the %s board as a bot (env %sDISCORD_BOT_TOKEN; '
                             'a secret)' % (name, env))
        ap.add_argument('--%s-discord-app-id' % name, metavar='ID',
                        default=os.environ.get(env + 'DISCORD_APP_ID', ''),
                        help='the bot\'s application id, for its slash command')
        ap.add_argument('--%s-discord-public-key' % name, metavar='HEX',
                        default=os.environ.get(env + 'DISCORD_PUBLIC_KEY', ''),
                        help='the bot\'s public key: checks what Discord sends to '
                             '/discord/interactions')
        ap.add_argument('--%s-bot-name' % name, metavar='NAME',
                        default=os.environ.get(env + 'BOT_NAME', 'ddr' + name),
                        help='the bot\'s name: its /<name>board command, its row in '
                             'a bot registry (polregistry.py), its player-count marker '
                             '(default %(default)s)')
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    started = []
    boardbot.use_registry(args, [n for n in BOARDS
                                 if int(getattr(args, '%s_port' % n) or 0)])
    for name, modname in BOARDS.items():
        port = int(getattr(args, '%s_port' % name) or 0)
        if not port:
            continue
        mod = importlib.import_module(modname)
        board = getattr(mod, 'BOARD', mod)
        serve(board, args, port)
        started.append('%s on http://%s:%d/' % (name, args.bind, port))
        if not board.art_files(args):
            log('%s: no baked art in %s -- run boardart.py against your '
                'disc; the page will be bare until then' % (name, board.art_dir(args)))
        if (getattr(args, '%s_discord_bot_token' % name) or '').strip():
            boardbot.start(board, args, name, Discord, watch)
            continue
        hook = (getattr(args, '%s_discord_webhook' % name) or '').strip()
        if not hook:
            continue
        if not hook.startswith('https://') or '/api/webhooks/' not in hook:
            log('%s: that is not a Discord webhook URL; posting is OFF' % name)
            continue
        state = os.path.join(args.state_dir, 'boards', '%s_discord.json' % name)
        d = Discord(name, hook, state, args.discord_every, args.discord_event_ttl,
                    args.discord_refresh)
        log('%s: Discord webhook set; the board message is %s'
            % (name, ('kept (id %s)' % d.msg_id) if d.msg_id else 'new'))
        threading.Thread(target=watch, args=(board, args, d),
                         name='discord-' + name, daemon=True).start()
    if not started:
        raise SystemExit('boards: no board has a port (--e2-port, --sn-port, --sn2-port)')
    if not boarddata.open_db(args.state_dir):
        log('no ddr.db in %s yet; boards are empty until the gate creates it'
            % args.state_dir)
    log('serving: %s' % '; '.join(started))
    while True:
        time.sleep(3600)


if __name__ == '__main__':
    main()
