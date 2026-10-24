#!/usr/bin/env python3
"""A board as a Discord bot, for boards.py.

A webhook posts into one channel someone pasted its URL from. A bot is invited
to a server and told where to post there, by a member who can manage that
server:

    /<name>board here     post the board in this channel from now on
    /<name>board stop     take the board out of this server
    /<name>board news     post announcements in this channel: a tournament
                          opening or ending, a Ranking Challenge week
    /<name>board nonews   stop the announcements
    /<name>board status   where the board posts in this server

The board message carries buttons (and a tournament list) that switch which
screen it shows, for everyone: the post's picture becomes that screen's
/view/<id>.png on the board's public page. The next refresh of the board puts
it back on its main screen.

<name> is the bot's name, --<game>-bot-name: ddre2, ddrsn and ddrsn2 unless
changed. Each server gets its own board message, edited in place exactly as
the webhook's is, with the board's news posts beside it. While it runs the bot
holds a Gateway session, so its status reads "Watching 3 players online"
(discordgw.py), and with a bot registry configured (polregistry.py) it also
publishes that count as live:<name> in Valkey.

What it needs, per board: the bot token, the application id (to register the
command) and the public key (to check what Discord sends). They come from
the flags/environment, or from a bot registry (polregistry.py),
which wins where it holds a value. The app's interactions endpoint must be
<the board's public URL>/discord/interactions; the registry's admin page sets
that, or set it in the Discord developer portal.
"""
import hashlib
import json
import os
import threading
import time

import discordgw
import polregistry

DISCORD_API = 'https://discord.com/api/v10'

#: Fluxer, beside Discord. Its message API is Discord's shape, with three gaps
#: that decide what the boards do there: no components (a button is dropped, so
#: link buttons become links in the text), no slash commands (the channels are
#: config: --<name>-fluxer-channels, or the registry), and no activities (the
#: status is a custom status).
FLUXER_API = os.environ.get('DDR_BOARDS_FLUXER_API', 'https://api.fluxer.app/v1')
FLUXER_GATEWAY = os.environ.get('DDR_BOARDS_FLUXER_GATEWAY',
                                'wss://gateway.fluxer.app/?v=1&encoding=json')

#: Manage Server or Administrator: who may move a board
MOVERS = 0x20 | 0x8


def log(text):
    print('[boards] %s' % text, flush=True)


def bot_name(args, name):
    return (getattr(args, '%s_bot_name' % name, '') or 'ddr' + name).strip().lower()


# ── Ed25519 (RFC 8032 section 5.1.7), to check an interaction's signature ────

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _x(y, sign):
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _x(_GY, 0)
_B = (_GX, _GY, 1, _GX * _GY % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _eq(p, q):
    return ((p[0] * q[2] - q[0] * p[2]) % _P == 0
            and (p[1] * q[2] - q[1] * p[2]) % _P == 0)


def _point(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, 'little')
    sign, y = y >> 255, y & ((1 << 255) - 1)
    if y >= _P:
        return None
    x = _x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    a, r = _point(public), _point(sig[:32])
    s = int.from_bytes(sig[32:], 'little')
    if a is None or r is None or s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), 'little') % _L
    return _eq(_mul(s, _B), _add(r, _mul(h, a)))


# ── where each bot posts: {"chosen"|"posted": {bot: {guild: channel}}} ───────

_chan_lock = threading.Lock()


def _channels_file(args):
    return os.path.join(args.state_dir, 'boards', 'discord_channels.json')


def channels(args):
    try:
        with open(_channels_file(args), encoding='utf-8') as fh:
            d = json.load(fh) or {}
    except (OSError, ValueError):
        d = {}
    return {k: d.get(k) or {} for k in ('chosen', 'posted', 'news')}


def _set_channel(args, which, bot, guild, cid):
    """Set (cid) or forget (None) one entry. False if it could not be saved."""
    with _chan_lock:
        d = channels(args)
        per = d[which].setdefault(bot, {})
        if cid is None:
            per.pop(guild, None)
        else:
            per[guild] = cid
        if not per:
            d[which].pop(bot, None)
        path = _channels_file(args)
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path + '.tmp', 'w', encoding='utf-8') as fh:
                json.dump(d, fh)
            os.replace(path + '.tmp', path)
            return True
        except OSError as e:
            log('could not save where the bots post (%s)' % e)
            return False


# ── the slash command ────────────────────────────────────────────────────────

def command_of(board, bot):
    title = board.TITLE
    sub = lambda n, d: {'type': 1, 'name': n, 'description': d[:100]}   # noqa: E731
    return {'name': '%sboard' % bot, 'type': 1, 'contexts': [0], 'integration_types': [0],
            'default_member_permissions': '32',
            'description': ('Choose where the %s board posts' % title)[:100],
            'options': [sub('here', 'Post the %s board in this channel' % title),
                        sub('stop', 'Take the %s board out of this server' % title),
                        sub('news', 'Post %s announcements in this channel' % title),
                        sub('nonews', 'Stop the %s announcements' % title),
                        sub('status', 'Show where the board posts')]}


def register_command(board, bot, token, app_id, call):
    """Put the bot's one command up: a PUT is the app's whole list, so it is
    idempotent. `call` is boards.Discord's request method, authorised."""
    st, data = call('PUT', '%s/applications/%s/commands' % (DISCORD_API, app_id),
                    json.dumps([command_of(board, bot)]).encode('utf-8'),
                    'application/json')
    if st not in (200, 201):
        log('%s: could not register /%sboard (%s %s)' % (bot, bot, st, json.dumps(data)[:160]))
    else:
        log('%s: /%sboard registered' % (bot, bot))
    return st


def _reply(text):
    return {'type': 4, 'data': {'flags': 64, 'content': text,
                                'allowed_mentions': {'parse': []}}}


def handle_command(board, args, bot, data):
    opts = (data.get('data') or {}).get('options') or []
    sub = str(opts[0].get('name')) if opts and isinstance(opts[0], dict) else 'status'
    cid = str(data.get('channel_id') or (data.get('channel') or {}).get('id') or '')
    guild = str(data.get('guild_id') or '')
    try:
        perms = int(((data.get('member') or {}).get('permissions')) or 0)
    except (TypeError, ValueError):
        perms = 0
    if not guild:
        return _reply('The board can only post in a server.')
    if sub == 'status':
        ch = channels(args)
        got = ch['chosen'].get(bot, {}).get(guild)
        news = ch['news'].get(bot, {}).get(guild)
        return _reply(('The %s board posts in <#%s>.' % (board.TITLE, got) if got else
                       'The %s board does not post in this server yet: run `/%sboard here` '
                       'in the channel you want.' % (board.TITLE, bot))
                      + ('\nAnnouncements go to <#%s>.' % news if news else
                         '\nNo announcements: `/%sboard news` in a channel turns them on.'
                         % bot))
    if not perms & MOVERS:
        return _reply('Only members who can manage the server can move the board.')
    if sub == 'news':
        if not cid or not _set_channel(args, 'news', bot, guild, cid):
            return _reply('The board could not save that just now; try again in a moment.')
        return _reply('Done: %s announcements (a tournament opening or ending, a new '
                      'Ranking Challenge week) will be posted in <#%s>.' % (board.TITLE, cid))
    if sub == 'nonews':
        _set_channel(args, 'news', bot, guild, None)
        return _reply('Done: no more %s announcements in this server.' % board.TITLE)
    if sub == 'stop':
        _set_channel(args, 'chosen', bot, guild, None)
        return _reply('Done: the %s board leaves this server within a minute, and its '
                      'posts go with it.' % board.TITLE)
    if sub != 'here' or not cid:
        return _reply('Use `/%sboard here`, `stop`, `news`, `nonews` or `status`.' % bot)
    if not _set_channel(args, 'chosen', bot, guild, cid):
        return _reply('The board could not save that just now; try again in a moment.')
    return _reply('Done: the %s board will post in <#%s> within a minute, and its old '
                  'post goes away. The bot needs to see and post in this channel, with '
                  'Embed Links and Attach Files.' % (board.TITLE, cid))


def interaction(board, args, headers, body):
    """(status, body) for one POST to /discord/interactions. Unsigned or
    mis-signed is 401, which is also what Discord's endpoint check demands."""
    name = board.NAME
    key = (getattr(args, '%s_discord_public_key' % name, '') or '').strip()
    try:
        ok = bool(key) and ed25519_verify(
            bytes.fromhex(key),
            (headers.get('X-Signature-Timestamp') or '').encode() + body,
            bytes.fromhex(headers.get('X-Signature-Ed25519') or ''))
    except ValueError:
        ok = False
    if not ok:
        return 401, b'invalid request signature'
    try:
        data = json.loads(body)
    except ValueError:
        return 400, b'bad json'
    bot = bot_name(args, name)
    if data.get('type') == 1:
        resp = {'type': 1}
    elif data.get('type') == 2 and (data.get('data') or {}).get('name') == '%sboard' % bot:
        resp = handle_command(board, args, bot, data)
    elif data.get('type') == 3:
        resp = handle_component(board, args, name, data)
    else:
        resp = _reply('That is not something this board does.')
    return 200, json.dumps(resp).encode('utf-8')


# ── the board message's buttons ──────────────────────────────────────────────

def components(board, args, name, snap, view):
    """The buttons under the board message, for the view it shows: its
    screens, its choices (a tournament list, or buttons), the pages, and the
    page itself. custom_id is "<row>|<view>" -- s, i, p or n, because two
    buttons can lead to the same view and Discord refuses a message whose ids
    repeat; the list's is "l|" and its value the view. None without a public
    page: a click shows the picture from there, so there is nothing to switch
    to without one."""
    url = (getattr(args, '%s_url' % name, '') or '').strip()
    if not url.startswith('https://'):
        return None
    nav = board.nav(snap, view)
    rows = []

    def button(row, label, target, on=False, disabled=False):
        return {'type': 2, 'style': 1 if on else 2, 'label': label[:80],
                'custom_id': ('%s|%s' % (row, target))[:100],
                'disabled': bool(disabled or on)}
    rows.append({'type': 1, 'components': [button('s', s['label'].title(), s['view'], s['on'])
                                           for s in nav['sections'][:5]]})
    items = nav['items']
    if len(items) > 5 or (items and any(len(i['label']) > 24 for i in items)):
        rows.append({'type': 1, 'components': [{
            'type': 3, 'custom_id': 'l|', 'placeholder': 'Choose a tournament',
            'options': [{'label': i['label'][:100], 'value': i['view'][:100],
                         'description': (i.get('note') or '')[:100], 'default': i['on']}
                        for i in items[:25]]}]})
    elif len(items) > 1:
        rows.append({'type': 1, 'components': [button('i', i['label'].title(), i['view'],
                                                      i['on']) for i in items]})
    tail = []
    if nav['pages'] > 1:
        tail += [button('p', 'Prev', nav['prev'] or nav['view'], disabled=not nav['prev']),
                 button('n', 'Next', nav['next'] or nav['view'], disabled=not nav['next'])]
    tail.append({'type': 2, 'style': 5, 'label': 'Open the board',
                 'url': '%s#%s' % (url.rstrip('/') + '/', nav['view'])})
    rows.append({'type': 1, 'components': tail})
    return rows


def handle_component(board, args, name, data):
    """A click on the board message: show that view in it, for everyone.
    Type 7 (UPDATE_MESSAGE) cannot carry a file, so the picture is the
    board's own /view/<id>.png, versioned so Discord fetches it fresh."""
    import boards            # the picture's address; imported here, not at the top
    d = data.get('data') or {}
    cid = str(d.get('custom_id') or '')
    if cid[:2] not in ('s|', 'i|', 'p|', 'n|', 'l|', 'v|'):
        return _reply('That button is not this board\'s.')
    view = cid[2:] or (d.get('values') or [''])[0]
    snap = board.cached_snapshot(args)
    view = board.nav(snap, view)['view']
    # the board's own words for the post; its attached picture is dropped,
    # since the view's picture comes from the page instead
    payload, _files = board.discord_message(snap, args, view)
    embed = dict(payload['embeds'][0])
    embed['image'] = {'url': boards.view_url(board, args, snap, view)}
    return {'type': 7, 'data': {'embeds': [embed], 'attachments': [],
                                'components': components(board, args, name, snap, view) or [],
                                'allowed_mentions': {'parse': []}}}


# ── the bot's posts, one board per server ────────────────────────────────────

def bot_message(board, args, name):
    """The board's message as the bot posts it: its main screen, and the
    buttons to switch to the others."""
    def build(snap, a):
        view = board.default_view(snap)
        payload, files = board.discord_message(snap, a, view)
        rows = components(board, a, name, snap, view)
        if rows:
            payload = dict(payload, components=rows)
        return payload, files
    return build


# ── announcements, in a server's news channel ────────────────────────────────

#: how old an event may be and still be announced: a restart catches up on
#: the last day, never on last month
NEWS_WINDOW = 24 * 3600


def fluxer_payload(payload):
    """A Discord message for Fluxer: the components go, and each link button
    becomes a [label](url) line under the last embed (or the text)."""
    out = dict(payload)
    links = []
    for row in out.pop('components', None) or []:
        for c in (row or {}).get('components') or []:
            if c.get('type') == 2 and c.get('style') == 5 and c.get('url'):
                links.append('[%s](%s)' % (c.get('label') or c['url'], c['url']))
    if not links:
        return out
    line = ' · '.join(links)
    if out.get('embeds'):
        out['embeds'] = [dict(e) for e in out['embeds']]
        last = out['embeds'][-1]
        last['description'] = ('%s\n\n%s' % (last.get('description') or '', line)).strip()[:4096]
    else:
        out['content'] = ('%s\n%s' % (out.get('content') or '', line)).strip()[:4000]
    return out


class FluxerPresence(discordgw.Presence):
    """The same Gateway session on Fluxer, whose presence is a custom status."""

    def _presence_payload(self):
        return {'op': 3, 'd': {'status': self.status, 'afk': False,
                               'custom_status': {'text': self._want} if self._want else None}}


def _ids(text):
    return [c.strip() for c in (text or '').split(',') if c.strip()]


def start_fluxer(board, args, name, discord_cls, watch_fn):
    """The board on Fluxer: its status, a post per configured channel (its own
    state file each, never shared with a Discord one), and its announcements."""
    bot = bot_name(args, name)
    token = (getattr(args, '%s_fluxer_bot_token' % name, '') or '').strip()
    FluxerPresence(bot + '-fluxer', token, url=FLUXER_GATEWAY,
                   status_fn=lambda: count_text(_online(board, args))).start()
    message = bot_message(board, args, name)
    chans = _ids(getattr(args, '%s_fluxer_channels' % name, ''))
    for cid in chans:
        d = discord_cls(bot + '-fluxer', '%s/channels/%s' % (FLUXER_API, cid),
                        os.path.join(args.state_dir, 'boards', '%s_fluxer_%s.json' % (bot, cid)),
                        args.discord_every, args.discord_event_ttl, args.discord_refresh,
                        auth=token, fluxer=True)
        threading.Thread(target=watch_fn, args=(board, args, d), kwargs={'message_fn': message},
                         name='fluxer-%s-%s' % (bot, cid), daemon=True).start()
    news = _ids(getattr(args, '%s_fluxer_news_channels' % name, ''))
    if news and hasattr(board, 'news'):
        threading.Thread(target=run_news, args=(board, args, name, token, discord_cls),
                         kwargs={'fluxer': news}, name='fluxer-news-' + bot, daemon=True).start()
    log('%s: on Fluxer too, in %d channel(s)%s' % (bot, len(chans),
                                                 ', news in %d' % len(news) if news else ''))


def run_news(board, args, name, token, discord_cls, every=60.0, rounds=None, fluxer=None):
    """Post each of board.news(snap) once, in every server's news channel,
    with the picture of its view. What was announced is kept in the state
    directory. On the very first run everything already happened is marked
    as told, so turning the feature on does not post a backlog."""
    bot = bot_name(args, name)
    path = os.path.join(args.state_dir, 'boards',
                        '%s_%snews.json' % (bot, 'fluxer_' if fluxer else ''))
    try:
        with open(path, encoding='utf-8') as fh:
            told = json.load(fh).get('told') or []
        first = False
    except (OSError, ValueError):
        told, first = [], True
    call = discord_cls(bot, '', os.devnull, auth=token)._call
    url = (getattr(args, '%s_url' % name, '') or '').strip()
    where = ({'fluxer:%s' % c: c for c in fluxer}, FLUXER_API) if fluxer else None
    n = 0
    while rounds is None or n < rounds:
        n += 1
        try:
            snap = board.cached_snapshot(args)
            now = time.time()
            due = [i for i in board.news(snap) if i['key'] not in told and i['at'] <= now]
            if first:
                told += [i['key'] for i in due]
                due, first = [], False
            for item in due:
                if now - item['at'] <= NEWS_WINDOW:
                    post_news(board, args, name, bot, snap, item, call, url, where)
                told.append(item['key'])
            if due or n == 1:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path + '.tmp', 'w', encoding='utf-8') as fh:
                    json.dump({'told': told[-500:]}, fh)
                os.replace(path + '.tmp', path)
        except Exception as e:                      # noqa: BLE001 never die
            log('%s: news error (%s); still running' % (bot, e))
        if rounds is None or n < rounds:
            time.sleep(every)


def post_news(board, args, name, bot, snap, item, call, url, where=None):
    """One announcement, with its screen attached, in each server's news
    channel. Unlike the board's own status posts these stay. `where` is
    ({key: channel}, api) for Fluxer's channels instead of Discord's."""
    import boards
    targets, api = where or (channels(args)['news'].get(bot) or {}, DISCORD_API)
    if not targets:
        return
    files = []
    art = board.art(args)
    if art is not None:
        files.append(('news.png', 'image/png', board.render_view(snap, art, item['view']).png()))
    embed = {'title': board.TITLE, 'description': item['text'][:4000],
             'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(item['at']))}
    if files:
        embed['image'] = {'url': 'attachment://news.png'}
    payload = {'embeds': [embed], 'allowed_mentions': {'parse': []},
               'attachments': [{'id': 0, 'filename': 'news.png'}] if files else []}
    if url.startswith('https://'):
        payload['components'] = [{'type': 1, 'components': [
            {'type': 2, 'style': 5, 'label': 'Open the board',
             'url': '%s#%s' % (url.rstrip('/') + '/', item['view'])}]}]
    if where:
        payload = fluxer_payload(payload)
    body, ctype = boards.multipart(payload, files)
    for guild, cid in targets.items():
        st, data = call('POST', '%s/channels/%s/messages' % (api, cid), body, ctype)
        log('%s: announced %s in server %s (%s)' % (bot, item['key'], guild, st))


def run_feeds(board, args, name, token, discord_cls, watch_fn):
    """The supervisor: a worker per server that chose a channel. A server that
    stops being a target has its posts deleted; a board moved to another
    channel deletes its old post before it posts in the new one."""
    bot = bot_name(args, name)
    message = bot_message(board, args, name)

    def make(guild, cid):
        return discord_cls(bot, '%s/channels/%s' % (DISCORD_API, cid),
                           os.path.join(args.state_dir, 'boards', '%s_bot_%s.json' % (bot, guild)),
                           args.discord_every, args.discord_event_ttl, args.discord_refresh,
                           auth=token)

    def run_one(guild, cid, ev):
        was = channels(args)['posted'].get(bot, {}).get(guild)
        if was and was != cid:
            n = make(guild, was).clear()
            log('%s: moved in server %s (%d old post(s) deleted)' % (bot, guild, n))
        _set_channel(args, 'posted', bot, guild, cid)
        stop = lambda: ev.is_set() or channels(args)['chosen'].get(bot, {}).get(guild) != cid  # noqa: E731
        watch_fn(board, args, make(guild, cid), message_fn=message, stop=stop)

    workers, quiet = {}, False
    while True:
        try:
            want = dict(channels(args)['chosen'].get(bot) or {})
            for guild, cid in list(channels(args)['posted'].get(bot, {}).items()):
                if guild not in want:
                    n = make(guild, cid).clear()
                    _set_channel(args, 'posted', bot, guild, None)
                    log('%s: no longer posts in server %s (%d post(s) deleted)' % (bot, guild, n))
            for guild in [g for g, w in workers.items() if want.get(g) != w['cid']]:
                workers.pop(guild)['ev'].set()
            for guild, cid in want.items():
                if guild in workers and workers[guild]['thread'].is_alive():
                    continue
                ev = threading.Event()
                t = threading.Thread(target=run_one, args=(guild, cid, ev), daemon=True,
                                     name='discord-%s-%s' % (bot, guild))
                workers[guild] = {'cid': cid, 'ev': ev, 'thread': t}
                t.start()
            if not want and not quiet:
                log('%s: nowhere to post yet -- run /%sboard here in a channel' % (bot, bot))
            quiet = not want
        except Exception as e:                      # noqa: BLE001 never die
            log('%s: feed supervisor error (%s); still running' % (bot, e))
        time.sleep(30)


def _online(board, args):
    try:
        return board.cached_snapshot(args).get('online')
    except Exception:                               # noqa: BLE001
        return None


def count_text(n):
    if n is None:
        return ''
    return '%d player%s online' % (n, '' if n == 1 else 's')


def publish_count(board, args, bot, every=10.0):
    """live:<bot> = {"count", "stamp"} in Valkey, for the registry's
    readers. Nothing is written while the gate's count is unknown, so the
    marker goes stale rather than claiming an empty game."""
    while True:
        n = _online(board, args)
        if n is not None:
            polregistry.kv_set('live:%s' % bot, json.dumps({'count': n, 'stamp': time.time()}),
                               ttl=86400)
        time.sleep(every)


def start(board, args, name, discord_cls, watch_fn):
    """Everything a board does as a bot: its command, its status, its posts."""
    bot = bot_name(args, name)
    token = (getattr(args, '%s_discord_bot_token' % name, '') or '').strip()
    app_id = (getattr(args, '%s_discord_app_id' % name, '') or '').strip()
    if not (getattr(args, '%s_discord_public_key' % name, '') or '').strip():
        log('%s: no public key -- /%sboard cannot be answered until it is set' % (bot, bot))
    if app_id:
        call = discord_cls(bot, '', os.devnull, auth=token)._call
        threading.Thread(target=register_command, args=(board, bot, token, app_id, call),
                         name='commands-' + bot, daemon=True).start()
    else:
        log('%s: no application id -- /%sboard is not registered' % (bot, bot))
    discordgw.Presence(bot, token, status_fn=lambda: count_text(_online(board, args))).start()
    if os.environ.get('POL_VALKEY_URL', '').strip():
        threading.Thread(target=publish_count, args=(board, args, bot),
                         name='count-' + bot, daemon=True).start()
    threading.Thread(target=run_feeds, args=(board, args, name, token, discord_cls, watch_fn),
                     name='feeds-' + bot, daemon=True).start()
    if hasattr(board, 'news'):
        threading.Thread(target=run_news, args=(board, args, name, token, discord_cls),
                         name='news-' + bot, daemon=True).start()
    log('%s: running as a bot (app %s)' % (bot, app_id or '?'))


def use_registry(args, names):
    """A bot registry over the flags: where a row holds a value it
    wins, where it does not the flag/environment stays. Each bot then reports
    what it runs on (botcreds:applied:<bot>), and the process exits when a row
    changes, for the container to restart on the new credentials."""
    if not polregistry.enabled() or not names:
        return None
    bots = []
    unread = False
    for name in names:
        bot = bot_name(args, name)
        bots.append(bot)
        try:
            row = polregistry.get(bot)
        except Exception as e:                      # noqa: BLE001 no db / no table yet
            log('%s: bot registry not readable (%s: %s); using the environment'
                % (bot, type(e).__name__, e))
            row = None
            unread = True
        for field, attr in (('token', '%s_discord_bot_token'), ('app_id', '%s_discord_app_id'),
                            ('public_key', '%s_discord_public_key'), ('url', '%s_url'),
                            ('fluxer_token', '%s_fluxer_bot_token')):
            if row and row.get(field):
                setattr(args, attr % name, row[field])
        # a channel list the registry names wins; one it does not name keeps the
        # environment's
        for key, ids in polregistry.fluxer_channels(row).items():
            if key == bot:
                setattr(args, '%s_fluxer_channels' % name, ids)
        if row and row.get('has_token') and not row.get('token'):
            log('%s: the registry\'s token cannot be unsealed here (POL_BOT_KEY missing or '
                'different); using the environment' % bot)
        token = (getattr(args, '%s_discord_bot_token' % name, '') or '').strip()
        source = 'registry' if row and row.get('token') else ('env' if token else '')
        try:
            row_at = float((row or {}).get('updated_at') or 0)
        except ValueError:
            row_at = 0.0
        ftoken = (getattr(args, '%s_fluxer_bot_token' % name, '') or '').strip()
        fsource = 'registry' if row and row.get('fluxer_token') else ('env' if ftoken else '')
        fchans = (getattr(args, '%s_fluxer_channels' % name, '') or '').strip()
        polregistry.applied(bot, source, (getattr(args, '%s_discord_app_id' % name, '')
                                          or '').strip(), row_at,
                            fsource, {bot: fchans} if fchans else {})
        log('%s: credentials from %s' % (bot, source or 'nowhere (no bot)'))
    return polregistry.watch(bots, unread=unread)
