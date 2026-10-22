#!/usr/bin/env python3
"""The gate's admin port: lets an OpenLobby admin panel see and run this server.

OpenLobby is the PlayOnline revival project's server stack. Its admin panel
knows nothing about DDR; a game tells it what it is over a small HTTP protocol
(pol-server, docs/admin-modules.md, "The game describes itself"). This is DDR's
side of that protocol, written for this project rather than copied, and served
from the gate because the gate is the only process that holds the players'
connections.

    GET  /openlobby/module.json     what this server is and what it offers
    GET  /openlobby/status.json     who is online, open tournaments, this week
    GET  /openlobby/calendar.json   Ranking Challenge weeks and tournaments
    GET  /openlobby/players.json    player search, for the panel's pickers
    GET  /openlobby/player.json     one OpenLobby account's dancers here
    POST /openlobby/actions/<id>    announce, disconnect
    *    /rankings, /content, /tournaments    tool pages, shown inside the panel

Off unless --admin-port is given. Every request must carry the token
(X-Devtool-Token) from DDR_ADMIN_TOKEN, and a port bound beyond loopback will
not start without one. The panel sends who asked in X-Devtool-Actor, and every
change made here is logged with that name.

The gate is host-networked and the panel lives on a Docker network, so in the
standard setup a tiny relay container (adminrelay.py) sits on that network as
"ddr" and forwards to this port. See docker-compose.yml.

Tool pages use no script, because the panel shows them under a policy that
allows none: every form posts back to its own page, which answers with the page
again and a note at the top.
"""
import calendar as calmod
import hmac
import html
import json
import os
import re
import socket
import struct
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import content
import db
import schedule

KEY = 'ddr'
TITLE = 'Dance Dance Revolution'
GAMES = (('e2', 'Extreme 2'), ('sn', 'SuperNOVA'), ('sn2', 'SuperNOVA 2'))
GAME_TITLE = dict(GAMES)
LOOPBACK = ('127.0.0.1', '::1', 'localhost')
MAX_BODY = 64 * 1024
PREFIX = '/openlobby/'

#: SuperNOVA's chat push, 0x4513: u32 status, u8 room flag, s32, s32 id,
#: char[16] name, text. See the chat notes in gate.py.
CHAT_PUSH = 0x4513
#: How an announcement is signed in the lobby chat.
ANNOUNCE_AS = 'SERVER'
#: The client's own line limit is not known, so an announcement is wrapped to
#: short lines and capped, rather than finding the limit on a live console.
ANNOUNCE_WIDTH = 40
ANNOUNCE_LINES = 6

#: Ids for tournaments added from the panel. SuperNOVA's hand-written ones use
#: small ids and SuperNOVA 2's generated ones start at 10000 and 20000
#: (schedule.py). Results are stored by id alone, so the ranges must not meet.
SN2_HAND_BASE = 30000
#: The Ranking Challenge override keeps a song list per challenge (content.py).
RC_CHALLENGES = 4


class Hooks:
    """What the admin port reads from the running gate. gate.py runs as
    __main__, so importing it here would load a second, empty copy; main()
    hands itself over instead."""

    def __init__(self, gate, args):
        self.g = gate
        self.args = args

    def sessions(self):
        """[(game, session)] for every connection that has picked a dancer."""
        g = self.g
        with g.WAITING_LOCK:
            return [('sn2' if w.is_sn2 else 'sn' if w.is_sn else 'e2', w)
                    for w in list(g.LOBBY)]

    def activity(self, w):
        with self.g.WAITING_LOCK:
            return self.g.session_activity(w)

    def competitions(self, game, now):
        if game == 'sn2':
            return self.g.sn2_competitions(self.args, now)
        return self.g.sn_competitions(self.args, now)

    def comp_file(self, game):
        name = '%s_competitions.json' % game
        given = getattr(self.args, '%s_comp_file' % game, '') or ''
        return self.g.comp_file_path(given, name)

    def song_count(self, game):
        return schedule.SN2_SONG_IDS if game == 'sn2' else self.g.SN_SONG_COUNT

    def player_files(self):
        """[(account key, player file)] for every dancer on the server."""
        with self.g.STATE_LOCK:
            return [(k, dict(f)) for k, a in self.g.STATE['accounts'].items()
                    for f in a.get('player_files', [])]


# -- what the panel reads ----------------------------------------------------

def status(h):
    now = int(time.time())
    players, rooms, counts = [], [], {g: 0 for g, _ in GAMES}
    for game, w in h.sessions():
        counts[game] += 1
        act = h.activity(w)
        where = GAME_TITLE[game]
        if w.peer is not None:
            where += ', playing %s' % w.peer.who()
        elif act != 'lobby':
            where += ', %s' % act
        players.append({'name': w.who(), 'room': where})
    week, left = schedule.rc_week(now)
    rooms.append({'name': 'Ranking Challenge, week %d' % week,
                  'detail': 'Extreme 2, %s left' % _span(left), 'state': 'open'})
    for game in ('sn', 'sn2'):
        for c in h.competitions(game, now):
            if c['start'] <= now < c['end']:
                rooms.append({'name': c['name'] or 'Tournament',
                              'detail': '%s, %s left' % (GAME_TITLE[game],
                                                         _span(c['end'] - now)),
                              'state': 'open'})
    return {'up': True, 'online': len(players), 'players': players,
            'rooms': rooms, 'rooms_label': 'events',
            'summary': ', '.join('%s %d' % (GAME_TITLE[g], counts[g])
                                 for g, _ in GAMES),
            'facts': [{'label': 'dancers', 'value': len(h.player_files())}]}


def events(h, lo, hi):
    """Calendar entries touching [lo, hi). The ids match the ones the panel's
    file module used to build from the boards, so a calendar already showing
    them does not see them change."""
    out = []
    week_s = schedule.RC_WEEK_SECONDS
    first, last = lo // week_s, (hi - 1) // week_s
    for k in range(first, min(last, first + 520) + 1):
        start = k * week_s
        week, _ = schedule.rc_week(start)
        out.append({'id': 'e2-rc-%d' % start,
                    'title': 'Ranking Challenge, week %d' % week,
                    'start': start, 'end': start + week_s, 'kind': 'challenge',
                    'about': 'Extreme 2: the weekly Ranking Challenge, two '
                             'cards of songs with their own ranking.'})
    now = int(time.time())
    for game in ('sn', 'sn2'):
        for c in h.competitions(game, now):
            if c['end'] <= lo or c['start'] >= hi:
                continue
            out.append({'id': '%s-comp-%s' % (game, c['id']),
                        'title': '%s (%s)' % (c['name'] or 'Tournament',
                                              GAME_TITLE[game]),
                        'start': c['start'], 'end': c['end'],
                        'kind': 'tournament',
                        'about': '%s: %d song%s' % (
                            GAME_TITLE[game], len(c['songs']),
                            '' if len(c['songs']) == 1 else 's')})
    return out


def find_players(h, q, limit):
    """Dancers whose name or id contains `q`, online ones first."""
    q = q.strip().lower()
    online = {}
    for game, w in h.sessions():
        pid = (w.player or {}).get('id')
        if pid is not None:
            online[pid] = GAME_TITLE[game]
    rows = []
    for _key, f in h.player_files():
        name, pid = str(f.get('name') or ''), f.get('id')
        if q and q not in name.lower() and q != str(pid):
            continue
        rows.append({'id': str(pid), 'label': name or '?',
                     'detail': ('online in %s' % online[pid]) if pid in online
                     else 'dancer %s' % pid,
                     'online': pid in online})
    rows.sort(key=lambda r: (not r['online'], r['label'].lower()))
    return rows[:limit]


def player(h, who):
    """An OpenLobby account's dancers on this server. Only logins the account
    has proved are its own count (who["links"]["ddr"], each key the stored
    login name, see ddrlink.py); a handle that happens to match a dancer's
    name is not proof."""
    keys = {x['key'] for x in who.get('links', {}).get(KEY, []) if x.get('key')}
    if not keys:
        return None
    # A login's account key is the first 8 bytes of its stored name.
    accounts = {k[:16] for k in keys}
    online = {(w.player or {}).get('id'): GAME_TITLE[g] for g, w in h.sessions()}
    week = schedule.rc_week()[0]
    chars = []
    for acct, f in h.player_files():
        if acct not in accounts:
            continue
        pid = f.get('id')
        facts = [{'label': 'dancer id', 'value': pid}]
        try:
            s = db.player_stats(pid, week)
            facts += [{'label': 'Extreme 2 matches', 'value': s['match_total']},
                      {'label': 'wins, draws, losses',
                       'value': '%d, %d, %d' % (s['win_total'], s['draw_total'],
                                                s['loss_total'])},
                      {'label': 'points', 'value': s['points_total']}]
        except Exception:                      # never fail the account window
            pass
        chars.append({'name': f.get('name') or '?',
                      'detail': ('online in %s' % online[pid]) if pid in online
                      else 'offline',
                      'online': pid in online, 'facts': facts})
    if not chars:
        return None
    return {'characters': chars}


# -- actions -----------------------------------------------------------------

def wrap(text, width=ANNOUNCE_WIDTH, lines=ANNOUNCE_LINES):
    """Plain ASCII lines no longer than `width`, at most `lines` of them."""
    text = text.encode('ascii', 'replace').decode('ascii')
    out, line = [], ''
    for word in text.split():
        while len(word) > width:
            if line:
                out.append(line)
                line = ''
            out.append(word[:width])
            word = word[width:]
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = (line + ' ' + word).strip()
    if line:
        out.append(line)
    return out[:lines]


def chat_frame(text, name=ANNOUNCE_AS):
    """One lobby chat line, as the 0x4513 push carries it."""
    nm = name.encode('ascii', 'replace')[:16]
    return (struct.pack('>I', 0) + bytes([0]) + struct.pack('>ii', 0, 0)
            + nm.ljust(16, bytes(1)) + text.encode('ascii', 'replace')
            + bytes(1))


def announce(h, params, actor, log):
    lines = wrap(str(params.get('text') or ''))
    if not lines:
        return False, 'Type a message first.'
    reached = skipped = 0
    for game, w in h.sessions():
        if game == 'e2':
            skipped += 1          # Extreme 2 has no chat to show it in
            continue
        for line in lines:
            w.push(CHAT_PUSH, chat_frame(line))
        reached += 1
    log('admin: %s announced %r to %d player(s)' % (actor or '?',
                                                     ' '.join(lines), reached))
    msg = 'Shown in the lobby chat to %d player%s.' % (
        reached, '' if reached == 1 else 's')
    if skipped:
        msg += (' %d Extreme 2 player%s did not see it: that game has no '
                'chat.' % (skipped, '' if skipped == 1 else 's'))
    return True, msg


def disconnect(h, params, actor, log):
    """Close the matching players' connections. The panel's Kick sends
    {"polid", "handles"}; the picker sends {"player": id}. A disconnected
    player can come straight back: this ends a session, it bans nobody."""
    names = {n.strip().lower() for n in
             str(params.get('handles') or '').split(',') if n.strip()}
    ids = {str(params.get('player') or '').strip()} - {''}
    gone = []
    for _game, w in h.sessions():
        p = w.player or {}
        if str(p.get('id')) in ids or str(p.get('name') or '').lower() in names:
            try:
                w.conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            gone.append(w.who())
    if not gone:
        return True, 'Nobody by that name is online.'
    log('admin: %s disconnected %s' % (actor or '?', ', '.join(gone)))
    return True, 'Disconnected %s.' % ', '.join(gone)


# -- tool pages --------------------------------------------------------------

CTYPE = 'text/html; charset=utf-8'
CSS = """
:root{--bg:#0f1216;--box:#161a20;--box2:#1d222a;--line:#2a303b;--text:#e6e9ef;
--muted:#9aa3b2;--accent:#6ea6ff;--on:#04121f;--good:#43c08f;--bad:#f2736b;
color-scheme:dark}
@media (prefers-color-scheme:light){:root{--bg:#f4f5f8;--box:#fff;--box2:#eef0f4;
--line:#dde1e8;--text:#161a21;--muted:#566070;--accent:#1f5fd6;--on:#fff;
--good:#0f7a54;--bad:#c13a32;color-scheme:light}}
*{box-sizing:border-box}
body{margin:0;padding:16px;font:14px/1.45 system-ui,sans-serif;background:var(--bg);
color:var(--text)}
h1{font-size:17px;margin:0 0 12px}h2{font-size:15px;margin:0 0 10px}
section{background:var(--box);border:1px solid var(--line);border-radius:12px;
padding:14px 16px;margin:0 0 16px;overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:12px;font-weight:500;color:var(--muted);
padding:6px 8px;border-bottom:1px solid var(--line)}
td{padding:6px 8px;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
.muted{color:var(--muted)}
.note{border-radius:8px;padding:10px 12px;margin:0 0 16px;background:var(--box2)}
.ok{color:var(--good)}.bad{color:var(--bad)}
form{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;margin:8px 0 0}
form.inline{display:inline-flex;margin:0}
label{display:flex;flex-direction:column;gap:4px;font-size:13px;color:var(--muted)}
input,select,textarea{font:inherit;color:var(--text);background:var(--box2);
border:1px solid var(--line);border-radius:8px;padding:6px 9px}
textarea{width:min(100%,36em);min-height:5em}
button{font:inherit;padding:6px 14px;border-radius:8px;border:1px solid var(--accent);
background:var(--accent);color:var(--on);cursor:pointer}
button.quiet{background:var(--box2);border-color:var(--line);color:var(--bad)}
"""


def esc(v):
    return html.escape('' if v is None else str(v), quote=True)


def page(title, body, note=None):
    msg = ''
    if note:
        ok, text = note
        msg = '<div class="note %s">%s</div>' % ('ok' if ok else 'bad', esc(text))
    return ('<!doctype html><meta charset=utf-8><meta name=viewport '
            'content="width=device-width,initial-scale=1"><title>%s</title>'
            '<style>%s</style><h1>%s</h1>%s%s'
            % (esc(title), CSS, esc(title), msg, body)).encode('utf-8')


def section(title, *parts):
    return '<section><h2>%s</h2>%s</section>' % (esc(title), ''.join(parts))


def table(heads, rows, empty='Nothing yet.'):
    if not rows:
        return '<p class=muted>%s</p>' % esc(empty)
    return ('<table><tr>%s</tr>%s</table>'
            % (''.join('<th>%s</th>' % esc(x) for x in heads),
               ''.join('<tr>%s</tr>' % ''.join('<td>%s</td>' % c for c in r)
                       for r in rows)))


def field(name, label, value='', kind='input'):
    if kind == 'textarea':
        box = '<textarea name="%s">%s</textarea>' % (esc(name), esc(value))
    else:
        box = '<input name="%s" value="%s" autocomplete=off>' % (esc(name),
                                                                 esc(value))
    return '<label>%s%s</label>' % (esc(label), box)


def button(text, hidden=None, quiet=False):
    """A one-button form, for delete-style actions inside a table."""
    hid = ''.join('<input type=hidden name="%s" value="%s">' % (esc(k), esc(v))
                  for k, v in (hidden or {}).items())
    return ('<form method=post class=inline>%s<button%s>%s</button></form>'
            % (hid, ' class=quiet' if quiet else '', esc(text)))


def posted(body):
    pairs = urllib.parse.parse_qsl((body or b'').decode('utf-8', 'replace'),
                                   keep_blank_values=True)
    return {k: v.strip() for k, v in pairs}


def _span(secs):
    secs = max(0, int(secs))
    if secs >= 2 * 86400:
        return '%d days' % (secs // 86400)
    if secs >= 3600:
        return '%d hours' % (secs // 3600)
    return '%d minutes' % (secs // 60)


def _date(t):
    return time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(t))


def rankings_page(h, method, body, actor, log):
    now = int(time.time())
    week = schedule.rc_week(now)[0]
    parts = []
    for card in (0, 1):
        rows = [[r['rank'], esc(r['name']), r['rc_score']]
                for r in db.rc_board(week, card, now)[:50]]
        parts.append(section('Ranking Challenge, week %d, card %d'
                             % (week, card + 1),
                             table(['Rank', 'Dancer', 'Score'], rows)))
    rows = [[r['rank'], esc(r['name']), r['points'], r['win'], r['draw'],
             r['loss']] for r in db.points_board(0, now)[:50]]
    parts.append(section('Extreme 2 head to head, all time',
                         table(['Rank', 'Dancer', 'Points', 'Wins', 'Draws',
                                'Losses'], rows)))
    for game in ('sn', 'sn2'):
        for c in h.competitions(game, now):
            if c['start'] > now:
                continue
            rows = [[r['rank'], esc(r['name']), r['score'], r['stages']]
                    for r in db.sn_comp_board(c['id'], 50, now)]
            state = 'open' if now < c['end'] else 'ended'
            parts.append(section('%s: %s (%s)' % (GAME_TITLE[game],
                                                  c['name'] or 'Tournament',
                                                  state),
                                 table(['Rank', 'Dancer', 'Total', 'Stages'],
                                       rows)))
    return page('Rankings', ''.join(parts))


def content_page(h, method, body, actor, log):
    """News (every game), SuperNOVA's server information, and the Ranking
    Challenge override. The same content.json the web admin page edits."""
    note = None
    c = content.load()
    news = list(c.get('news') or [])
    info = list(c.get('info') or [])
    rc = dict(c.get('rc') or {})
    if method == 'POST':
        f = posted(body)
        what = f.get('do', '')
        if what in ('news', 'info'):
            title = f.get('title', '')[:64]
            if title:
                item = {'title': title, 'body': f.get('body', '')[:1024]}
                if what == 'info':
                    item['time'] = int(time.time())
                (news if what == 'news' else info).append(item)
                note = (True, 'Added %s.' % title)
            else:
                note = (False, 'A title is needed.')
        elif what in ('news-del', 'info-del'):
            items = news if what == 'news-del' else info
            try:
                note = (True, 'Removed %s.'
                        % items.pop(int(f.get('i', '-1'))).get('title', ''))
            except (ValueError, IndexError):
                note = (False, 'That item is already gone.')
        elif what == 'rc':
            rc = _rc_override(f)
            note = (True, 'Saved.' if rc else
                    'Nothing set, so the generated lineup is back.')
        elif what == 'rc-clear':
            rc = {}
            note = (True, 'The generated lineup is back.')
        if note and note[0]:
            content.save({'news': news, 'rc': rc or None, 'info': info})
            log('admin: %s changed content (%s)' % (actor or '?', what))
    week = schedule.rc_week()[0]
    parts = [
        section('News',
                '<p class=muted>Shown in every game after login. With none '
                'here, the built-in news is shown.</p>',
                table(['Title', 'Text', ''],
                      [[esc(n['title']), esc(n.get('body', '')),
                        button('Remove', {'do': 'news-del', 'i': i}, True)]
                       for i, n in enumerate(news)]),
                '<form method=post><input type=hidden name=do value=news>%s%s'
                '<button>Add</button></form>'
                % (field('title', 'Title'), field('body', 'Text', '',
                                                   'textarea'))),
        section('SuperNOVA server information',
                table(['Title', 'Text', ''],
                      [[esc(n['title']), esc(n.get('body', '')),
                        button('Remove', {'do': 'info-del', 'i': i}, True)]
                       for i, n in enumerate(info)]),
                '<form method=post><input type=hidden name=do value=info>%s%s'
                '<button>Add</button></form>'
                % (field('title', 'Title'), field('body', 'Text', '',
                                                   'textarea'))),
        section('Extreme 2 Ranking Challenge, week %d' % week,
                '<p class=muted>Songs are generated each week. Anything set '
                'here replaces that part only: set a difficulty and the songs '
                'still rotate. Song ids are 0 to %d, separated by commas. '
                'Id 8 is left out: it hangs the game.</p>'
                % (schedule.RC_SONG_IDS - 1),
                '<form method=post><input type=hidden name=do value=rc>%s%s%s'
                '<button>Save</button></form>'
                % (''.join(field('songs%d' % i, 'Challenge %d (now %s)' % (
                       i + 1, ', '.join(map(str, schedule.rc_auto_songs(week, i)))),
                       ', '.join(map(str, (rc.get('songs') or {}).get(str(i), []))))
                       for i in range(RC_CHALLENGES)),
                   field('difficulty', 'Difficulty (0 to 2)',
                         '' if rc.get('difficulty') is None else rc['difficulty']),
                   field('stages', 'Stages (1 to 10)',
                         '' if rc.get('stages') is None else rc['stages'])),
                button('Go back to the generated lineup', {'do': 'rc-clear'},
                       True)),
    ]
    return page('News and events', ''.join(parts), note)


def _ints(raw, lo, hi):
    out = []
    for part in re.split(r'[,\s;]+', raw or ''):
        if part.isdigit() and lo <= int(part) <= hi:
            out.append(int(part))
    return out


def _rc_override(f):
    rc = {}
    songs = {}
    for i in range(RC_CHALLENGES):
        got = [x for x in _ints(f.get('songs%d' % i), 0, schedule.RC_SONG_IDS - 1)
               if x not in schedule.RC_BAD_SONG_IDS]
        if got:
            songs[str(i)] = got
    if songs:
        rc['songs'] = songs
    d = _ints(f.get('difficulty'), 0, 2)
    if d:
        rc['difficulty'] = d[0]
    st = _ints(f.get('stages'), 1, 10)
    if st:
        rc['stages'] = st[0]
    return rc


def tournaments_page(h, method, body, actor, log):
    """SuperNOVA and SuperNOVA 2 tournaments. Without a competitions file
    each game runs its generated ones; the first change here writes the file,
    starting from what is running now so no open tournament disappears."""
    now = int(time.time())
    note = None
    if method == 'POST':
        f = posted(body)
        game = f.get('game', '')
        if game in ('sn', 'sn2'):
            note = _change_tournaments(h, game, f, now)
            if note[0]:
                log('admin: %s changed %s tournaments (%s)'
                    % (actor or '?', GAME_TITLE[game], f.get('do', '')))
    parts = []
    for game in ('sn', 'sn2'):
        path = h.comp_file(game)
        own = bool(path) and os.path.exists(path)
        rows = []
        for c in sorted(h.competitions(game, now), key=lambda c: c['start']):
            state = ('open' if c['start'] <= now < c['end'] else
                     'coming' if c['start'] > now else 'ended')
            rows.append([c['id'], esc(c['name']), state, _date(c['start']),
                         _date(c['end']), esc(', '.join(map(str, c['songs']))),
                         button('Remove', {'do': 'del', 'game': game,
                                           'id': c['id']}, True)])
        last = h.song_count(game) - 1
        parts.append(section(
            GAME_TITLE[game],
            '<p class=muted>%s</p>' % (
                'This server runs its own list.' if own else
                'These are generated from the calendar. Adding or removing '
                'one switches to a list of your own, starting from these.'),
            table(['Id', 'Name', 'Now', 'Starts', 'Ends', 'Songs', ''], rows),
            '<form method=post><input type=hidden name=do value=add>'
            '<input type=hidden name=game value=%s>%s%s%s%s%s'
            '<button>Add tournament</button></form>'
            % (game, field('name', 'Name'),
               field('songs', 'Song ids, 0 to %d (up to 10)' % last),
               field('start', 'Starts (YYYY-MM-DD, UTC)',
                     time.strftime('%Y-%m-%d', time.gmtime(now))),
               field('days', 'Days', '7'),
               field('difficulty', 'Difficulty (0 beginner to 4 challenge)',
                     '1')),
            button('Go back to the generated ones', {'do': 'reset',
                                                     'game': game}, True)
            if own else ''))
    return page('Tournaments', ''.join(parts), note)


def _change_tournaments(h, game, f, now):
    path = h.comp_file(game)
    if not path:
        return False, 'The gate has no state folder to keep the list in.'
    what = f.get('do')
    if what == 'reset':
        try:
            os.remove(path)
        except OSError:
            pass
        return True, 'Back to the generated tournaments.'
    comps = [{'id': c['id'], 'name': c['name'], 'songs': c['songs'],
              'start': c['start'], 'end': c['end'],
              'difficulty': c.get('difficulty'), 'options': c.get('options')}
             for c in h.competitions(game, now)]
    if what == 'del':
        keep = [c for c in comps if str(c['id']) != f.get('id')]
        if len(keep) == len(comps):
            return False, 'That tournament is already gone.'
        comps = keep
        msg = 'Removed. Its results stay in the database.'
    elif what == 'add':
        name = f.get('name', '').upper()[:30]
        songs = _ints(f.get('songs'), 0, h.song_count(game) - 1)[:10]
        try:
            start = calmod.timegm(time.strptime(f.get('start', ''), '%Y-%m-%d'))
            days = int(f.get('days') or 7)
        except ValueError:
            return False, 'The start date is YYYY-MM-DD and days a number.'
        diff = _ints(f.get('difficulty'), 0, 4)
        if not name or not songs or not 1 <= days <= 366:
            return False, 'A name, at least one song and 1 to 366 days.'
        if len(comps) >= h.g.SN_COMP_MAX:
            return False, 'The game shows at most %d tournaments.' % h.g.SN_COMP_MAX
        used = [c['id'] for c in comps]
        if game == 'sn2':
            new = max([i for i in used if i >= SN2_HAND_BASE] + [SN2_HAND_BASE - 1]) + 1
        else:
            new = max([i for i in used if i < schedule.SN2_WEEKLY_BASE] + [0]) + 1
        comps.append({'id': new, 'name': name, 'songs': songs, 'start': start,
                      'end': start + days * 86400,
                      'difficulty': diff[0] if diff else None, 'options': None})
        msg = 'Added %s.' % name
    else:
        return False, 'Unknown change.'
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(comps, fh, indent=1)
    os.replace(tmp, path)
    return True, msg


# -- the HTTP side -----------------------------------------------------------

def manifest():
    return {
        'v': 1, 'key': KEY, 'title': TITLE, 'short': 'DDR',
        'platform': 'PS2 disc',
        'about': 'Extreme 2, SuperNOVA and SuperNOVA 2 online play.',
        'content_ids': [], 'accounts': KEY,
        'calendar': True, 'help': False, 'player': True, 'players': True,
        'services': [{'name': 'DDR Online',
                      'containers': ['ddr-gate', 'ddr-web', 'ddr-stun',
                                     'ddr-boards'],
                      'warning': 'Everyone in DDR online play is disconnected.'}],
        'tools': [
            {'id': 'rankings', 'label': 'Rankings', 'path': 'rankings',
             'about': 'Ranking Challenge, head to head and tournament standings.'},
            {'id': 'content', 'label': 'News and events', 'path': 'content',
             'about': 'News, SuperNOVA server information, Ranking Challenge songs.'},
            {'id': 'tournaments', 'label': 'Tournaments', 'path': 'tournaments',
             'about': 'Add or remove SuperNOVA and SuperNOVA 2 tournaments.'}],
        'actions': [
            {'id': 'announce', 'label': 'Message in the lobby',
             'kind': 'announce', 'danger': False,
             'about': 'SuperNOVA and SuperNOVA 2 players see it in the lobby '
                      'chat. Extreme 2 has no chat.',
             'fields': [{'id': 'text', 'label': 'Message', 'type': 'text'}]},
            {'id': 'disconnect', 'label': 'Disconnect a player', 'kind': 'kick',
             'danger': True,
             'about': 'Ends their connection. They can connect again.',
             'fields': [{'id': 'player', 'label': 'Dancer', 'type': 'player'}]}],
    }


TOOLS = {'rankings': rankings_page, 'content': content_page,
         'tournaments': tournaments_page}


def serve(hooks, bind, port, token, log=print):
    """Start the admin port in a daemon thread. Returns the server."""
    if bind not in LOOPBACK and not token:
        raise ValueError('the admin port on %s needs DDR_ADMIN_TOKEN set' % bind)

    def say(msg):
        log(msg)

    class Handler(BaseHTTPRequestHandler):
        server_version = 'ddr-admin'

        def log_message(self, *a):
            pass

        def send(self, code, body, ctype='application/json; charset=utf-8'):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self.route('GET')

        def do_POST(self):
            self.route('POST')

        def route(self, method):
            got = self.headers.get('X-Devtool-Token', '')
            if token and not hmac.compare_digest(got.encode(), token.encode()):
                return self.send(403, {'error': 'bad or missing token'})
            actor = (self.headers.get('X-Devtool-Actor') or '')[:64]
            path, _, query = self.path.partition('?')
            q = dict(urllib.parse.parse_qsl(query))
            body = b''
            if method == 'POST':
                n = int(self.headers.get('Content-Length') or 0)
                if n > MAX_BODY:
                    return self.send(413, {'error': 'too large'})
                body = self.rfile.read(n) if n > 0 else b''
            try:
                return self.answer(method, path, q, body, actor)
            except Exception as e:                 # say what kind, not what
                say('admin: %s %s failed: %r' % (method, path, e))
                return self.send(500, {'ok': False, 'error': 'failed: %s'
                                       % e.__class__.__name__})

        def answer(self, method, path, q, body, actor):
            if path == PREFIX + 'module.json':
                return self.send(200, manifest())
            if path == PREFIX + 'status.json':
                return self.send(200, status(hooks))
            if path == PREFIX + 'calendar.json':
                try:
                    lo, hi = int(q.get('from', '0')), int(q.get('to', '0'))
                except ValueError:
                    return self.send(400, {'error': 'from and to are unix seconds'})
                return self.send(200, {'events': events(hooks, lo, hi)})
            if path == PREFIX + 'players.json':
                try:
                    limit = int(q.get('limit') or 20)
                except ValueError:
                    limit = 0
                if not 1 <= limit <= 50:
                    return self.send(400, {'error': 'limit is 1 to 50'})
                return self.send(200, {'players': find_players(
                    hooks, q.get('q', ''), limit)})
            if path == PREFIX + 'player.json':
                try:
                    links = json.loads(q.get('links') or '{}')
                except ValueError:
                    links = {}
                who = {'polid': q.get('polid', ''),
                       'links': links if isinstance(links, dict) else {}}
                return self.send(200, player(hooks, who) or {})
            if path.startswith(PREFIX + 'actions/') and method == 'POST':
                name = path[len(PREFIX + 'actions/'):]
                fn = {'announce': announce, 'disconnect': disconnect}.get(name)
                if fn is None:
                    return self.send(404, {'ok': False, 'msg': 'no such action'})
                try:
                    params = json.loads(body or b'{}')
                except ValueError:
                    return self.send(400, {'ok': False, 'msg': 'the body is not JSON'})
                if not isinstance(params, dict):
                    params = {}
                ok, msg = fn(hooks, params, actor, say)
                return self.send(200, {'ok': bool(ok), 'msg': msg})
            if path.startswith(PREFIX):
                return self.send(404, {'error': 'not found'})
            tool = TOOLS.get(path.strip('/').split('/')[0])
            if tool is None:
                return self.send(404, {'error': 'not found'})
            return self.send(200, tool(hooks, method, body, actor, say), CTYPE)

    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, name='admin-port',
                     daemon=True).start()
    say('admin port for OpenLobby on %s:%d%s'
        % (bind, srv.server_address[1], '' if token else ' (no token)'))
    return srv
