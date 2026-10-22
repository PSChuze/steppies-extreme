#!/usr/bin/env python3
"""The Extreme 2 board: who is online, this week's Ranking Challenge, and the
head-to-head tables, for boards.py.

Every number comes from the same db.py queries the in-game ranking screens
use, so the board and the console always agree.
"""
import hashlib
import json
import os
import time

import boarddata
import boardimg
import boardpage
import db

NAME = 'e2'
TITLE = 'DDR EXTREME 2'
TOP = 20                 # rows per table on the page
TOP_DISCORD = 5          # rows per table in the Discord message
#: the font its tabs' words are drawn in (selected ones are lit, not recoloured)
LABELS = ('sys', 'sys')
#: the page's accent, the teal of the game's online buttons
ACCENT = '#2ec7c0'


def art_dir(args):
    return os.path.join(args.state_dir, 'boardart', NAME)


def art_files(args):
    index = boarddata.art(art_dir(args))
    return set(index.get('files') or ()) | ({'board.json'} if index else set())


def _sig(snap):
    """Changes only when something on the board does. The countdown and the
    stamp tick every second and would otherwise mean an edit every minute."""
    keep = {k: v for k, v in snap.items() if k not in ('stamp', 'week_left')}
    return hashlib.sha1(json.dumps(keep, sort_keys=True).encode()).hexdigest()


def _rows(board, score_key):
    return [{'rank': r['rank'], 'player': r['player'], 'name': r['name'],
             'dancer': r.get('dancer'), 'score': r[score_key],
             **({k: r[k] for k in ('win', 'draw', 'loss', 'match') if k in r})}
            for r in board[:TOP]]


def snapshot(args):
    now = time.time()
    art = boarddata.art(art_dir(args))
    lv = boarddata.live(args.state_dir, now)
    game = (lv or {}).get('games', {}).get(NAME) if lv else None
    week, left, cards = boarddata.rc_cards(args.state_dir, now)
    have = boarddata.open_db(args.state_dir)
    rc = []
    for card, songs in enumerate(cards):
        rc.append({'card': card,
                   'songs': [{'id': s, 'title': boarddata.song_title(art, s)}
                             for s in songs],
                   'board': _rows(db.rc_board(week, card, now), 'rc_score')
                   if have else []})
    snap = {
        'game': NAME, 'title': TITLE, 'stamp': now,
        # None, not 0, when the gate is down: "nobody here" and "cannot tell"
        # are different things to show
        'online': game['count'] if game else None,
        'players': game['players'] if game else [],
        'week': week, 'week_left': left, 'week_ends': int(now + left),
        'rc': rc,
        'points_week': _rows(db.points_board(week, now), 'points') if have else [],
        'points_total': _rows(db.points_board(0, now), 'points') if have else [],
        'h2h_week': _rows(db.h2h_board(week, now, game='x2'), 'win') if have else [],
        'h2h_total': _rows(db.h2h_board(0, now, game='x2'), 'win') if have else [],
        'recent': boarddata.recent_h2h('x2', 10) if have else [],
    }
    snap['sig'] = _sig(snap)
    return snap


cached_snapshot = boarddata.cached(snapshot)


def _leader(table):
    return (table[0]['player'], table[0]['name']) if table else None


def discord_events(prev, snap):
    out = []
    if snap['week'] != prev['week']:
        out.append('**Ranking Challenge week %d** has begun.' % snap['week'])
        return out          # every table resets with the week; no leader news
    for old, new in zip(prev['rc'], snap['rc']):
        lead = _leader(new['board'])
        if lead and lead != _leader(old['board']):
            out.append('**%s** takes #1 on Ranking Challenge card %d with %s.'
                       % (boarddata.md(lead[1]), new['card'] + 1,
                          '{:,}'.format(new['board'][0]['score'])))
    lead = _leader(snap['points_week'])
    if lead and lead != _leader(prev['points_week']):
        out.append('**%s** leads the week\'s head-to-head points.' % boarddata.md(lead[1]))
    return out


def _card(c):
    return 'CARD %d' % (c + 1)


def _left(seconds):
    d, rest = divmod(max(0, int(seconds)), 86400)
    return ('%dD ' % d if d else '') + '%02d:%02d' % (rest // 3600, rest % 3600 // 60)


# The screen, 640x448 like the game's: the chrome "C" frame on the left with
# its LCD title bar and ten rows inside it, a column on the right. The page and
# Discord both show these pictures (views below), so there is one layout.
ROW_Y, ROW_H = 84, 33


def _draw_rows(art, c, rows, value, extra=None):
    for i, r in enumerate(rows):
        y = ROW_Y + i * ROW_H
        art.sprite(c, 'bar_dark' if i % 2 == 0 else 'bar_grey', 64, y + 3)
        if r['rank'] <= 10:
            art.sprite(c, 'badge%d' % r['rank'], 30, y)
        else:
            w = art.text_width('sys', r['rank'])
            art.text(c, 'sys', r['rank'], 45 - w // 2, y + 3)
        art.text(c, 'sys', r['name'], 72, y + 3, maxw=120)
        if extra:
            art.text(c, 'sys', extra(r), 280, y + 3, right=True)
        art.text(c, 'digits', value(r), 354, y, right=True, mono=True)
    if not rows:
        art.text(c, 'sys', 'NO ENTRIES YET', 72, ROW_Y + 3)


def _screen(art, title, right):
    c = boardimg.Canvas.from_image(art.image('bg.png'))
    art.sprite(c, 'frame', 0, 16)
    art.text(c, 'sys', title, 30, 31, maxw=200)
    art.text(c, 'sys', right, 334, 31, right=True)
    return c


#: the right column's bottom line: who is online, and the page
FOOT_Y = 404


def _pager(art, c, page, pages):
    if pages > 1:
        art.text(c, 'sys', 'PAGE %d OF %d' % (page + 1, pages), 632, FOOT_Y, right=True)


def render_rc(snap, art, card, page=0):
    """One Ranking Challenge card: its ranking in the frame, its ten songs'
    banners down the right."""
    rc = snap['rc'][card]
    c = _screen(art, _card(card),
                'ENDS ' + _left(snap['week_ends'] - time.time()))
    _draw_rows(art, c, rc['board'][page * 10:page * 10 + 10], lambda r: r['score'])
    _pager(art, c, page, _pages(rc['board']))
    art.sprite(c, 'rc_banner', 380, 0)
    for i, s in enumerate(rc['songs'][:10]):
        art.sprite(c, 'song%d' % s['id'], 396, 86 + i * 31)
    online = snap['online']
    art.text(c, 'sys', 'OFFLINE' if online is None else 'ONLINE %d' % online,
             396, FOOT_Y)
    return c


def render_points(snap, art, total=False, page=0):
    """Head-to-head points, the week's or all time, and who is online."""
    rows = snap['points_total' if total else 'points_week']
    c = _screen(art, 'HEAD-TO-HEAD', 'TOTAL' if total else 'WEEK %d' % snap['week'])
    _draw_rows(art, c, rows[page * 10:page * 10 + 10], lambda r: r['score'],
               lambda r: '%d-%d-%d' % (r['win'], r['loss'], r['draw']))
    _pager(art, c, page, _pages(rows))
    art.sprite(c, 'head_to_head', 396, 24)
    art.sprite(c, 'total_ranking' if total else 'this_week', 396, 44)
    online = snap['online']
    art.text(c, 'sys', 'SERVER OFFLINE' if online is None else 'ONLINE %d' % online,
             396, 84)
    for i, p in enumerate(snap['players'][:11]):
        art.text(c, 'sys', p['name'], 396, 112 + i * 25, maxw=120)
        art.text(c, 'sys', ACTIVITY.get(p['activity'], ''), 632, 112 + i * 25,
                 right=True)
    return c


ACTIVITY = {'lobby': 'LOBBY', 'searching': 'SEARCHING', 'room': 'IN A ROOM',
            'matched': 'MATCHED', 'playing': 'PLAYING'}


# ── views: rc.<card>.<page>, h2h.week.<page>, h2h.total.<page> ──────────────

def _pages(rows):
    return max(1, -(-len(rows) // 10))


def default_view(snap):
    return 'rc.0.0'


def _parse(snap, view):
    parts = (view or '').split('.')
    kind = parts[0] if parts[0] in ('rc', 'h2h') else 'rc'
    if kind == 'rc':
        arg = 1 if len(parts) > 1 and parts[1] == '1' else 0
        rows = snap['rc'][arg]['board']
    else:
        arg = 'total' if len(parts) > 1 and parts[1] == 'total' else 'week'
        rows = snap['points_total' if arg == 'total' else 'points_week']
    try:
        page = max(0, int(parts[2])) if len(parts) > 2 else 0
    except ValueError:
        page = 0
    pages = _pages(rows)
    return kind, arg, min(page, pages - 1), pages


def nav(snap, view):
    """What a viewer can switch to from `view`, for the page's tabs and the
    Discord buttons."""
    kind, arg, page, pages = _parse(snap, view)
    base = '%s.%s' % (kind, arg)
    return {
        'view': '%s.%d' % (base, page),
        'sections': [{'label': 'RANKING CHALLENGE', 'view': 'rc.0.0', 'sprite': 'tab_rc',
                      'on': kind == 'rc'},
                     {'label': 'HEAD-TO-HEAD', 'view': 'h2h.week.0', 'sprite': 'tab_h2h',
                      'on': kind == 'h2h'}],
        'items': ([{'label': 'CARD 1', 'view': 'rc.0.0', 'on': arg == 0},
                   {'label': 'CARD 2', 'view': 'rc.1.0', 'on': arg == 1}] if kind == 'rc' else
                  [{'label': 'THIS WEEK', 'view': 'h2h.week.0', 'on': arg == 'week'},
                   {'label': 'TOTAL', 'view': 'h2h.total.0', 'on': arg == 'total'}]),
        'page': page, 'pages': pages,
        'prev': '%s.%d' % (base, page - 1) if page else None,
        'next': '%s.%d' % (base, page + 1) if page + 1 < pages else None,
        'alt': describe(snap, kind, arg, page)}


def describe(snap, kind, arg, page):
    out = ['%d online.' % snap['online'] if snap['online'] is not None else 'Server offline.']
    if kind == 'rc':
        rc = snap['rc'][arg]
        out.append('Ranking Challenge week %d, card %d.' % (snap['week'], arg + 1))
        out += ['%d. %s, %s.' % (r['rank'], r['name'], r['score'])
                for r in rc['board'][page * 10:page * 10 + 10]]
        out.append('Songs: %s.' % '; '.join(s['title'] for s in rc['songs']))
    else:
        rows = snap['points_total' if arg == 'total' else 'points_week']
        out.append('Head-to-head points, %s.' % ('all time' if arg == 'total' else 'this week'))
        out += ['%d. %s, %d points, %d-%d-%d.' % (r['rank'], r['name'], r['score'], r['win'],
                                                  r['loss'], r['draw'])
                for r in rows[page * 10:page * 10 + 10]]
    return ' '.join(out)


#: The screen stops where the chrome frame's art does. In the game the
#: frame's bottom arm meets the bottom of the screen and reads as running off
#: it; with background showing below, it read as a cut-off picture.
SCREEN_H = 432


def render_view(snap, art, view, brand=True):
    kind, arg, page, _pages_ = _parse(snap, view)
    if kind == 'rc':
        return render_rc(snap, art, arg, page).crop(SCREEN_H)
    return render_points(snap, art, arg == 'total', page).crop(SCREEN_H)


def art(args):
    index = boarddata.art(art_dir(args))
    return boardimg.Art(art_dir(args), index) if index else None


def news(snap):
    """Lasting announcements for a news channel: each Ranking Challenge week
    as it begins, with card 1 on show."""
    rc = snap['rc'][0]
    return [{'key': 'e2-week-%d' % snap['week_ends'], 'at': snap['week_ends'] - 7 * 86400,
             'view': 'rc.0.0',
             'text': '**%s**: Ranking Challenge week %d is on until <t:%d:f>. Card 1 opens '
                     'with **%s**.' % (TITLE, snap['week'], snap['week_ends'],
                                       boarddata.md(rc['songs'][0]['title']) if rc['songs']
                                       else 'ten new songs')}]


def _text_table(rows, fmt):
    if not rows:
        return '*No entries yet.*'
    return '\n'.join('`%2d` **%s** %s' % (r['rank'], boarddata.md(r['name']), fmt(r))
                     for r in rows[:TOP_DISCORD])


def discord_message(snap, args, view=None):
    """The board message. Through a webhook, with nothing to click, it shows
    all three screens; given a view (the bot's message, which has buttons for
    the rest) it shows that one."""
    online = snap['online']
    head = ('**%d** online' % online if online is not None else 'Server offline')
    desc = '%s · Week **%d** ends <t:%d:R>' % (head, snap['week'], snap['week_ends'])
    embed = {'title': TITLE + ' ONLINE', 'description': desc, 'color': 0x5b2bd6,
             'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                        time.gmtime(snap['stamp']))}
    if args.e2_url:
        embed['url'] = args.e2_url
    index = boarddata.art(art_dir(args))
    files, embeds = [], [embed]
    if index:
        a = boardimg.Art(art_dir(args), index)
        shots = ([('board.png', render_view(snap, a, view))] if view else
                 [('rc1.png', render_rc(snap, a, 0).crop(SCREEN_H)),
                  ('rc2.png', render_rc(snap, a, 1).crop(SCREEN_H)),
                  ('points.png', render_points(snap, a).crop(SCREEN_H))])
        for i, (name, canvas) in enumerate(shots):
            files.append((name, 'image/png', canvas.png()))
            e = embed if i == 0 else {'url': embed.get('url') or 'https://ddr.invalid/'}
            e['image'] = {'url': 'attachment://' + name}
            if i:
                embeds.append(e)
    else:
        # no art baked: the standings as text instead
        embed['fields'] = [
            {'name': 'Ranking Challenge %d' % (c['card'] + 1), 'inline': True,
             'value': _text_table(c['board'], lambda r: '{:,}'.format(r['score']))}
            for c in snap['rc']] + [
            {'name': 'Head-to-head points (week)', 'inline': False,
             'value': _text_table(snap['points_week'], lambda r: '%d pts (%d-%d-%d)'
                                  % (r['score'], r['win'], r['loss'], r['draw']))}]
    return {'embeds': embeds, 'allowed_mentions': {'parse': []},
            'attachments': [{'id': i, 'filename': f[0]} for i, f in enumerate(files)]}, files


PAGE = boardpage.page(TITLE)
