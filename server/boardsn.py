#!/usr/bin/env python3
"""The SuperNOVA and SuperNOVA 2 boards: who is online and every tournament's
standings, for boards.py.

The two games share an engine and the ranking screen's layout, so one class
serves both; each draws with its own disc's art, and SuperNOVA 2's chrome,
cyan and textured background are its own (boardart.py, THEME).

The competition list comes from live.json, not from sn_competitions.json:
without that file the gate builds competitions from its own flags, which
nothing outside the gate can see. The standings are db.sn_comp_board, the
same query the in-game tournament ranking uses.

VIEWS. Everything the board shows is a screen drawn at the game's resolution,
named by a view id, the same picture on the page and in Discord:

    rank.<tournament id>.<page>   the game's Internet Ranking screen
    online.<tournament id>        the ONLINE PLAY screen: the tournament's
                                  stages, and who is in the lobby now
"""
import hashlib
import json
import os
import time

import boarddata
import boardimg
import boardpage
import db

TOP = 24                # rows per tournament kept
ROWS = 8                # rows on one ranking screen
W, H = 640, 480


def _status(c, now):
    if now < c['start']:
        return 'upcoming'
    return 'open' if now < c['end'] else 'ended'


def featured(comps):
    """The tournament shown first: the open one, else the next one, else the
    one that ended last."""
    for want in ('open', 'upcoming'):
        for c in comps:
            if c['status'] == want:
                return c
    return max(comps, key=lambda c: c['end'], default=None)


def left(t, now=None):
    s = max(0, int(t - (time.time() if now is None else now)))
    d, rest = divmod(s, 86400)
    return ('%dD ' % d if d else '') + '%02d:%02d' % (rest // 3600, rest % 3600 // 60)


ACTIVITY = {'lobby': 'LOBBY', 'searching': 'SEARCHING', 'room': 'IN A ROOM',
            'matched': 'MATCHED', 'playing': 'PLAYING'}


class SnBoard:
    #: the fonts its tabs' words are drawn in: (normally, when selected)
    LABELS = ('teal', 'yellow')

    def __init__(self, name, title, comps_key):
        self.NAME, self.TITLE = name, title
        #: the page's accent: SuperNOVA's menus are orange, SuperNOVA 2's cyan
        self.ACCENT = '#f28a12' if name == 'sn' else '#33d8ee'
        self.comps_key = comps_key
        self.PAGE = boardpage.page(title)
        self.cached_snapshot = boarddata.cached(self.snapshot)

    def art_dir(self, args):
        return os.path.join(args.state_dir, 'boardart', self.NAME)

    def art_files(self, args):
        index = boarddata.art(self.art_dir(args))
        return set(index.get('files') or ()) | ({'board.json'} if index else set())

    def art(self, args):
        index = boarddata.art(self.art_dir(args))
        return boardimg.Art(self.art_dir(args), index) if index else None

    @staticmethod
    def _sig(snap):
        """Leaves out times: a competition from the gate flags is "open since
        a day ago until a month from now" afresh on every write, so its start
        and end move every few seconds without anything changing."""
        keep = {k: v for k, v in snap.items() if k not in ('stamp', 'comps')}
        keep['comps'] = [{k: v for k, v in c.items() if k not in ('start', 'end')}
                         for c in snap['comps']]
        return hashlib.sha1(json.dumps(keep, sort_keys=True).encode()).hexdigest()

    def snapshot(self, args):
        now = time.time()
        art = boarddata.art(self.art_dir(args))
        lv = boarddata.live(args.state_dir, now)
        game = (lv or {}).get('games', {}).get(self.NAME) if lv else None
        have = boarddata.open_db(args.state_dir)
        comps = []
        for c in boarddata.last_live(args.state_dir).get(self.comps_key) or []:
            comps.append({
                'id': c['id'], 'name': c.get('name') or 'TOURNAMENT %d' % c['id'],
                'start': c['start'], 'end': c['end'], 'status': _status(c, now),
                'songs': [{'id': s, 'title': boarddata.song_title(art, s)}
                          for s in c.get('songs') or []],
                'board': db.sn_comp_board(c['id'], TOP) if have else []})
        snap = {'game': self.NAME, 'title': self.TITLE, 'stamp': now,
                'online': game['count'] if game else None,
                'players': game['players'] if game else [],
                'comps': comps}
        snap['sig'] = self._sig(snap)
        return snap

    # -- views ----------------------------------------------------------------

    def default_view(self, snap):
        c = featured(snap['comps'])
        return 'rank.%s.0' % c['id'] if c else 'online.0'

    def _parse(self, snap, view):
        """(kind, tournament or None, page) for a view id, made valid: a view
        for a tournament that is gone falls back to the featured one."""
        parts = (view or '').split('.')
        kind = parts[0] if parts[0] in ('rank', 'online') else 'rank'
        comps = {str(c['id']): c for c in snap['comps']}
        comp = comps.get(parts[1]) if len(parts) > 1 else None
        comp = comp or featured(snap['comps'])
        try:
            page = max(0, int(parts[2])) if len(parts) > 2 else 0
        except ValueError:
            page = 0
        pages = max(1, -(-len(comp['board']) // ROWS)) if comp else 1
        return kind, comp, min(page, pages - 1), pages

    def nav(self, snap, view):
        """What a viewer can switch to from `view`: the two screens, the
        tournaments, and the pages. The page's tabs and the Discord buttons
        are both built from this."""
        kind, comp, page, pages = self._parse(snap, view)
        cid = comp['id'] if comp else 0
        cur = '%s.%s.%d' % (kind, cid, page) if kind == 'rank' else 'online.%s' % cid
        return {
            'view': cur,
            'sections': [{'label': 'RANKING', 'view': 'rank.%s.0' % cid, 'on': kind == 'rank'},
                         {'label': 'ONLINE PLAY', 'view': 'online.%s' % cid,
                          'on': kind == 'online'}],
            'items': [{'label': c['name'], 'view': ('rank.%s.0' if kind == 'rank'
                                                    else 'online.%s') % c['id'],
                       'on': c is comp, 'note': c['status'].upper()}
                      for c in snap['comps']],
            'page': page, 'pages': pages if kind == 'rank' else 1,
            'prev': ('rank.%s.%d' % (cid, page - 1)) if kind == 'rank' and page else None,
            'next': ('rank.%s.%d' % (cid, page + 1)) if kind == 'rank' and page + 1 < pages
            else None,
            'alt': self.describe(snap, kind, comp, page)}

    def describe(self, snap, kind, comp, page):
        out = ['%d online.' % snap['online'] if snap['online'] is not None
               else 'Server offline.']
        if comp is None:
            return ' '.join(out + ['No tournament.'])
        out.append('Tournament %s, %s.' % (comp['name'], comp['status']))
        if kind == 'rank':
            out += ['%d. %s, %s.' % (r['rank'], r['name'], r['score'])
                    for r in comp['board'][page * ROWS:page * ROWS + ROWS]]
        else:
            out.append('Stages: %s.' % '; '.join(s['title'] for s in comp['songs']))
            out += ['%s, %s.' % (p['name'], ACTIVITY.get(p['activity'], ''))
                    for p in snap['players']]
        return ' '.join(out)

    def render_view(self, snap, art, view, brand=True):
        """`brand`: put the game's logo on the screen itself. Discord wants it
        (the picture is all there is); the page has the logo in its header."""
        kind, comp, page, pages = self._parse(snap, view)
        if kind == 'online':
            return self.render_online(snap, art, comp, brand)
        return self.render_rank(snap, art, comp, page, pages, brand)

    def render_rank(self, snap, art, comp, page=0, pages=1, brand=True):
        """The game's Internet Ranking screen, with the game's logo in the
        header strip, which is where the two SuperNOVAs would otherwise look
        the same."""
        c = boardimg.Canvas.from_image(art.image('bg.png'))
        if brand and 'logo' in art.index['sprites']:
            _f, _x, _y, lw, lh = art.index['sprites']['logo']
            # a wide logo fits the header strip; a square one may stand taller
            art.sprite(c, 'logo', 16, 4, h=40 if lw > 2 * lh else 56)
        art.sprite(c, 'internet_ranking', 368, 25)
        if comp is None:
            art.text(c, 'teal', 'NO TOURNAMENT', 20, 70)
        else:
            when = {'open': 'ENDS ' + left(comp['end']),
                    'upcoming': 'OPENS ' + left(comp['start']),
                    'ended': 'ENDED'}[comp['status']]
            ww = art.text(c, 'yellow', when, 620, 74, right=True, scale=0.7)
            art.fit_text(c, 'teal', comp['name'], 20, 70, 600 - ww - 24)
            rows = comp['board'][page * ROWS:page * ROWS + ROWS]
            if not rows:
                art.text(c, 'yellow', 'NO ENTRIES YET', 100, 116)
            for i, r in enumerate(rows):
                y = 108 + i * 37
                art.sprite(c, ('plate1', 'plate2', 'plate3')[r['rank'] - 1]
                           if r['rank'] <= 3 else 'plate', 20, y)
                art.text(c, 'white', r['rank'], 50, y + 4, mono=True, center=True)
                art.text(c, 'yellow' if r['rank'] <= 3 else 'teal', r['name'],
                         100, y + 3, maxw=330)
                art.text(c, 'white', r['score'], 620, y + 4, right=True, mono=True)
        online = snap['online']
        art.text(c, 'drum', 'ONLINE %d' % online if online is not None else 'OFFLINE',
                 20, 412)
        nav = []
        n = len(snap['comps'])
        if comp is not None and n > 1:
            nav.append('TOURNAMENT %d OF %d' % (snap['comps'].index(comp) + 1, n))
        if pages > 1:
            nav.append('PAGE %d OF %d' % (page + 1, pages))
        if nav:
            art.text(c, 'teal', '   '.join(nav), 620, 457, right=True, scale=0.7)
        return c

    def render_online(self, snap, art, comp, brand=True):
        """The ONLINE PLAY screen, built the way the game builds its lobby:
        the title strip, the side strip with the game's name, a highlighted
        bar for the tournament, its stages, and the lobby's framed panel with
        who is online. The date sits bottom left in UTC, as the lobby shows
        it."""
        theme = art.index.get('theme') or {}
        bg = theme.get('online_bg')
        if isinstance(bg, str):
            c = boardimg.Canvas.from_image(art.image(bg))
        else:
            c = boardimg.Canvas(W, H)
            c.gradient(*(bg or [[0, 0, 0], [0, 0, 0]]))
        sprites = art.index['sprites']
        if 'side' in sprites:
            sw, sh = sprites['side'][3:5]
            art.sprite(c, 'side', 2 if sw > 16 else 0, 54 if sh < H else 0)
        if 'header' in sprites:
            art.sprite(c, 'header', 0, 8)
            art.sprite(c, 'online_play', 18, 18)
        if brand and 'logo' in sprites:
            f, sx, sy, sw, sh = sprites['logo']
            w = round(sw * 34 / sh)
            art.sprite(c, 'logo', 632 - w, 10, h=34)
        accent = theme.get('accent', 'yellow')
        if comp is None:
            art.text(c, accent, 'NO TOURNAMENT', 56, 64)
        else:
            art.sprite(c, 'lobby_bar', 44, 56)
            when = {'open': 'ENDS ' + left(comp['end']),
                    'upcoming': 'OPENS ' + left(comp['start']),
                    'ended': 'ENDED'}[comp['status']]
            # the bar is the name's; the countdown sits beside it
            art.fit_text(c, 'teal', comp['name'], 60, 62, 400, least=0.6)
            art.text(c, 'yellow', when, 632, 63, right=True, scale=0.5)
            art.text(c, accent, 'STAGES', 632, 78, right=True, scale=0.5)
            songs = comp['songs'][:10]
            # one size for the whole list, the size its longest title fits at
            widest = max([art.text_width('teal', s['title']) for s in songs] or [1])
            k = max(0.55, min(0.8, 540 / max(1, widest)))
            for i, s in enumerate(songs):
                y = 102 + i * 24
                art.text(c, 'white', i + 1, 70, y, right=True, mono=True, scale=0.8)
                art.text(c, 'teal', s['title'], 82, y + round((0.8 - k) * 12), maxw=540,
                         scale=k)
        # the lobby's framed panel: who is here
        e = theme.get('frame_edge', 12)
        art.panel(c, 'frame', 40, 348, 584, 104, e)
        players = snap['players']
        head = ('SERVER OFFLINE' if snap['online'] is None
                else 'ONLINE NOW %d' % len(players))
        art.text(c, 'yellow', head, 58, 358, scale=0.7)
        for i, p in enumerate(players[:3]):
            y = 380 + i * 22
            art.text(c, 'teal', p['name'], 58, y, maxw=300, scale=0.75)
            art.text(c, 'yellow', ACTIVITY.get(p['activity'], ''), 606, y, right=True,
                     scale=0.75)
        if len(players) > 3:
            art.text(c, 'teal', 'AND %d MORE' % (len(players) - 3), 606, 358, right=True,
                     scale=0.7)
        art.text(c, 'yellow', time.strftime('%m.%d.%Y %H:%M UTC', time.gmtime()),
                 12, 460, scale=0.55)
        return c

    def render(self, snap, args, view=None):
        art = self.art(args)
        if art is None:
            return None
        return self.render_view(snap, art, view or self.default_view(snap)).png()

    # -- Discord --------------------------------------------------------------

    def discord_events(self, prev, snap):
        md = boarddata.md
        out = []
        before = {c['id']: c for c in prev['comps']}
        for c in snap['comps']:
            old = before.get(c['id'])
            if c['status'] == 'open' and (old is None or old['status'] != 'open'):
                out.append('Tournament **%s** is now open, %d stage%s.'
                           % (md(c['name']), len(c['songs']),
                              's' * (len(c['songs']) != 1)))
            elif c['status'] == 'ended' and old is not None and old['status'] == 'open':
                podium = ', '.join('%d. %s' % (r['rank'], md(r['name']))
                                   for r in c['board'][:3])
                out.append('Tournament **%s** has ended. %s'
                           % (md(c['name']), podium or 'Nobody entered.'))
            elif c['status'] == 'open' and c['board'] and old is not None and (
                    not old['board']
                    or old['board'][0]['player'] != c['board'][0]['player']):
                out.append('**%s** takes the lead in **%s** with %s.'
                           % (md(c['board'][0]['name']), md(c['name']),
                              '{:,}'.format(c['board'][0]['score'])))
        return out

    def news(self, snap):
        """Lasting announcements, for a server's news channel: each
        tournament opening and each one ending. A key names each, so it is
        announced once; `at` is when it happened, so a restart does not
        announce last month's."""
        md = boarddata.md
        out = []
        for c in snap['comps']:
            key = '%s-%s-%s' % (self.NAME, c['id'], c['name'])
            if c['status'] in ('open', 'ended'):
                out.append({'key': key + '-open', 'at': c['start'],
                            'view': 'online.%s' % c['id'],
                            'text': '**%s**: tournament **%s** is open until <t:%d:f>. '
                                    '%d stage%s; enter from ONLINE PLAY.'
                                    % (self.TITLE, md(c['name']), c['end'], len(c['songs']),
                                       's' * (len(c['songs']) != 1))})
            if c['status'] == 'ended':
                podium = ', '.join('%d. %s' % (r['rank'], md(r['name']))
                                   for r in c['board'][:3])
                out.append({'key': key + '-end', 'at': c['end'],
                            'view': 'rank.%s.0' % c['id'],
                            'text': '**%s**: tournament **%s** has ended. %s'
                                    % (self.TITLE, md(c['name']),
                                       ('Winners: ' + podium) if podium
                                       else 'Nobody entered.')})
        return out

    def discord_message(self, snap, args, view=None):
        """The board message: the default view as an attached picture. With a
        bot, boardbot adds the buttons; a click shows another view in place."""
        online = snap['online']
        lines = ['**%d** online' % online if online is not None else 'Server offline']
        comp = featured(snap['comps'])
        if comp is not None:
            when = {'open': 'ends <t:%d:R>' % comp['end'],
                    'upcoming': 'opens <t:%d:R>' % comp['start'],
                    'ended': 'ended <t:%d:R>' % comp['end']}[comp['status']]
            lines.append('**%s** %s' % (boarddata.md(comp['name']), when))
        embed = {'title': self.TITLE + ' ONLINE', 'description': '\n'.join(lines),
                 'color': 0x0a8fa3 if self.NAME == 'sn' else 0x2fd6e8,
                 'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ',
                                            time.gmtime(snap['stamp']))}
        url = getattr(args, '%s_url' % self.NAME, '')
        if url:
            embed['url'] = url
        files = []
        image = self.render(snap, args, view)
        if image is not None:
            embed['image'] = {'url': 'attachment://board.png'}
            files.append(('board.png', 'image/png', image))
        elif comp is not None:
            embed['fields'] = [{'name': comp['name'][:200], 'value': '\n'.join(
                '`%2d` **%s** %s' % (r['rank'], boarddata.md(r['name']),
                                     '{:,}'.format(r['score']))
                for r in comp['board'][:5]) or '*No entries yet.*'}]
        payload = {'embeds': [embed], 'allowed_mentions': {'parse': []},
                   # replaces the last image on an edit instead of adding one
                   'attachments': [{'id': i, 'filename': f[0]}
                                   for i, f in enumerate(files)]}
        return payload, files


BOARD = SnBoard('sn', 'DDR SuperNOVA', 'sn_comps')
