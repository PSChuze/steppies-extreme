#!/usr/bin/env python3
"""SQLite storage for accounts, player files, friends and results.

One database, `ddr.db`, in the state directory. It uses the `sqlite3` module
from the standard library, so it adds nothing to install and keeps the
"nothing to build" promise.

Why a database and not the JSON files it replaces: results grow with every
play, and the old code rewrote the whole file on each one. SQLite inserts one
row and commits it atomically, survives a power cut mid-write without a
hand-rolled temp-and-rename, and lets a ranking board be a small indexed query
instead of loading all of history into memory.

Accounts, player files and friends are small and bounded, so the gate keeps
them in memory exactly as before and writes the whole set back on each change;
that is cheap and keeps the account and friends code untouched. Only results
are incremental.

On first run against a directory that still has the old `state.json` and
`results.json`, their contents are imported once, so upgrading loses nothing.
"""
import json
import os
import sqlite3
import threading
import time

from schedule import RC_WEEK_SECONDS, RC_WEEKS

_lock = threading.RLock()
_conn = None
_dir = None

POINTS = {'win': 3, 'draw': 1, 'loss': 0}

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS accounts (key TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS player_files (
    account_key TEXT, slot INTEGER, id INTEGER, name TEXT, dancer INTEGER,
    extra TEXT, PRIMARY KEY (account_key, slot));
CREATE TABLE IF NOT EXISTS friends (
    player_id TEXT, other_id TEXT, state INTEGER,
    PRIMARY KEY (player_id, other_id));
-- Login credentials, for verifying a password instead of trusting whatever
-- the client sends. The 0x3003 login blob is username[32] + MD5(username +
-- the server's challenge + password), and the challenge is a constant, so the
-- digest is stable per (username, password). The username here is the hex of
-- that 32-byte field with trailing NULs removed; it is finer than the 8-byte
-- account key, so two usernames that share a key still have separate
-- credentials. `source` is 'login' for trust-on-first-use or 'register' if a
-- registration flow wrote it. Empty unless --verify-login is on.
CREATE TABLE IF NOT EXISTS credentials (
    username TEXT PRIMARY KEY, digest TEXT, source TEXT, updated TEXT);
CREATE TABLE IF NOT EXISTS rc_results (
    t INTEGER, week INTEGER, card INTEGER, player INTEGER, name TEXT,
    dancer INTEGER, score INTEGER, combo INTEGER, ms INTEGER, stage INTEGER,
    song INTEGER);
CREATE TABLE IF NOT EXISTS rc_entries (
    t INTEGER, week INTEGER, card INTEGER, player INTEGER);
CREATE TABLE IF NOT EXISTS h2h_results (
    t INTEGER, week INTEGER,
    a_player INTEGER, a_name TEXT, a_dancer INTEGER, a_score INTEGER,
    b_player INTEGER, b_name TEXT, b_dancer INTEGER, b_score INTEGER);
CREATE TABLE IF NOT EXISTS sn_comp_results (
    t INTEGER, comp INTEGER, player INTEGER, name TEXT, stage INTEGER,
    score INTEGER);
CREATE INDEX IF NOT EXISTS rc_week ON rc_results (week, card);
CREATE INDEX IF NOT EXISTS rc_entry_week ON rc_entries (week, player);
CREATE INDEX IF NOT EXISTS h2h_week ON h2h_results (week);
CREATE INDEX IF NOT EXISTS sn_comp_idx ON sn_comp_results (comp);
"""

# Player-file keys stored as their own columns; anything else (options blob,
# endpoint, and whatever is added later) rides along in the `extra` JSON so the
# schema does not have to change to keep a new field.
PF_COLUMNS = ('slot', 'id', 'name', 'dancer')


def setup(state_dir):
    """Open (creating if needed) ddr.db in `state_dir`, and import the old JSON
    files once if the database is still empty. Safe to call more than once."""
    global _conn, _dir
    with _lock:
        if _conn is not None:
            return
        _dir = state_dir or '.'
        os.makedirs(_dir, exist_ok=True)
        _conn = sqlite3.connect(os.path.join(_dir, 'ddr.db'),
                                check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.executescript('PRAGMA journal_mode=WAL;'
                            'PRAGMA synchronous=NORMAL;' + SCHEMA)
        _conn.commit()
        _import_json_once()


def close():
    global _conn
    with _lock:
        if _conn is not None:
            _conn.close()
            _conn = None


def _import_json_once():
    """One-time import from state.json and results.json, if present and the
    matching tables are empty. Never deletes the JSON; it just stops being
    read once the database has the data."""
    cur = _conn.execute('SELECT COUNT(*) FROM accounts')
    have_comp = _conn.execute('SELECT COUNT(*) FROM sn_comp_results').fetchone()[0]
    if cur.fetchone()[0] == 0 or have_comp == 0:
        sj = os.path.join(_dir, 'state.json')
        if os.path.exists(sj):
            try:
                with open(sj, encoding='utf-8') as f:
                    st = json.load(f)
                if _conn.execute('SELECT COUNT(*) FROM accounts').fetchone()[0] == 0:
                    _write_state(st)
                    print('  imported accounts from %s' % sj, flush=True)
                if have_comp == 0 and st.get('sn_comp'):
                    _import_sn_comp(st['sn_comp'])
                    print('  imported tournament results from %s' % sj,
                          flush=True)
            except (OSError, ValueError) as e:
                print('!! could not import %s: %s' % (sj, e), flush=True)
    empty = _conn.execute('SELECT COUNT(*) FROM rc_results').fetchone()[0] == 0 \
        and _conn.execute('SELECT COUNT(*) FROM h2h_results').fetchone()[0] == 0
    if empty:
        rj = os.path.join(_dir, 'results.json')
        if os.path.exists(rj):
            try:
                with open(rj, encoding='utf-8') as f:
                    r = json.load(f)
                _import_results(r)
                print('  imported results from %s' % rj, flush=True)
            except (OSError, ValueError) as e:
                print('!! could not import %s: %s' % (rj, e), flush=True)


def _import_results(r):
    now = int(time.time())
    with _conn:
        for e in r.get('rc_entries', []):
            _conn.execute('INSERT INTO rc_entries (t,week,card,player) '
                          'VALUES (?,?,?,?)',
                          (e.get('t', now), e.get('week', 0), e.get('card', 0),
                           e.get('player', 0)))
        for x in r.get('rc', []):
            _conn.execute(
                'INSERT INTO rc_results (t,week,card,player,name,dancer,score,'
                'combo,ms,stage,song) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
                (x.get('t', now), x.get('week', 0), x.get('card', 0),
                 x.get('player', 0), x.get('name', ''), x.get('dancer', 0),
                 x.get('score', 0), x.get('combo', 0), x.get('ms', 0),
                 x.get('stage', 0), x.get('song')))
        for h in r.get('h2h', []):
            a, b = h.get('a', {}), h.get('b', {})
            _conn.execute(
                'INSERT INTO h2h_results (t,week,a_player,a_name,a_dancer,'
                'a_score,b_player,b_name,b_dancer,b_score) '
                'VALUES (?,?,?,?,?,?,?,?,?,?)',
                (h.get('t', now), h.get('week', 0),
                 a.get('player', 0), a.get('name', ''), a.get('dancer', 0),
                 a.get('score', 0), b.get('player', 0), b.get('name', ''),
                 b.get('dancer', 0), b.get('score', 0)))


def _import_sn_comp(sn):
    """Import interim SuperNOVA tournament results kept in state.json under
    STATE['sn_comp'] = {comp: {pid: {name, stages: {stage: best_score}}}}
    before this database existed. One row per (player, stage)."""
    now = int(time.time())
    with _conn:
        for comp, players in (sn or {}).items():
            for pid, rec in (players or {}).items():
                name = rec.get('name', '')
                for stage, score in (rec.get('stages') or {}).items():
                    _conn.execute(
                        'INSERT INTO sn_comp_results (t,comp,player,name,stage,'
                        'score) VALUES (?,?,?,?,?,?)',
                        (now, int(comp), int(pid), name, int(stage), score))


# -- accounts, player files, friends: the in-memory STATE, loaded and saved ----

def load_state():
    """Return the STATE dict the gate keeps in memory: the same shape the old
    state.json had, so nothing downstream changes."""
    with _lock:
        st = {'accounts': {}, 'next_id': 1, 'friends': {}}
        row = _conn.execute("SELECT v FROM meta WHERE k='next_id'").fetchone()
        if row:
            st['next_id'] = int(row[0])
        for a in _conn.execute('SELECT key FROM accounts'):
            st['accounts'][a['key']] = {'player_files': []}
        for p in _conn.execute('SELECT * FROM player_files ORDER BY slot'):
            acc = st['accounts'].setdefault(p['account_key'],
                                            {'player_files': []})
            pf = {'slot': p['slot'], 'id': p['id'], 'name': p['name'],
                  'dancer': p['dancer']}
            if p['extra']:
                pf.update(json.loads(p['extra']))
            acc['player_files'].append(pf)
        for f in _conn.execute('SELECT * FROM friends'):
            st['friends'].setdefault(f['player_id'], {})[f['other_id']] = \
                f['state']
        return st


def save_state(state):
    """Write the whole in-memory STATE back. The account and friends data is
    small and bounded, so replacing it wholesale each time is cheap; results
    are never touched here."""
    with _lock:
        _write_state(state)


def _write_state(state):
    with _conn:
        _conn.execute('DELETE FROM accounts')
        _conn.execute('DELETE FROM player_files')
        _conn.execute('DELETE FROM friends')
        _conn.execute("INSERT OR REPLACE INTO meta (k,v) VALUES ('next_id',?)",
                      (str(state.get('next_id', 1)),))
        for key, acc in state.get('accounts', {}).items():
            _conn.execute('INSERT OR REPLACE INTO accounts (key) VALUES (?)',
                          (key,))
            for pf in acc.get('player_files', []):
                extra = {k: v for k, v in pf.items() if k not in PF_COLUMNS}
                _conn.execute(
                    'INSERT OR REPLACE INTO player_files '
                    '(account_key,slot,id,name,dancer,extra) '
                    'VALUES (?,?,?,?,?,?)',
                    (key, pf.get('slot', 0), pf.get('id', 0), pf.get('name', ''),
                     pf.get('dancer', 0),
                     json.dumps(extra) if extra else None))
        for pid, others in state.get('friends', {}).items():
            for other, stt in others.items():
                _conn.execute('INSERT OR REPLACE INTO friends '
                              '(player_id,other_id,state) VALUES (?,?,?)',
                              (str(pid), str(other), stt))


# -- results: incremental inserts and indexed queries --------------------------

def _occurrence(week, now):
    """Absolute week index of the latest occurrence of week number `week` at or
    before `now`. Week numbers wrap every RC_WEEKS, so a board for one number
    covers only its most recent run."""
    cur = int(now) // RC_WEEK_SECONDS
    return cur - ((cur % RC_WEEKS + 1 - week) % RC_WEEKS)


def _window(week, now):
    """(t_lo, t_hi) bounding the latest occurrence of `week`."""
    w = _occurrence(week, now)
    return w * RC_WEEK_SECONDS, (w + 1) * RC_WEEK_SECONDS


def record_rc_entry(pid, week, card, now=None):
    now = int(now or time.time())
    with _lock, _conn:
        _conn.execute('INSERT INTO rc_entries (t,week,card,player) '
                      'VALUES (?,?,?,?)', (now, week, card, pid))


def record_rc(pid, name, dancer, week, card, score, combo, ms, stage,
              song=None, now=None):
    now = int(now or time.time())
    with _lock, _conn:
        _conn.execute(
            'INSERT INTO rc_results (t,week,card,player,name,dancer,score,'
            'combo,ms,stage,song) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
            (now, week, card, pid, name, dancer, score, combo, ms, stage, song))


def record_h2h(week, a, b, now=None):
    now = int(now or time.time())
    with _lock, _conn:
        _conn.execute(
            'INSERT INTO h2h_results (t,week,a_player,a_name,a_dancer,a_score,'
            'b_player,b_name,b_dancer,b_score) VALUES (?,?,?,?,?,?,?,?,?,?)',
            (now, week, a.get('player', 0), a.get('name', ''),
             a.get('dancer', 0), a.get('score', 0), b.get('player', 0),
             b.get('name', ''), b.get('dancer', 0), b.get('score', 0)))
    return outcome(a.get('score', 0), b.get('score', 0))


def outcome(sa, sb):
    if sa == sb:
        return 'draw', 'draw'
    return ('win', 'loss') if sa > sb else ('loss', 'win')


def rc_tries(pid, week, now=None):
    now = int(now or time.time())
    lo, hi = _window(week, now)
    counts = [0, 0]
    with _lock:
        for r in _conn.execute(
                'SELECT card, COUNT(*) n FROM rc_entries '
                'WHERE player=? AND week=? AND t>=? AND t<? GROUP BY card',
                (pid, week, lo, hi)):
            if r['card'] in (0, 1):
                counts[r['card']] = min(r['n'], 255)
    return counts[0], counts[1]


def rc_board(week, card, now=None):
    now = int(now or time.time())
    with _lock:
        if week <= 0:
            rows = _conn.execute(
                'SELECT player, score, name, dancer, t FROM rc_results '
                'WHERE card=?', (card,)).fetchall()
        else:
            lo, hi = _window(week, now)
            rows = _conn.execute(
                'SELECT player, score, name, dancer, t FROM rc_results '
                'WHERE card=? AND week=? AND t>=? AND t<?',
                (card, week, lo, hi)).fetchall()
    best = {}
    latest = {}
    for r in rows:
        pid = r['player']
        if pid not in best or r['score'] > best[pid]['score']:
            best[pid] = r
        if pid not in latest or r['t'] >= latest[pid]['t']:
            latest[pid] = r
    order = sorted(best.values(), key=lambda r: (-r['score'], r['t']))
    return [{'rank': i + 1, 'player': r['player'],
             'name': latest[r['player']]['name'],
             'dancer': latest[r['player']]['dancer'],
             'rc_score': r['score']}
            for i, r in enumerate(order)]


def _h2h_rows(week, now):
    with _lock:
        if week <= 0:
            return _conn.execute('SELECT * FROM h2h_results').fetchall()
        lo, hi = _window(week, now)
        return _conn.execute(
            'SELECT * FROM h2h_results WHERE week=? AND t>=? AND t<?',
            (week, lo, hi)).fetchall()


def h2h_tally(week=0, now=None):
    now = int(now or time.time())
    out = {}
    names = {}
    for r in _h2h_rows(week, now):
        pa, pb = r['a_player'], r['b_player']
        names[pa] = (r['a_name'], r['a_dancer'])
        names[pb] = (r['b_name'], r['b_dancer'])
        for pid, res in zip((pa, pb), outcome(r['a_score'], r['b_score'])):
            t = out.setdefault(pid, {'match': 0, 'win': 0, 'draw': 0,
                                     'loss': 0, 'points': 0})
            t['match'] += 1
            t[res] += 1
            t['points'] += POINTS[res]
    for pid, t in out.items():
        t['name'], t['dancer'] = names.get(pid, ('', 0))
    return out


def _rank(tally, key):
    return [dict(t, player=pid, rank=i + 1)
            for i, (pid, t) in enumerate(sorted(tally.items(), key=key))]


def h2h_board(week=0, now=None):
    return _rank(h2h_tally(week, now),
                 lambda kv: (-kv[1]['win'], kv[1]['loss'], -kv[1]['draw'], kv[0]))


def points_board(week=0, now=None):
    return _rank(h2h_tally(week, now),
                 lambda kv: (-kv[1]['points'], -kv[1]['win'], kv[0]))


def _rank_of(board, pid):
    return next((r['rank'] for r in board if r['player'] == pid), 0)


def player_stats(pid, week, now=None):
    total, weekly = h2h_tally(0, now), h2h_tally(week, now)
    t, w = total.get(pid, {}), weekly.get(pid, {})
    return {
        'match_total': t.get('match', 0), 'win_total': t.get('win', 0),
        'draw_total': t.get('draw', 0), 'loss_total': t.get('loss', 0),
        'match_week': w.get('match', 0), 'win_week': w.get('win', 0),
        'draw_week': w.get('draw', 0), 'loss_week': w.get('loss', 0),
        'points_total': t.get('points', 0), 'points_week': w.get('points', 0),
        'ranking_h2h_total': _rank_of(h2h_board(0, now), pid),
        'ranking_h2h_week': _rank_of(h2h_board(week, now), pid),
        'ranking_point_total': _rank_of(points_board(0, now), pid),
        'ranking_point_week': _rank_of(points_board(week, now), pid),
    }


def rc_log(pid, cap=119, now=None):
    with _lock:
        mine = _conn.execute(
            'SELECT * FROM rc_results WHERE player=? ORDER BY t DESC LIMIT ?',
            (pid, cap)).fetchall()
    out = []
    for r in mine:
        board = rc_board(r['week'], r['card'], r['t'] + 1)
        out.append({'song': r['song'], 'ranking': _rank_of(board, pid),
                    'score': r['score'], 'ms': r['ms'], 'combo': r['combo']})
    return out


def _weeks_played(pid, now):
    with _lock:
        rows = _conn.execute(
            'SELECT DISTINCT week, MAX(t) mt FROM h2h_results '
            'WHERE a_player=? OR b_player=? GROUP BY week ORDER BY mt DESC',
            (pid, pid)).fetchall()
    seen = []
    for r in rows:
        lo, hi = _window(r['week'], now)
        if lo <= r['mt'] < hi:
            seen.append(r['week'])
    return seen


def h2h_log(pid, cap=59, now=None):
    now = int(now or time.time())
    out = []
    for wk in _weeks_played(pid, now)[:cap]:
        t = h2h_tally(wk, now).get(pid, {})
        out.append({'week': wk, 'match': t.get('match', 0),
                    'win': t.get('win', 0), 'draw': t.get('draw', 0),
                    'loss': t.get('loss', 0)})
    return out


def point_log(pid, cap=59, now=None):
    now = int(now or time.time())
    out = []
    for wk in _weeks_played(pid, now)[:cap]:
        out.append({'week': wk,
                    'ranking': _rank_of(points_board(wk, now), pid),
                    'points': h2h_tally(wk, now).get(pid, {}).get('points', 0)})
    return out


# -- SuperNOVA competition results --------------------------------------------

def sn_comp_record(comp, pid, name, stage, score, now=None):
    """One tournament stage result. Each 0x5006 is a single stage (1..10);
    the `stage` column is stored so the board can sum a player's best on each
    stage rather than reward one lucky stage."""
    now = int(now or time.time())
    with _lock, _conn:
        _conn.execute('INSERT INTO sn_comp_results (t,comp,player,name,stage,'
                      'score) VALUES (?,?,?,?,?,?)',
                      (now, comp, pid, name, stage, score))


def sn_comp_board(comp, limit=100, now=None):
    """Competition standings, best total first.

    A player's total is the sum of their best score on each stage they have
    played; `stages` is how many distinct stages that is. Ranking on the total
    means a full run beats one lucky stage.
    """
    with _lock:
        rows = _conn.execute(
            'SELECT player, name, stage, score, t FROM sn_comp_results '
            'WHERE comp=?', (comp,)).fetchall()
    best = {}          # player -> {stage -> best score}
    latest = {}        # player -> most recent name
    for r in rows:
        st = best.setdefault(r['player'], {})
        if r['stage'] not in st or r['score'] > st[r['stage']]:
            st[r['stage']] = r['score']
        if r['player'] not in latest or r['t'] >= latest[r['player']][0]:
            latest[r['player']] = (r['t'], r['name'])
    tally = [(pid, sum(s.values()), len(s)) for pid, s in best.items()]
    tally.sort(key=lambda x: (-x[1], x[0]))
    return [{'rank': i + 1, 'player': pid, 'name': latest[pid][1],
             'score': total, 'stages': nstages}
            for i, (pid, total, nstages) in enumerate(tally[:limit])]


# -- login credentials: trust-on-first-use, or set by a registration flow -----

def credential_verify(username, digest, now=None):
    """Check a login digest against the stored one for `username`.

    Returns 'first' the first time a username is seen (and records it), 'ok'
    when the digest matches, and 'mismatch' when it does not. `username` and
    `digest` are hex strings.
    """
    now = int(now or time.time())
    with _lock, _conn:
        row = _conn.execute('SELECT digest FROM credentials WHERE username=?',
                            (username,)).fetchone()
        if row is None:
            _conn.execute('INSERT INTO credentials (username,digest,source,'
                          'updated) VALUES (?,?,?,?)',
                          (username, digest, 'login', str(now)))
            return 'first'
        return 'ok' if row['digest'] == digest else 'mismatch'


def credential_set(username, digest, source='register', now=None):
    """Store or replace a credential, for a registration or password change."""
    now = int(now or time.time())
    with _lock, _conn:
        _conn.execute('INSERT OR REPLACE INTO credentials (username,digest,'
                      'source,updated) VALUES (?,?,?,?)',
                      (username, digest, source, str(now)))
