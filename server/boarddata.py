#!/usr/bin/env python3
"""What the boards read: the database, the gate's lobby snapshot, the calendar.

All of it read-only. The boards run in their own process (boards.py) beside
the gate, and share only the state directory with it:

    ddr.db          results, opened with mode=ro so nothing here can write it
    live.json       who is online, written by the gate every few seconds
    content.json    operator overrides for the Ranking Challenge
    boardart/       art baked from the operator's own disc (boardart.py)

The ranking queries are db.py's own, run against a read-only connection, so a
board and the in-game ranking screens can never disagree.
"""
import json
import os
import sqlite3
import threading
import time

import content
import db
from schedule import RC_ENTRIES, rc_auto_songs, rc_week

#: A live.json older than this means the gate is not running, not that the
#: lobby is empty. The gate rewrites it every 5 seconds by default.
LIVE_STALE = 30.0

_open_lock = threading.Lock()


def open_db(state_dir):
    """Point db.py at a read-only connection to ddr.db. False until the gate
    has created it."""
    with _open_lock:
        if db._conn is not None:
            return True
        path = os.path.join(state_dir, 'ddr.db')
        if not os.path.exists(path):
            return False
        conn = sqlite3.connect('file:%s?mode=ro' % path, uri=True,
                               check_same_thread=False)
        conn.row_factory = sqlite3.Row
        db._conn = conn
        return True


def live(state_dir, now=None):
    """The gate's lobby snapshot, or None when the gate has not written one
    recently."""
    now = time.time() if now is None else now
    try:
        with open(os.path.join(state_dir, 'live.json'), encoding='utf-8') as fh:
            snap = json.load(fh)
    except (OSError, ValueError):
        return None
    if now - float(snap.get('stamp') or 0) > LIVE_STALE:
        return None
    return snap


def last_live(state_dir):
    """live.json whatever its age: the competition list outlives the gate."""
    try:
        with open(os.path.join(state_dir, 'live.json'), encoding='utf-8') as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def rc_cards(state_dir, now=None):
    """(week, seconds left, [songs for card 0, songs for card 1]), exactly as
    the gate serves them: generated from the week, then the operator's
    overrides from content.json on top."""
    week, left = rc_week(now)
    path = os.path.join(state_dir, 'content.json')
    cards = []
    for chal in (0, 1):
        songs = rc_auto_songs(week, chal, RC_ENTRIES)
        o_songs, _diff, o_stages = content.rc_override(week, chal, path)
        if o_songs:
            songs = (list(o_songs) + songs)[:RC_ENTRIES]
        if o_stages:
            songs = songs[:max(1, min(RC_ENTRIES, o_stages))]
        cards.append(songs)
    return week, left, cards


def recent_h2h(game, limit=10):
    """The last few head-to-head matches of one game ('x2' or 'sn')."""
    with db._lock:
        rows = db._conn.execute(
            'SELECT * FROM h2h_results WHERE game=? ORDER BY t DESC LIMIT ?',
            (game, limit)).fetchall()
    return [{'t': r['t'],
             'a': {'player': r['a_player'], 'name': r['a_name'],
                   'dancer': r['a_dancer'], 'score': r['a_score']},
             'b': {'player': r['b_player'], 'name': r['b_name'],
                   'dancer': r['b_dancer'], 'score': r['b_score']}}
            for r in rows]


def art(art_dir):
    """The baked art index (board.json), or {} when no disc has been baked:
    song titles, dancer names, and the image files the page draws with."""
    try:
        with open(os.path.join(art_dir, 'board.json'), encoding='utf-8') as fh:
            return json.load(fh) or {}
    except (OSError, ValueError):
        return {}


def md(text):
    """A player name made safe for Discord markdown."""
    return ''.join('\\' + ch if ch in '\\*_~`|>[]()#-' else ch
                   for ch in str(text))


def song_title(art_index, sid):
    return (art_index.get('songs') or {}).get(str(sid)) or 'SONG %d' % sid


def cached(fn, ttl=2.0):
    """fn(args) at most once per `ttl` seconds; every open page polls its
    board, so this keeps a crowd from becoming a query storm."""
    box = {'t': 0.0, 'v': None}
    lock = threading.Lock()

    def wrapper(args):
        with lock:
            if box['v'] is None or time.time() - box['t'] >= ttl:
                box['v'], box['t'] = fn(args), time.time()
            return box['v']
    return wrapper
