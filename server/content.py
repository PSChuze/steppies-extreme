#!/usr/bin/env python3
"""Operator-editable content, shared between the gate and the web admin.

One small JSON file that the web process writes and the gate process reads.
They are separate containers, so this is the only thing they share besides the
state directory itself.

Everything here is optional. With no file, or an empty one, the gate falls back
to what it generates on its own, which is the point: a server nobody administers
still has a running event and sensible news. This exists so that a server
someone *does* administer can say something specific.

Shape:

    {
      "news": [ {"title": "...", "body": "..."} ],
      "rc":   { "songs": {"0": [id, ...], ...}, "difficulty": 0, "stages": 10 }
    }

`news` replaces the built-in news when non-empty. `rc` overrides the generated
challenge when present; any field left out falls back to the generated value, so
an entry with only "difficulty" changes the difficulty and leaves the song
lineup rotating.

Reads are cached on the file's mtime, so the gate can call load() on every
request without touching the disk each time.
"""
import json
import os
import threading

DEFAULT_PATH = '/state/content.json'

_lock = threading.Lock()
_cache = {'path': None, 'mtime': None, 'data': {}}

EMPTY = {'news': [], 'rc': None}


def load(path=DEFAULT_PATH):
    """Current content, or EMPTY if there is no file or it is unreadable.

    A broken file must never take the server down: an operator editing JSON by
    hand at 2am should get their old content back and a log line, not a dead
    lobby. The caller decides whether to complain.
    """
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return dict(EMPTY)
    with _lock:
        if _cache['path'] == path and _cache['mtime'] == mtime:
            return _cache['data']
    try:
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError('top level is not an object')
    except Exception:
        return dict(EMPTY)
    out = dict(EMPTY)
    news = data.get('news')
    if isinstance(news, list):
        out['news'] = [n for n in news
                       if isinstance(n, dict) and n.get('title')]
    rc = data.get('rc')
    if isinstance(rc, dict):
        out['rc'] = rc
    with _lock:
        _cache.update(path=path, mtime=mtime, data=out)
    return out


def save(data, path=DEFAULT_PATH):
    """Write content atomically, so a reader never sees a half-written file."""
    tmp = path + '.tmp'
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    with _lock:
        _cache.update(path=None, mtime=None, data={})


def rc_override(week, challenge, path=DEFAULT_PATH):
    """Operator overrides for one challenge, as (songs, difficulty, stages).

    Any element may be None, meaning "use the generated value".
    """
    rc = load(path).get('rc') or {}
    songs = None
    table = rc.get('songs')
    if isinstance(table, dict):
        picked = table.get(str(challenge))
        if isinstance(picked, list) and picked:
            songs = [int(x) for x in picked if isinstance(x, (int, float))]
    diff = rc.get('difficulty')
    stages = rc.get('stages')
    return (songs or None,
            int(diff) if isinstance(diff, (int, float)) else None,
            int(stages) if isinstance(stages, (int, float)) else None)
