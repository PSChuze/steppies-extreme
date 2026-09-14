#!/usr/bin/env python3
"""The ranking-challenge calendar, and the challenge generator.

Kept apart from the gate because the operator page needs to show the same
numbers the gate serves, and the two run in different processes. Nothing here
touches the network or any state; it is arithmetic on the clock, which is what
makes it safe to call from either side and get the same answer.
"""
import math
import time

RC_ENTRIES = 10
RC_SONG_IDS = 74

# Wire song ids that must never be served. Id 8 is "Miracle Moon (L.E.D.LIGHT
# STYLE MIX)", and its Ranking Challenge banner is the only 8-bit, 256-colour
# one of the 74; the rest are 4-bit. Drawing it hangs the online scene a few
# minutes into the tab. See docs/protocol.md, "A song id that hangs the
# client". Add to this set if another one is ever found, and the generator
# below will route around it without any other change.
RC_BAD_SONG_IDS = frozenset({8})

# Ids the generator is willing to invent on its own. The whole table has now
# been served to a real client in blocks and only id 8 misbehaves, so this is
# the full range. Keep it as an explicit set rather than a bare range: if
# another id ever turns out to be bad it belongs in RC_BAD_SONG_IDS, and this
# stays the statement of what has actually been checked.
RC_TESTED_SONG_IDS = frozenset(range(0, RC_SONG_IDS))

RC_WEEK_SECONDS = 7 * 24 * 3600
RC_WEEKS = 60          # the schedule byte is 1..60; see the tab gate


def rc_week(now=None):
    """(week number, seconds remaining in it) for the 0x5012 schedule reply.

    The week is wall-clock derived rather than stored, so every client sees the
    same one, a restart does not reset it, and it advances on its own. That is
    what makes an unattended server feel like it has a running event instead of
    a frozen one.
    """
    now = int(time.time() if now is None else now)
    week = int(now // RC_WEEK_SECONDS) % RC_WEEKS + 1
    return week, RC_WEEK_SECONDS - int(now % RC_WEEK_SECONDS)


def rc_auto_songs(week, challenge, count=RC_ENTRIES):
    """Song ids for one challenge in one week, generated not configured.

    Deterministic, so it survives a restart and every client agrees, and
    arithmetic rather than `random`, so it does not depend on the seeding
    details of a particular Python version.

    The pool is the tested ids minus the known-bad ones. Stepping through it by
    a stride coprime with its length visits distinct slots, so the ten ids in a
    challenge never repeat.
    """
    pool = sorted(RC_TESTED_SONG_IDS - RC_BAD_SONG_IDS)
    if not pool:
        return [0] * count
    n = len(pool)
    start = (week * 7 + challenge * 13) % n
    # Any stride coprime with the pool size visits every slot before repeating,
    # which is what keeps the ten ids distinct. Walk up until one is.
    step = 1 + (week * 3 + challenge * 5) % max(1, n - 1)
    while math.gcd(step, n) != 1:
        step += 1
    return [pool[(start + i * step) % n] for i in range(min(count, n))]
