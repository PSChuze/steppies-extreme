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
    return spread(pool, week * 7 + challenge * 13, week * 3 + challenge * 5,
                  count)


def spread(pool, a, b, count, shuffled=False):
    """`count` distinct entries of `pool`, picked by two seeds.

    Starts at slot `a` and steps by a stride derived from `b`. Any stride
    coprime with the pool size visits every slot before repeating, which is
    what keeps the picks distinct, so walk up until one is. `shuffled` also
    refuses strides 1 and n-1, which walk the table in order; the Ranking
    Challenge does not ask for it, so its published lineups do not change.
    """
    if not pool:
        return [0] * count
    n = len(pool)
    start = a % n
    step = 1 + b % max(1, n - 1)
    while (math.gcd(step, n) != 1
           or (shuffled and n > 3 and step % n in (1, n - 1))):
        step = step % (n - 1) + 1 if shuffled else step + 1
    return [pool[(start + i * step) % n] for i in range(min(count, n))]


# ── SuperNOVA 2 tournaments ───────────────────────────────────────────────
#
# Generated from the clock the way the Ranking Challenge is, so an unattended
# server always has something running and every client agrees on it.
#
# SuperNOVA 2's song table is 72 records at 0x002f1a20 in SLUS_216.08, stride
# 0xa8, and the wire id is the index into it, as in SuperNOVA. It has no
# online-only songs: SuperNOVA's five (felw, punc, nizi, silv, trim) are
# ordinary songs here, at 0x32, 0x34, 0x3c, 0x40 and 0x41.
#
# Scores are kept per competition id in a table SuperNOVA shares, so these
# ids live in their own ranges, one id per period, which also makes each
# period's board start empty. SuperNOVA's hand-written competitions use small
# ids.
SN2_SONG_IDS = 72
SN2_BAD_SONG_IDS = frozenset()       # none found yet; see RC_BAD_SONG_IDS
SN2_WEEKLY_BASE = 10000              # + week index since the epoch
SN2_MONTHLY_BASE = 20000             # + 28-day period index
SN2_MONTH_SECONDS = 28 * 24 * 3600
# Chart difficulty 0..4 (beginner .. challenge). Weekly cups rotate through
# basic, difficult and expert; not every song has a challenge chart, so 4 is
# never picked.
SN2_WEEKLY_DIFFICULTIES = (1, 2, 3)
SN2_MONTHLY_DIFFICULTY = 2


def _day(t):
    """A competition's start as the name shows it, e.g. 10/08 (UTC)."""
    return time.strftime('%m/%d', time.gmtime(t))


def sn2_auto_competitions(now=None):
    """SuperNOVA 2's competitions at `now`: this week's cup and next week's,
    and this period's marathon and the next one. The server sorts them into
    open and upcoming by their windows.

    Same shape as gate.sn_competitions entries.
    """
    now = int(time.time() if now is None else now)
    pool = sorted(set(range(SN2_SONG_IDS)) - SN2_BAD_SONG_IDS)
    out = []
    week = now // RC_WEEK_SECONDS
    for w in (week, week + 1):
        out.append({
            'id': SN2_WEEKLY_BASE + w,
            'name': 'WEEKLY CUP ' + _day(w * RC_WEEK_SECONDS),
            'songs': spread(pool, w * 11, w * 5 + 3, 5, shuffled=True),
            'start': w * RC_WEEK_SECONDS,
            'end': (w + 1) * RC_WEEK_SECONDS,
            'difficulty': SN2_WEEKLY_DIFFICULTIES[
                w % len(SN2_WEEKLY_DIFFICULTIES)],
            'options': None})
    month = now // SN2_MONTH_SECONDS
    for m in (month, month + 1):
        out.append({
            'id': SN2_MONTHLY_BASE + m,
            'name': 'MARATHON ' + _day(m * SN2_MONTH_SECONDS),
            'songs': spread(pool, m * 17 + 5, m * 7 + 1, 10, shuffled=True),
            'start': m * SN2_MONTH_SECONDS,
            'end': (m + 1) * SN2_MONTH_SECONDS,
            'difficulty': SN2_MONTHLY_DIFFICULTY,
            'options': None})
    return out
