#!/usr/bin/env python3
"""Play results for Extreme 2: decode, keep, rank, serve back.

The wire decoders live here. The storage and the ranking queries live in
`db.py` (SQLite), and this module re-exports them so the gate keeps calling
`results.record_rc`, `results.rc_board` and so on unchanged. It used to hold a
JSON file of its own; that moved into the one database `db.py` owns, which
inserts each result instead of rewriting a whole file and answers a board with
an indexed query instead of loading all of history.

`LOCK` is here for the gate's endgame-pairing critical section, which has to be
atomic across two connections; it is separate from the database's own lock.
"""
import struct
import threading

from db import (record_rc, record_rc_entry, record_h2h, rc_tries, rc_board,
                h2h_tally, h2h_board, points_board, player_stats, rc_log,
                h2h_log, point_log, sn_comp_record, sn_comp_board,
                credential_verify, credential_set)

# Re-exported so `results.X` keeps working; silences unused-import checkers.
__all__ = ['record_rc', 'record_rc_entry', 'record_h2h', 'rc_tries',
           'rc_board', 'h2h_tally', 'h2h_board', 'points_board',
           'player_stats', 'rc_log', 'h2h_log', 'point_log', 'outcome', 'LOCK',
           'parse_rc_entry', 'parse_rc_regist', 'parse_endgame',
           'sn_comp_record', 'sn_comp_board', 'credential_verify',
           'credential_set']

LOCK = threading.RLock()


def outcome(row):
    """(result for a, result for b) for a stored head-to-head row."""
    from db import outcome as _o
    return _o(row['a'].get('score', 0), row['b'].get('score', 0))


# -- the three messages the client sends --------------------------------------

def parse_rc_entry(payload):
    """0x5004 GetRCEntry: s32 player id, u8 featured card (0 or 1)."""
    if len(payload) < 5:
        return None
    pid, card = struct.unpack('>iB', payload[:5])
    return {'player': pid, 'card': card}


def parse_rc_regist(payload):
    """0x5006 GetRCRegist: s32 player id, s32 score, s32 play time in ms,
    s16 max combo, s16 stage field.

    Score and max combo are confirmed against a results screen. The time is
    inferred from two samples. The stage field has been 0 in every sample.
    """
    if len(payload) < 16:
        return None
    pid, score, ms, combo, stage = struct.unpack('>iiihh', payload[:16])
    return {'player': pid, 'score': score, 'ms': ms, 'combo': combo,
            'stage': stage}


def parse_endgame(payload):
    """0x4430 GetEndgame: 36 bytes, a copy of a stack struct the save-record
    builder at 0x00236f40 zeroes and then fills in four places.

        wire order   +4 u32 score, +0 u16 stage counter, +8 u32 PLAY+0x30,
                     +2 u16 PLAY+0x124, then 12 u16 that are always zero

    The score is computed from two play counters just before the call. The two
    PLAY fields are unnamed: +0x30 read the same for both players of one match
    (14400), +0x124 read 8 and 109 in a match one player failed early.
    """
    if len(payload) < 12:
        return None
    score, stage, p30, p124 = struct.unpack('>iHIH', payload[:12])
    return {'score': score, 'stage': stage, 'p30': p30, 'p124': p124}
