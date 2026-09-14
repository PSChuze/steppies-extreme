#!/usr/bin/env python3
"""
Poll DDR Extreme 2's live network state over PINE and print every CHANGE.

Reading these globals after the fact is useless -- the RPC framework resets its
sub-state to 0 and clears the in-flight guard when a call ends, but leaves the
error byte set, so a post-mortem read cannot tell a fresh failure from a stale
one. This samples continuously and prints only transitions, so the actual
sequence of an attempt is visible.

    python tools/pinewatch.py            # until Ctrl-C
    python tools/pinewatch.py --seconds 120

Addresses: gp = 0x00314cf0 (ELF .reginfo ri_gp_value), so the netwk pointer is
at [gp-0x6fc] = 0x003145f4. See docs/protocol.md.
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pine import Pine, PineError  # noqa: E402

NETWK_PTR = 0x003145f4
RPC_STATE = 0x01045ea0
RPC_ERROR = 0x01045ea3
RPC_GUARD = 0x01045eac
SVRLIST_PTR = 0x0104bdc0

# ── --rc: the online scene's bump allocator, for the Ranking Challenge /
# Practice tab freeze ────────────────────────────────────────────────────────
#
# The online scene allocates out of one block with a bump pointer, set up at
# 0x001e8810:
#
#     base = FUN_00203270(...)          ; one block for the whole scene
#     memset(0x0104c1b4, 0, 0x38)       ; cursor, count, and 12 size slots
#     ARENA_PTR = (base + 0x3f) & ~0x3f
#
# and every allocation is the same four lines (FUN_001e7950 case 10,
# FUN_00262c40, FUN_001f5770):
#
#     out = 0
#     if (ARENA_PTR != 0 && ARENA_N < 12) { out = ARENA_PTR; ARENA_PTR += size;
#                                           sizes[ARENA_N++] = size; }
#     RC_SONGLIST = out
#     memset(out, 0, size)              <-- NOT guarded
#
# **The failure path writes to address 0.** There is no check on `out` before
# the memset, and no check that the bump pointer is still inside the block --
# only the count against 12. So an allocation that fails clears 0x1de40 bytes
# from address 0, which is a hard freeze with no keepalives afterwards, and one
# that succeeds past the end of the block corrupts whatever follows it.
#
# ARENA_N is reset only on whole-scene transitions (0x001e86ac, 0x001e875c,
# 0x00222a3c, 0x002372f0, 0x002635ec), not per tab, so tab switches inside one
# online session accumulate. Watch ARENA_N climb toward 12 and RC_SONGLIST go
# to 0 on the visit that hangs.
ARENA_PTR = 0x0104c1b4        # bump cursor; 0 = the arena never came up
ARENA_N = 0x0104c1b8          # blocks handed out, hard cap 12
RC_SONGLIST = 0x0104c0d0      # the 0x1de40 online song list; 0 = alloc FAILED
SCENE_STATE = 0x0104bd08      # online scene state (FUN_001e84c0's switch)
RC_PUMP = 0x0104bd09          # RC fetch state machine (FUN_001e7950), 0..10
RC_PUMP_I = 0x0104bd0a        # its per-id index in case 8
RC_SCREEN = 0x0104c0d7        # 0/2/3 -- which RC sub-screen is drawn
TAB_CUR = 0x0104beec          # current tab, index into PTR_FUN_002e7c10
TAB_WANT = 0x0104beed         # tab being switched to


def sb(v):
    return v - 256 if v > 127 else v


def s32(v):
    return v - (1 << 32) if v >> 31 else v


def sample_rc(p):
    """The arena and the RC state machine. Cheap reads, all globals."""
    n = p.read(ARENA_N, 4)
    songlist = p.read(RC_SONGLIST, 4)
    d = {'arena_ptr': '0x%08x' % p.read(ARENA_PTR, 4),
         'arena_n': '%d/12%s' % (n, '  <-- CAP REACHED' if n >= 12 else ''),
         'rc_songlist': ('0x%08x' % songlist) + (
             '  <-- ALLOC FAILED, next memset hits address 0' if songlist == 0
             else ''),
         'scene': p.read(SCENE_STATE, 1),
         'rc_pump': p.read(RC_PUMP, 1),
         'rc_pump_i': p.read(RC_PUMP_I, 1),
         'rc_screen': p.read(RC_SCREEN, 1),
         'tab': '%d->%d' % (p.read(TAB_CUR, 1), p.read(TAB_WANT, 1))}
    return d


def sample(p):
    netwk = p.read(NETWK_PTR, 4)
    d = {'netwk': netwk}
    if not (0x00100000 <= netwk < 0x02000000):
        return d
    d['outer(0x6c4)'] = p.read(netwk + 0x6c4, 4)
    d['gate(0x6cc)'] = p.read(netwk + 0x6cc, 4)
    d['flags(0x6c0)'] = '0x%08x' % p.read(netwk + 0x6c0, 4)
    d['svr_idx(0x8e0)'] = s32(p.read(netwk + 0x8e0, 4))
    d['recv_op(0x8d8)'] = '0x%04x' % p.read(netwk + 0x8d8, 4)
    d['rpc_state'] = p.read(RPC_STATE, 1)
    d['rpc_err'] = sb(p.read(RPC_ERROR, 1))
    d['guard'] = '0x%08x' % p.read(RPC_GUARD, 4)
    d['svrlist'] = '0x%08x' % p.read(SVRLIST_PTR, 4)
    ctx = p.read(netwk + 0x8d0, 4)
    d['ctx'] = '0x%08x' % ctx
    if 0x00100000 <= ctx < 0x02000000:
        d['svrlist_n(ctx+0x120)'] = p.read(ctx + 0x120, 4)
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--slot', type=int, default=None)
    ap.add_argument('--interval', type=float, default=0.15)
    ap.add_argument('--seconds', type=float, default=0, help='0 = run until Ctrl-C')
    ap.add_argument('--rc', action='store_true',
                    help='also watch the online scene\'s bump allocator and the '
                         'Ranking Challenge state machine -- for the RC / '
                         'Practice tab freeze. Enter and leave the tabs while '
                         'this runs: arena_n climbing to 12, or rc_songlist '
                         'going to 0, is the freeze about to happen.')
    a = ap.parse_args()
    p = Pine(slot=a.slot) if a.slot else Pine()
    try:
        print('watching %s | %s' % (p.game_id(), p.title()), flush=True)
    except PineError as e:
        sys.exit('PINE: %s' % e)
    prev = {}
    t0 = time.time()
    while True:
        if a.seconds and time.time() - t0 > a.seconds:
            print('done.', flush=True)
            return
        try:
            cur = sample(p)
            if a.rc:
                cur.update(sample_rc(p))
        except PineError:
            time.sleep(0.5)
            continue
        diff = {k: v for k, v in cur.items() if prev.get(k) != v}
        if diff and prev:
            ts = '%7.2fs' % (time.time() - t0)
            print(ts + '  ' + '  '.join('%s=%s' % (k, v) for k, v in diff.items()),
                  flush=True)
        elif not prev:
            print('  initial: ' + '  '.join('%s=%s' % (k, v) for k, v in cur.items()),
                  flush=True)
        prev = cur
        time.sleep(a.interval)


if __name__ == '__main__':
    main()
