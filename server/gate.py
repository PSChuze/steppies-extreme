#!/usr/bin/env python3
"""
Stub gate server for DDR Extreme 2 / SuperNOVA (Konami "dx2" backend).

Listens on TCP 9573 -- the port DDR Extreme 2 hardcodes for
dx2gate01.konamionline.com (immediate 0x2565 at 0x001d4f34).

Frame format (see docs/protocol.md, recovered from 0x00856de0 / 0x00856cd8):

    The WHOLE frame is XOR'd with a repeating 4-byte key, index = i & 3 counted
    from the start of the frame. After de-XOR the 24-byte header is big-endian:

        +0x00  u16  opcode
        +0x02  u16  payload length   (hard cap 0x400 == 1024)
        +0x04  u32  serial
        +0x08  16B  MD5(plain_header[0:8] || plain_payload)
        +0x18  payload

The client IGNORES the digest on receive (the memcmp result is discarded at
0x00857288), but it DOES compute a correct one when sending -- which is what lets
us brute-force the 4-byte key from the very first frame with certainty.
"""
import argparse
import binascii
import hashlib
import json
import os
import select
import socket
import math
import struct
import sys
import threading
import time

HDR = 24
MAX_PAYLOAD = 0x400

# Response opcodes recovered from the client's sub-state-1 compares.
# See docs/protocol.md, "Message grouping".
OPCODES = {
    0x2002: 'SvrList', 0x2003: 'SvrList', 0x2004: 'SvrList',
    0x2007: 'SvrTime',
    0x2009: 'SvrInfo', 0x200a: 'SvrInfo', 0x200b: 'SvrInfo',
    0x3002: 'Connect{Account,Lobby}Server', 0x3004: 'Connect{Account,Lobby}Server',
    0x3012: 'GetPlayerFileList', 0x3022: 'NewCreatePlayerFile', 0x3032: 'DeletePlayerFile',
    # SuperNOVA-only, from the 0x00272310 dispatch. Names are structural
    # (BEGIN/DATA/END), not Konami's -- SuperNOVA has no NetPrg* table.
    0x3121: 'SN-3120 BEGIN', 0x3122: 'SN-3120 DATA', 0x3123: 'SN-3120 END',
    0x3911: 'SN-3910', 0x3921: 'SN-3920',
    0x4101: 'SelectPlayerFile', 0x4103: 'GetPlayerInfo',
    0x4105: 'GetPlayerOption', 0x4107: 'SavePlayerOption',
    0x4109: 'GetPlyerHtoHLog', 0x4110: 'GetPlyerHtoHLog', 0x4111: 'GetPlyerHtoHLog',
    0x4113: 'GetPlyerPointLog', 0x4114: 'GetPlyerPointLog', 0x4115: 'GetPlyerPointLog',
    0x4117: 'GetPlyerRCLog', 0x4118: 'GetPlyerRCLog', 0x4119: 'GetPlyerRCLog',
    0x411b: 'SetMyAddr',
    0x4201: 'GetBlockList', 0x4203: 'EntryBlock',
    0x4211: 'GetPlayerList', 0x4212: 'GetPlayerList', 0x4213: 'GetPlayerList',
    0x4301: 'GetRoomList', 0x4310: 'GetRoomList', 0x4311: 'GetRoomList',
    0x4331: 'CreateRoom', 0x4341: 'OutRoom',
    0x4400: 'PEER-CHANNEL (relayed both ways)',
    0x44b0: 'MATCH/opponent record (server push)',
    0x4411: 'GetStartStaus',   # request 0x4410 carries a 1-byte body, observed 01
    0x4412: 'PLAY START gate (server push, u8 -> netwk+0x8d4)',
    0x4500: 'server push -- float into ctx+0x2b90c',
    0x4411: 'GetStartStaus', 0x441e: 'GetRuleMask',
    0x4431: 'GetEndgame', 0x4441: 'Confiscate',
    0x5001: 'GetRCInfo', 0x5003: 'GetRCTrycount', 0x5005: 'GetRCEntry',
    0x5007: 'GetRCRegist', 0x5010: 'GetRCIdList', 0x5012: 'GetSchedule',
    0x5013: 'WEEK ROLLOVER (server push, u8 -> ctx+0x2a383)',
    0x6001: 'Ranking', 0x6002: 'Ranking', 0x6003: 'Ranking',
}


# request opcode -> the response opcodes to send, TERMINATOR LAST.
#
# The last opcode of a group completes the RPC; the earlier ones only reset the
# client's timeout and keep it waiting. From decompiling NetPrgSvrInfo
# (0x001e4620) sub-state 1:
#
#     if (opcode == 0x200b) { done = true; return 1; }   // terminator
#     else if (opcode == 0x200a || opcode == 0x2009)
#         timeout_counter = 0;                           // reset, keep waiting
#
# Observed live: answering 0x2008 with only 0x2009 left the client holding the
# connection open forever -- timer reset, waiting on a part that never came.
#
# REQUEST opcodes are NOT derivable from the response opcodes. `0x5009 -> 0x5010`
# and `0x2005 -> 0x2002..0x2004` both break any +1 rule, and 0x2005 was seen live
# after a "+1" guess sent the wrong reply. They are extracted from the binary by
# `tools/reqmap.py`: each RPC's send path is a 2-instruction thunk in DATA07,
# `j 0x0085b7a0` with `addiu $a1,$zero,<opcode>` in the delay slot.
#
# BUT the thunk scan only finds the 15 EMPTY-BODY requests. Any request that
# carries a payload is built inline instead, and those were missing from this
# table entirely -- including 0x3020, where the +1 guess (0x3021) is WRONG and
# would have hung new-player-file creation. The complete inventory is every
# caller of the set-opcode primitive `0x00856b30(buf, opcode)` in DATA07: 22 of
# them, listed below. Anything still answered by the +1 guess has simply not
# been seen on the wire yet -- check it against that scan before trusting it.
REQUEST_RESPONSES = {
    0x2005: (0x2002, 0x2003, 0x2004),   # SvrList
    0x2006: (0x2007,),                  # SvrTime
    0x2008: (0x2009, 0x200a, 0x200b),   # SvrInfo
    # 0x3002 ONLY, not (0x3002, 0x3004). NetPrgConnectAccountServer waits for
    # them in SEPARATE sub-states -- one checks netwk+0x8d8 == 0x3002, a later
    # one checks == 0x3004 -- and the receive handler OVERWRITES 0x8d8 with the
    # newest opcode. Sending both back to back would let 0x3004 clobber 0x3002
    # before the client ever saw it. The second exchange has its own request,
    # which we learn from the log the first time it is sent.
    0x3001: (0x3002,),                  # Connect{Account,Lobby}Server, step 1
    # Step 2, observed live 2026-08-27: a 48-byte body, three of whose six
    # 8-byte blocks are byte-identical -- an 8-byte block cipher in ECB over a
    # mostly-empty credential struct. Answered with 0x3004 and the client
    # proceeded, so an empty acceptance is enough for now.
    0x3003: (0x3004,),                  # Connect{Account,Lobby}Server, step 2
    0x3010: (0x3012,),                  # GetPlayerFileList
    0x3020: (0x3022,),                  # NewCreatePlayerFile  -- NOT 0x3021
    0x3030: (0x3032,),                  # DeletePlayerFile     -- NOT 0x3031

    # --- SuperNOVA-only. Extreme 2 never sends these. -----------------------
    #
    # Recovered from SuperNOVA's SECOND parse dispatch, the compare chain at
    # 0x00272310 keyed on ctx+0x15c0, which also carries 0x3004/0x3012/0x3022/
    # 0x3032/0x0004. Each parser validates TWO things -- its own opcode, and the
    # opcode of the request still in flight at ctx+0x2364+0xc -- so the pairing
    # is read straight out of the binary rather than guessed:
    #
    #     0x272c90 (0x3121): checks 0x3121, then request == 0x3120
    #     0x272b50 (0x3122): checks 0x3122, then request == 0x3120
    #     0x272ae0 (0x3123): checks 0x3123, then request == 0x3120
    #     0x272da0 (0x3911): request == 0x3910
    #     0x272960 (0x3921): request == 0x3920
    #
    # The same scan independently reproduces the two documented +1 exceptions
    # (0x3020->0x3022 at 0x2730c0, 0x3030->0x3032 at 0x272fb0), which is what
    # makes it trustworthy here.
    #
    # 0x3120 is a three-part list like SvrInfo/SvrList. Its 0x3122 record is
    # 592 bytes (the parser computes n*592 off the count at ctx+0x9f48) and is
    # not decoded yet, so we send BEGIN + TERMINATOR only -- an empty list. A
    # zero-length 0x3122 would be worse than none: the parser would read fields
    # off the end of an empty message.
    # 0x3122 is included now; payload_for returns an EMPTY LIST for it when
    # there is no news, which sends no frame for that part at all. A
    # zero-length 0x3122 would be worse than none -- see the news block.
    0x3120: (0x3121, 0x3122, 0x3123),   # SuperNOVA -- the news feed
    0x3910: (0x3911,),                  # SuperNOVA
    0x3920: (0x3921,),                  # SuperNOVA
    0x4100: (0x4101,),                  # SelectPlayerFile
    0x4102: (0x4103,),                  # GetPlayerInfo
    0x4104: (0x4105,),                  # GetPlayerOption
    0x4106: (0x4107,),                  # SavePlayerOption
    0x411a: (0x411b,),                  # SetMyAddr
    0x4202: (0x4203,),                  # EntryBlock
    0x4330: (0x4331,),                  # CreateRoom
    0x4410: (0x4411,),                  # GetStartStaus
    0x4430: (0x4431,),                  # GetEndgame
    0x4440: (0x4441,),                  # Confiscate
    0x5000: (0x5001,),                  # GetRCInfo
    0x5002: (0x5003,),                  # GetRCTrycount
    0x5004: (0x5005,),                  # GetRCEntry
    0x5006: (0x5007,),                  # GetRCRegist
    0x6000: (0x6001, 0x6002, 0x6003),   # Get{HtoH,Point,RC}Ranking
    0x4108: (0x4109, 0x4110, 0x4111),   # GetPlyerHtoHLog
    0x4112: (0x4113, 0x4114, 0x4115),   # GetPlyerPointLog
    0x4116: (0x4117, 0x4118, 0x4119),   # GetPlyerRCLog
    0x4200: (0x4201,),                  # GetBlockList
    0x4210: (0x4211, 0x4212, 0x4213),   # GetPlayerList
    0x4300: (0x4301, 0x4310, 0x4311),   # GetRoomList
    0x4340: (0x4341,),                  # OutRoom
    0x441d: (0x441e,),                  # GetRuleMask
    0x5009: (0x5010,),                  # GetRCIdList
    0x5011: (0x5012,),                  # GetSchedule
}


def svrinfo_record(ident, type_, users, addr, name, extra=''):
    """One SvrInfo server record, as the 0x200a payload.

    Decompiled from the record parser at 0x008588f0, which stores into a
    604-byte (0x25c) struct at `ctx+0x490C + count*0x25c` and then increments the
    count at ctx+0x4908. Field sizes below sum to exactly 0x25c in memory; on the
    WIRE the two char arrays are FIXED-width (0x856490 memcpy's exactly n bytes
    and NUL-terminates at dst[n] -- there is no length prefix), and the last
    field is NUL-terminated variable length (0x856410 with delimiter 0, which
    also consumes the terminator).

        u32 BE   0x856510   -> struct +0x00
        u8       0x8567a0   -> struct +0x04
        u8       0x8567a0   -> struct +0x05
        19 bytes 0x856490   -> struct +0x06  (20-byte field, NUL added)
        64 bytes 0x856490   -> struct +0x1a  (65-byte field, NUL added)
        cstring  0x856410   -> struct +0x5b  (513-byte field)

    Minimum wire size 4+1+1+19+64+1 = 90 bytes.

    UNVERIFIED: which numeric field is which. The client's debug format is
    "addr:%s, name:%s, id:%d, type:%d, port:%d, user:%d" -- two strings, which
    line up with the 19- and 64-byte fields, but FOUR numbers against only three
    numeric fields (u32, u8, u8). So one of id/type/port/user is not in this
    record, or the u32 packs two of them. Treat the names here as a hypothesis
    to be confirmed by what the client actually dials.
    """
    a = addr.encode('ascii', 'replace')[:19].ljust(19, b'\x00')
    n = name.encode('ascii', 'replace')[:64].ljust(64, b'\x00')
    return (struct.pack('>I', ident)
            + bytes([type_ & 0xff, users & 0xff])
            + a + n
            + extra.encode('ascii', 'replace') + b'\x00')


def live_users():
    """Players currently in the lobby, for the SvrList user count.

    This is a GATE-PHASE snapshot: the SvrList is fetched once, before the
    client logs in, so the number a player sees on the server-select screen is
    the population at the moment they connected and does not update while they
    sit there. That is inherent to where the field lives, not a limitation of
    the count.
    """
    with WAITING_LOCK:
        return min(len(LOBBY), 0xffff)


def svrlist_entry(n0, type_, label, host, port, b, c):
    """One SvrList entry, as (part of) the 0x2003 payload.

    From the parser at 0x00858aa0. Entries live in the CLIENT CONTEXT at
    `ctx+0x124 + i*0x30` (the count is the word just before, at `ctx+0x120`),
    and the WIRE order is the parser's call order, which is NOT the struct
    order:

        0x8563d0                     "more data?" -- -1 once the cursor reaches
                                     the payload length, so MANY entries pack
                                     into one message and it parses until spent
        0x8565f0 u32 BE   -> +0x00
        0x8565f0 u32 BE   -> +0x04   TYPE  (and the connection slot index)
        0x856490 16 bytes -> +0x0e   label, fixed width
        0x856490 15 bytes -> +0x1f   HOST  -- the string the client DIALS
        0x8566c0 u16 BE   -> +0x0a   PORT  -- the port the client DIALS
        0x856710 u16 BE   -> +0x08   **USER COUNT** -- the population shown on
                                     the server-select screen as "DDR 0000/1000"
        0x8566c0 u16 BE   -> +0x0c   still unidentified

    Wire size = 4+4+16+15+2+2+2 = 45 bytes. Max 200 entries.

    HOST and PORT are SETTLED, from `0x00858870(ctx, index, timeout)` -- the
    routine every downstream connect goes through:

        e = ctx + index*0x30
        return 0x00858510(e + 0x143,            // host string  = entry+0x1f
                          *(u16 *)(e + 0x12e),  // port         = entry+0x0a
                          ctx + *(int *)(e + 0x128) * 0x20)   // slot = TYPE

    and 0x00858510 is the socket()/connect() primitive. So this list -- not the
    hardcoded gate address -- is what points the client at every server after
    the gate.

    TYPE does double duty: it selects the entry (0x0085b990 scans for a
    requested type; ConnectAccountServer asks for 1) AND it indexes the 4-slot
    connection table as `ctx + type*0x20`. The gate itself is slot 0, so an
    account server must be TYPE 1 and a lobby server TYPE 2. **Keep TYPE <= 3**:
    the lookup range-checks 0..4, but there are only four slots, so a type-4
    entry that anything actually dialled would scribble past them.

    Still UNVERIFIED: +0x00, +0x08 and +0x0c. The debug format is
    "addr:%s, name:%s, id:%d, type:%d, port:%d, user:%d", so they are most
    likely id and user count, but nothing depends on them yet.
    """
    lb = label.encode('ascii', 'replace')[:16].ljust(16, b'\x00')
    hs = host.encode('ascii', 'replace')[:15].ljust(15, b'\x00')
    return (struct.pack('>II', n0, type_) + lb + hs
            + struct.pack('>HHH', port, b, c))


# WRONG EARLIER: 0x0003 is NOT a goodbye. It looked like one because it is the
# last frame of the gate phase -- but on the ACCOUNT connection it is the FIRST
# frame the client sends (serial 1), and leaving it unanswered made the client
# hang up immediately. It is a request, and it needs a reply.
#
# 0x0004 and 0x0005 are both real entries in the dispatch at 0x0085c3c0:
#   0x0004 -> 0x859790(ctx+0x4900)   parser
#   0x0005 -> (no parser)            terminator, same shape as 0x200b / 0x2004
# 0x0003 is the GOODBYE. Settled from the binary, after I twice guessed wrong:
# 0x00858490 builds a message with opcode 3, sends it, then calls 0x008541b0
# (close socket) -- and it is called from 0x008582ec, inside the disconnect
# routine 0x008582a0. It is emitted by the teardown path, not a greeting.
#
# So seeing 0x0003 as the FIRST frame on a connection does not mean "hello", it
# means the client connected and immediately tore the connection down.
# 0x4400 is the PEER CHANNEL, not an RPC. The client BUILDS it at 0x0085a6b0
# (opcode 0x4400, sent on slot 2 = the lobby TCP connection) and receives it
# through the same opcode. Answering it with a +1 guess would be nonsense; the
# server's job is to RELAY it to the paired opponent, which on_frame does.
NO_REPLY = {0x0003, 0x4400}

# Requests we knowingly answer with the +1 guess, so the warning stays quiet.
# 0x0005 is the keepalive: both slot dispatchers special-case a RECEIVED 5 and
# return without parsing, so no reply is needed at all and the 0x0006 we send
# is an invented opcode the client demonstrably ignores (three full matches,
# 2026-08-27). Harmless, but it is made up -- if it ever needs to go, the fix
# is to add 0x0005 to NO_REPLY, not to invent a body for 0x0006.
QUIET_GUESS = {0x0005}


# SuperNOVA-only overrides, applied when Session.is_sn. Derived the same way as
# everything else here: each parser validates the opcode of the request still in
# flight at ctx+0x2364+0xc, so the grouping is read out of the binary.
#
# GetBlockList is a THREE-part reply in SuperNOVA and a one-part reply in
# Extreme 2. 0x270fb0 (0x4204) and 0x270e30 (0x4205) both check request ==
# 0x4200; 0x4204 sets flags |= 2 and reads a u32 status via 0x271530, and 0x4205
# sets flags |= 0xe with no payload -- so 0x4204 is BEGIN and 0x4205 is END,
# with 0x4201 the data record between them. Sending 0x4201 alone leaves the
# client waiting on a terminator that never comes.
REQUEST_RESPONSES_SN = {
    0x4200: (0x4204, 0x4201, 0x4205),   # GetBlockList -- BEGIN, DATA, END
    # Two more three-part groups in an opcode family Extreme 2 does not have at
    # all. BEGIN/DATA/END told apart by the flag each parser sets, the same way
    # 0x2002/0x2004 and 0x4204/0x4205 are: BEGIN |= 2, END |= 0xe.
    #   0x8005 0x0026b3e0  flags 2     u32 status
    #   0x8006 0x0026b2b0  --          loop: s32 + fixed string
    #   0x8007 0x0026b210  flags 0xe   u32 status   <- unlike 0x4205, END has a body
    #   0x8001 0x0026b790  flags 2     u32 status
    #   0x8002 0x0026b5a0  --          loop: s32, 5x u8, s32  (13 bytes;
    #                                  see SN_SONG_* below, which is right)
    #   0x8003 0x0026b500  flags 0xe   u32 status
    # Both DATA parsers lead with the "anything left?" probe 0x279a60 (-1 when
    # spent), so an EMPTY body is a well-formed empty list here -- unlike the
    # SvrList BEGIN, which reads unconditionally and treats short as an error.
    0x8004: (0x8005, 0x8006, 0x8007),
    0x8000: (0x8001, 0x8002, 0x8003),
    # Two more, same BEGIN/DATA/END shape but the BEGIN body is EIGHT bytes,
    # not four -- do not assume the pattern holds:
    #   0x7001 0x0026cbb0  u32 status + s32 -> ctx+0x303c   flags |= 2 ONLY if
    #                      the status is 0 (beql at 0x0026cc38)
    #   0x7002 0x0026caf0  loop: string
    #   0x7003 0x0026ca70  u32 status                        flags |= 0xe
    #   0x7011 0x0026c8b0  u32 status + s32, s32 CLAMPED to 0x2800 -- a count
    #   0x7012 0x0026c720  loop: string
    #   0x7013 0x0026c6a0  u32 status                        flags |= 0xe
    0x7000: (0x7001, 0x7002, 0x7003),
    0x7010: (0x7011, 0x7012, 0x7013),
    # Ranking Challenge. Same three-part shape; the roles come from the flag each
    # parser sets, since these three do not compare the in-flight request the way
    # the others do (so tools/sndispmap.py lists them under "no in-flight check").
    #   0x5031 0x00269680 flags 2    u32 status
    #   0x5032 0x00269550 --         loop: s32, string, s32, s32, s32
    #   0x5033 0x00269500 flags 0xe  empty
    0x5030: (0x5031, 0x5032, 0x5033),
    0x5034: (0x5035, 0x5036, 0x5037),
    # Room setup. SuperNOVA is room-oriented where Extreme 2 is player-oriented:
    # players create rooms with a 4-digit PIN, a song and a difficulty, and the
    # per-setting toggles are their own RPCs. Observed live:
    #   0x4392 len 2 -> song id (u16)
    #   0x4394 len 1 -> difficulty (u8)
    # Both answers are ENDs that read a u32 status (0x0026d6e0, 0x0026d530).
    # Answering them empty is a short read, so the client re-sends the toggle --
    # which looks like the player spamming the button but is the server failing
    # to acknowledge.
    0x4392: (0x4393,),
    0x4394: (0x4395,),
    # Friend list. The +1 rule is wrong for every one of these -- there is no
    # 0x4521, 0x4524, 0x4527 or 0x452a in the dispatch at all. Each response is
    # an END that names its request at ctx+0x2364+0xc:
    #   0x4522 0x0026c1b0  req 0x4520  22B: u32 status, u8, char[17]
    #   0x4525 0x0026bf70  req 0x4523   4B: u32 status
    #   0x4528 0x0026bda0  req 0x4526  22B: u32 status, u8, char[17]
    #   0x452b 0x0026bb60  req 0x4529   4B: u32 status
    #
    # Each of those four parsers accepts TWO in-flight requests, not one. The
    # compare chain in 0x0026c1b0 is
    #     lw    $v1, 0xc($s0)          ; the in-flight request
    #     addiu $v0, $zero, 0x4520 ; beq $v1,$v0, body
    #     addiu $v0, $zero, 0x4521 ; beq $v1,$v0, body
    # so 0x4521 is answered by the SAME 0x4522, and 0x4524 / 0x4527 / 0x452a by
    # 0x4525 / 0x4528 / 0x452b. tools/sndispmap.py stopped at the first compare
    # until 2026-09-13 and so reported these four requests as unanswered; the
    # +1 fallback happened to send the right opcode anyway, but with no body,
    # and 0x4522 / 0x4528 are 21-byte replies whose string read copies a fixed
    # 16 bytes regardless of payload length. Same failure as 0x3901: not a
    # rejection, a name made of whatever the message buffer last held.
    0x4520: (0x4522,),
    0x4521: (0x4522,),
    0x4523: (0x4525,),
    0x4524: (0x4525,),
    0x4526: (0x4528,),
    0x4527: (0x4528,),
    0x4529: (0x452b,),
    0x452a: (0x452b,),
    # THE FRIENDS LIST. Observed live 2026-08-28: opening it FROZE the game,
    # because 0x3080 was unmapped and the +1 fallback answered 0x3081 -- an
    # opcode with NO PARSER IN THE CLIENT AT ALL. The dispatcher drops it, the
    # completion flag is never set, and the RPC waits forever. This is the
    # documented multi-part trap in its worst form: not a short read, not an
    # error, a hang.
    #
    # The real group is 0x3082/0x3084/0x3086, and it is the reason
    # tools/sndispmap.py never found it: this family keeps its state in a
    # SECOND block at ctx+0x2c64 rather than ctx+0x2364, so its parsers neither
    # compare the in-flight request at ctx+0x2370 nor set flags in ctx+0x236c.
    # They flag ctx+0x2c6c instead -- 0x3082 |= 2 (BEGIN), 0x3086 |= 0xe (END).
    #   0x3082 0x0026c5a0  BEGIN  u32 status via 0x271530
    #   0x3084 0x0026c470  DATA   loop, max 0x28 = 40 records, 23 bytes each:
    #                             s32 id, char[16] name, u8, u8, u8
    #   0x3086 0x0026c420  END    no body at all
    0x3080: (0x3082, 0x3084, 0x3086),
    # 0x3900 -> 0x3901 ONLY (parser 0x0026b9a0, in-flight check 0x3900). A
    # single END whose body is u32 status + a fixed 32-byte string written to
    # the pointer the request builder parked at ctx+0x2374. Served empty it was
    # a short read; the parser copies 32 bytes regardless of the payload length,
    # so the name came from whatever was left in the message buffer.
    0x3900: (0x3901,),
    # 0x3006 -> 0x3007 ONLY (parser 0x0026e240). END, bare u32 status. The +1
    # fallback happened to pick the right opcode here, but still sent no body.
    0x3006: (0x3007,),
    # Chat. 0x4513 has NO in-flight request check, so it is a server PUSH -- it
    # is what the server sends to everyone in the room, and answering 0x4511
    # with it echoes the sender their own line. See CHAT_* below.
    0x4511: (0x4513,),
    # 0x4512 is the WHISPER -- a DIFFERENT body from 0x4511, addressed by
    # name. It was unmapped, so the +1 fallback answered it correctly by
    # luck while the body parser skipped it and the text was lost.
    0x4512: (0x4513,),

    # --- recovered 2026-09-13 by tools/snblocks.py, which groups parsers by
    # the STATE BLOCK they drive instead of by the in-flight request compare.
    #
    # 0x5040 IS THE SAME BUG AS THE FRIENDS LIST, still armed. Its three
    # parsers share ctx+0x13038 -- 0x5041 BEGIN (writes +0x08), 0x5042 DATA
    # (writes +0x14), 0x5043 END (writes +0x04/+0x08/+0x10) -- exactly the
    # shape of 0x5030 on ctx+0x13cd0 and 0x5034 on ctx+0x13f40, both of which
    # this table already gets right. None of the three compares the in-flight
    # request, so sndispmap.py never grouped them and 0x5040 fell through to
    # the +1 fallback, which sends 0x5041 ALONE: a BEGIN with no terminator.
    # That is the friends-list freeze exactly -- the RPC's completion flag is
    # never set and the client waits forever. Untested on the client; the
    # grouping is from the binary.
    0x5040: (0x5041, 0x5042, 0x5043),
    # Single ENDs that name their request at ctx+0x2364+0xc, so these are read
    # out of the binary rather than guessed. The +1 rule is right for all four,
    # but the fallback sends them EMPTY, and only 0x4231 tolerates that:
    #   0x0007 0x0026e360  2B   u16 BE
    #   0x4231 0x0026b8b0  4B   u32
    #   0x4324 0x0026fb10  55B  u32, s32, char[16], u8, 5x s32, u8, s32,
    #                            u16, u8, u16
    #   0x5021 0x00269b40  16B  u32, 3x s32
    0x0006: (0x0007,),
    0x4230: (0x4231,),
    0x4323: (0x4324,),
    0x5020: (0x5021,),

    # --- the head-to-head search path, from a live trace 2026-09-13 ----------
    #
    # SuperNOVA does NOT matchmake by advertising a room the way Extreme 2
    # does. Watching both clients search, the sequence is:
    #
    #     0x4a00  len 10   "I am available"  -- body is s32 OWN PLAYER ID then
    #                                          six zero bytes. Two clients sent
    #                                          9 and 11, each its own id.
    #     0x4a02  len 0
    #     0x4300  GetRoomList
    #     0x4210  GetPlayerList  -> and the player list is the screen you pick
    #                               an opponent from
    #
    # so the browse is the matchmaking, and the server's job is to populate the
    # lists rather than to push at a waiting client. Both acks are bare
    # statuses (SN_STATUS_ONLY); neither was mapped, so both were being served
    # empty -- a short read of the status word.
    # 0x4b00 asks WHERE THE OPPONENT IS -- s32 target id in, the endpoint
    # pair back. Unmapped until 2026-09-13, so it fell through to the +1
    # fallback with no body and the two clients never found each other.
    0x4b00: (0x4b01,),
    # The IN-MATCH handshake. All three were unmapped, so every one of them
    # reached the client through the +1 fallback with NO BODY -- and each
    # reply is a status word the client then acts on, read out of whatever
    # the message buffer last held. 0x4413 in particular is sent by both
    # sides the moment the match starts (body 02, observed 2026-09-14) and
    # its reply sets ctx+0x142fc, the most widely consumed flag in the
    # whole context -- six readers in netlby_mas4.
    0x4413: (0x4414,),
    0x4416: (0x4417,),
    0x4432: (0x4433,),
    0x4a00: (0x4a01,),
    0x4a02: (0x4a03,),
}

# Responses whose body is a bare u32 BE status, read by 0x00271530 into
# ctx+0x2350 (via 0x279c70). A zero-length body is a SHORT READ here, not an
# empty message.
SN_STATUS_ONLY = (0x3121, 0x4204, 0x8001, 0x8003, 0x8005, 0x8007,
                  0x7003, 0x7013, 0x5031, 0x5035,
                  # room family -- all ENDs reading a bare u32 status
                  0x4393, 0x4395, 0x4341, 0x4343, 0x4381, 0x4391, 0x4351,
                  0x4525, 0x452b, 0x4211,
                  # friends-list BEGIN, and the 0x3006 acknowledgement
                  0x3082, 0x3007,
                  # the 0x5040 group, recovered 2026-09-13. Note the END here
                  # carries a status where 0x5033 and 0x5037 -- the same shape
                  # of group -- have no body at all. Check each one.
                  0x5041, 0x5043,
                  # 0x4231. Its parser reads the word with 0x279c70 directly
                  # rather than through 0x271530, so it does not land in
                  # ctx+0x2350; four zero bytes are still what it wants.
                  0x4231,
                  # OBSERVED SHORT 2026-09-13, all three on the head-to-head
                  # search path, all three answered with a zero-length body:
                  #   0x4301  GetRoomList BEGIN, parser 0x00270620
                  #   0x4a01  the 0x4a00 "I am available" ack, 0x0026d200
                  #   0x4a03  the 0x4a02 ack, 0x0026d100
                  # Every one reads a STATUS(u32) through 0x271530, and a short
                  # read there is silent -- the status comes from whatever the
                  # message buffer last held, so a stale non-zero word reads as
                  # a failed request.
                  0x4301, 0x4a01, 0x4a03,
                  # the in-match handshake, all bare statuses
                  0x4414, 0x4417, 0x4433)

# BEGINs whose body is u32 status + s32 count (8 bytes), not a bare status.
# BEGINs/ENDs whose body is u32 status + s32 (8 bytes), not a bare status.
# 0x4331 CreateRoom is SuperNOVA-only in this shape: Extreme 2 answers it
# empty and matchmakes through 0x44b0 instead, so this is gated on is_sn.
# The s32 is presumed to be the room id.
SN_STATUS_COUNT = (0x7001, 0x7011, 0x4331)


def response_sequence(request_opcode, is_sn=False):
    """Opcodes to send in reply to `request_opcode`, terminator last.

    Unknown requests fall back to +1 -- a guess, logged as such by the caller,
    and only correct by luck. Prefer adding the real mapping from reqmap.py.
    """
    if is_sn:
        seq = REQUEST_RESPONSES_SN.get(request_opcode)
        if seq:
            return (seq, True)
    seq = REQUEST_RESPONSES.get(request_opcode)
    return (seq, True) if seq else ((request_opcode + 1,), False)


def name_of(op):
    if op in OPCODES:
        return OPCODES[op]
    # requests are (probably) response - 1; unverified, see docs/protocol.md
    if op + 1 in OPCODES:
        return 'req->' + OPCODES[op + 1]
    return '?'


def xor(buf, key, start=0):
    return bytes(b ^ key[(start + i) & 3] for i, b in enumerate(buf))


def hexdump(b, indent='      '):
    out = []
    for off in range(0, len(b), 16):
        chunk = b[off:off + 16]
        hx = ' '.join('%02x' % c for c in chunk)
        asc = ''.join(chr(c) if 0x20 <= c < 0x7f else '.' for c in chunk)
        out.append('%s%04x  %-47s  %s' % (indent, off, hx, asc))
    return '\n'.join(out)


def digest(plain_hdr8, payload):
    return hashlib.md5(plain_hdr8 + payload).digest()


def recover_key(buf):
    """Brute-force the 4-byte XOR key from one complete client frame.

    key[0:2] falls out of a guessed opcode; key[2:4] out of the length, which we
    already know (len(buf) - 24). MD5 then confirms the guess. 65536 candidates,
    every one cryptographically verified -- no false positives in practice.
    """
    if len(buf) < HDR:
        return None
    for length in (len(buf) - HDR, 0):
        if not (0 <= length <= MAX_PAYLOAD) or len(buf) < HDR + length:
            continue
        for opcode in range(0x10000):
            key = bytes([buf[0] ^ (opcode >> 8),
                         buf[1] ^ (opcode & 0xff),
                         buf[2] ^ ((length >> 8) & 0xff),
                         buf[3] ^ (length & 0xff)])
            plain = xor(buf[:HDR + length], key)
            if digest(plain[0:8], plain[HDR:HDR + length]) == plain[8:HDR]:
                return key
    return None


def build(opcode, serial, payload, key):
    hdr8 = struct.pack('>HHI', opcode, len(payload), serial)
    return xor(hdr8 + digest(hdr8, payload) + payload, key)


# ── PLAYER FILE STORE ────────────────────────────────────────────────────────
# The client asks for its player files (0x3010) on every login and creates one
# (0x3020) when the list comes back empty. Without persistence it re-creates the
# same dancer every session, so keep the two slots on disk next to the XOR key.
# One global account for now: nothing in the protocol has identified the player
# yet -- the 0x3003 credential blob is still opaque.
# Keyed by the 0x3003 credential blob, hex -- the only per-account identity the
# protocol exposes. Both the account AND the lobby connection send 0x3003, so
# the same key is available wherever player files are touched. Two clients
# sharing a memory card image will produce the SAME blob and collapse into one
# account; the log prints the blob so that is visible rather than mysterious.
# Live lobby connections that have created a room and not yet left it. The
# matchmaking UI has no create-vs-join choice: BOTH clients advertise and wait,
# so pairing is the server's job -- nothing in the client will ever browse.
WAITING_LOCK = threading.Lock()
RELAY = None                       # udprelay.Relay, when --udp-relay is on
PUBLIC = None                      # publicaddr.PublicAddress, set in main()
WAITING = []                       # of Session, advertising a room
LOBBY = []                         # of Session, has selected a player file

STATE_LOCK = threading.Lock()
STATE = {'accounts': {}, 'next_id': 1}
STATE_PATH = None
ANON = 'anonymous'


def alloc_id():
    """A GLOBALLY unique player id. Caller holds STATE_LOCK.

    It cannot be derived from the slot. Two accounts each with one player file
    in slot 0 both used to get id 1, which is fine for 0x4101 (the client only
    checks the echo against what it was told) but breaks the moment the server
    has to tell one player about another -- matchmaking, room lists, the
    0x4400 push. Observed live 2026-08-27 with two clients: accounts
    589d06c1... and d2598cc7... both held id 1.
    """
    STATE['next_id'] = STATE.get('next_id', 1) + 1
    return STATE['next_id'] - 1


def account(key):
    """The player-file list for one credential blob. Caller holds STATE_LOCK."""
    return STATE['accounts'].setdefault(key or ANON, {'player_files': []})


# ── FRIENDS (SuperNOVA) ──────────────────────────────────────────────────────
#
# Kept as STATE['friends'], a map of player id -> {other id: state}, saved with
# everything else. Player ids are already globally unique (see alloc_id), so an
# id is a usable key across accounts.
#
# THE FOUR OPERATIONS COME IN PAIRS -- one addressed by ID, one by NAME -- and
# each pair shares a response. That is read straight out of the builders, and it
# is also why those response parsers accept two in-flight requests:
#
#   0x4520 s32 / 0x4521 char[16]  -> 0x4522  (u32 status, u8, char[16])
#   0x4523 s32 / 0x4524 char[16]  -> 0x4525  (u32 status)
#   0x4526 s32 / 0x4527 char[16]  -> 0x4528  (u32 status, u8, char[16])
#   0x4529 s32 / 0x452a char[16]  -> 0x452b  (u32 status)
#
# **THERE IS NO REQUEST/APPROVE FLOW. There are two lists.** Settled by
# correlation against the UI on 2026-09-13, which also corrected a wrong guess:
#
#   aaa "sends a friend request" to qq   ->  0x4520, target id
#   qq deletes aaa from its IGNORE list  ->  0x4529, target id
#
# The second is the tell: the entry appeared under IGNORE, so a trailing byte
# selects the list and the whole model of pending/accepted was wrong.
#
# WHICH byte took two wrong guesses and then a probe. Byte 0 was blamed first
# at 1 and then at 0, and the entry landed under Ignore both times. Serving
# twelve synthetic records at once -- one per combination, each named after its
# own bytes -- settled it in a single pass: **byte 1 is the list** and byte 2
# is the online marker, so writing "online" into byte 1 had been filing every
# friend added by a connected player under Ignore.
#
# What the four pairs actually are is then forced by the reply shapes: the two
# that echo a name back (0x4522, 0x4528) are the two ADDs, and the two bare
# statuses (0x4525, 0x452b) are the two REMOVEs. Two lists times add/remove:
#
#   0x4520 / 0x4521  ->  add to FRIENDS       (confirmed)
#   0x4523 / 0x4524  ->  remove from FRIENDS  (inferred from the symmetry)
#   0x4526 / 0x4527  ->  add to IGNORE        (inferred)
#   0x4529 / 0x452a  ->  remove from IGNORE   (confirmed)
#
# Both lists are ONE-DIRECTIONAL -- a personal bookmark and a personal block
# list. That is also why the protocol has no "incoming friend request" push
# anywhere: nothing needs to be delivered to the other player.
FRIEND_LIST = 'friend'      # entry byte 1 == 0
IGNORE_LIST = 'ignore'      # entry byte 1 == 1
LIST_BYTE = {FRIEND_LIST: 0, IGNORE_LIST: 1}


def online_ids():
    """Player ids with a live SuperNOVA lobby connection. Caller must NOT hold
    WAITING_LOCK."""
    with WAITING_LOCK:
        return {(w.player or {}).get('id') for w in LOBBY if w.is_sn}


def friends_of(pid):
    """The friend map for one player id. Caller holds STATE_LOCK."""
    return STATE.setdefault('friends', {}).setdefault(str(pid), {})


def find_player(pid=None, name=None):
    """Look a player file up across every account. Caller holds STATE_LOCK."""
    for acct in STATE['accounts'].values():
        for f in acct.get('player_files', []):
            if pid is not None and f.get('id') == pid:
                return f
            if name is not None and f.get('name') == name:
                return f
    return None


def friend_add(a_id, b_id, which):
    """Put b on a's list. ONE-DIRECTIONAL. Caller holds STATE_LOCK."""
    friends_of(a_id)[str(b_id)] = which


def friend_remove(a_id, b_id, which=None):
    """Take b off a's list. Caller holds STATE_LOCK.

    `which` restricts the removal to one list, so removing from IGNORE cannot
    silently drop a friend of the same name.
    """
    have = friends_of(a_id).get(str(b_id))
    if have is not None and (which is None or have == which):
        friends_of(a_id).pop(str(b_id), None)


def friend_probe_body():
    """Synthetic 0x3084 records that spell out their own bytes.

    Two runs have now put an added friend on the IGNORE list -- first with
    byte 0 = 1, then with byte 0 = 0 -- so byte 0 is not the discriminator and
    guessing one byte at a time is too slow. This serves one record per
    combination with the values encoded in the NAME, so a single look at the
    Friends screen and the Ignore screen maps all three bytes at once.

    A record named "F-102" carries byte0=1, byte1=0, byte2=2. Whichever names
    appear under Friends have the friend encoding; whichever appear under
    Ignore have the ignore encoding; any that appear on neither screen are
    rejected outright, which is itself worth knowing.
    """
    out = b''
    ident = 9000
    for b0 in (0, 1, 2):
        for b1 in (0, 1):
            for b2 in (0, 1):
                nm = ('F-%d%d%d' % (b0, b1, b2)).encode('ascii')
                out += (struct.pack('>i', ident) + nm.ljust(16, bytes(1))
                        + bytes([b0, b1, b2]))
                ident += 1
    return out


def friendlist_body(pid, online_ids=(), force=None, probe=False):
    """The `0x3084` DATA records -- 23 bytes each, at most 40.

    Parser `0x0026c470`, writing into `ctx+0x2c64 + n*24 + 0x18`:

        s32 id / char[16] name / u8 / u8 / u8

    a 23-byte record in a 24-byte struct. The loop stops at 40 (`slti 0x28`) or
    when the payload runs out, whichever comes first.

    **The three trailing bytes are not identified.** They are served here as
    (relationship state, online, dancer) because those are the three things a
    friends list plausibly shows and each is independently visible on screen,
    but that is a guess -- `--friend-bytes` overrides all three with constants
    so a run through the UI can settle them the way `--stat-probe` settled the
    player record.
    """
    if probe:
        return friend_probe_body()
    out = b''
    with STATE_LOCK:
        rel = dict(friends_of(pid))
        for other, st in sorted(rel.items(), key=lambda kv: int(kv[0])):
            other_id = int(other)
            pf = find_player(pid=other_id)
            if pf is None:
                continue
            nm = pf.get('name', '').encode('ascii', 'replace')[:16]
            if force is not None:
                b0, b1, b2 = force
            else:
                # SETTLED by --friend-probe, 2026-09-13. Twelve synthetic
                # records went out, one per combination, each named after its
                # own bytes; exactly the six with BYTE 1 == 0 appeared, and
                # within those byte 2 drove the online/offline marker:
                #
                #   byte 0  no effect on which screen or on the marker
                #   byte 1  THE LIST -- 0 friends, 1 ignore
                #   byte 2  ONLINE -- 0 offline, 1 online
                #
                # This server had been putting *online* in byte 1, so every
                # friend added while both players were connected went straight
                # to the Ignore list. Two earlier guesses both blamed byte 0.
                b0 = 0
                b1 = LIST_BYTE.get(st, 0)
                b2 = 1 if other_id in online_ids else 0
            out += (struct.pack('>i', other_id) + nm.ljust(16, bytes(1))
                    + bytes([b0 & 0xff, b1 & 0xff, b2 & 0xff]))
            if len(out) >= 40 * 23:
                break
    return out


def state_load(path):
    global STATE_PATH
    STATE_PATH = path
    # The database lives beside the old state.json and imports it once if it is
    # still empty, so an existing server keeps its accounts. STATE_PATH stays
    # the state.json path: other code derives the state directory from it.
    db.setup(os.path.dirname(path) or '.')
    loaded = db.load_state()
    STATE.clear()
    STATE.update(loaded)
    STATE.setdefault('next_id', 1)
    dirty = False
    # MIGRATION: accounts used to be keyed on the WHOLE 48-byte 0x3003 blob,
    # which is not stable -- blocks 5 and 6 change every login, so every login
    # minted a fresh account and a fresh dancer. Only the FIRST 8 BYTES are
    # stable across sessions (see docs/protocol.md, "Known gaps"), and
    # that is what `acct` is now. Re-key anything still on the long form so the
    # player files already on disk survive the change instead of orphaning.
    longkeys = [k for k in STATE['accounts'] if k != ANON and len(k) > 16]
    for key in longkeys:
        acc = STATE['accounts'].pop(key)
        short = key[:16]
        tgt = STATE['accounts'].setdefault(short, {'player_files': []})
        # Several long keys collapsing to one short key is EXPECTED and is the
        # whole point -- they were always the same account, re-minted once per
        # login. Merge by player-file SLOT, keeping the HIGHEST id: ids come
        # from a monotonic counter, so the highest is the most recent, and the
        # player's latest name/dancer is the one they will expect to see.
        for f in acc['player_files']:
            same = [g for g in tgt['player_files']
                    if g.get('slot') == f.get('slot')]
            if not same:
                tgt['player_files'].append(f)
            elif f.get('id', 0) > same[0].get('id', 0):
                tgt['player_files'][tgt['player_files'].index(same[0])] = f
        dirty = True
    if longkeys:
        print('  migrated %d unstable account key(s) -> %d stable account(s)'
              % (len(longkeys), len({k[:16] for k in longkeys})))
    for acc in STATE['accounts'].values():
        for f in acc['player_files']:
            if 'id' not in f:
                f['id'] = alloc_id()
                dirty = True
    if dirty:
        state_save()
    print('loaded %d account(s), %d player file(s) from %s'
          % (len(STATE['accounts']),
             sum(len(a['player_files']) for a in STATE['accounts'].values()),
             os.path.join(os.path.dirname(path) or '.', 'ddr.db')),
          flush=True)


def state_save():
    """Persist accounts, player files and friends to the database.

    The account data is small and bounded, so the whole set is rewritten in one
    transaction; SQLite commits it atomically, so a crash mid-write cannot lose
    it. Callers hold STATE_LOCK, so the snapshot is consistent. Results are
    written incrementally elsewhere, never here.
    """
    if STATE_PATH is None:
        return
    try:
        db.save_state(STATE)
    except Exception as e:
        print('!! could not save state: %s' % e, flush=True)


def playerfile_list_sn(files, status=0):
    """SuperNOVA's 0x3012, from its OWN parser at 0x002731f0. It is NOT Extreme
    2's -- serving the Extreme 2 layout here is what made a created dancer fail
    to appear.

        u32 BE  -> ctx+0x2350      status for the whole reply (0 = OK)
        then, while (i < 2):
          u8      SLOT      -- also the index: entry = ctx+0xb684 + slot*36
          s32 BE  -> entry+0x18
          16 B    -> entry+0x1c    name, fixed width
          u8      -> entry+0x15    dancer/character id
          s32 BE  -> entry+0x30
          s32 BE  -> entry+0x34

    **30 bytes per entry, stride 36** -- against Extreme 2's 42 and 48. The
    wire order differs too: Extreme 2 has a u32 between the name and the dancer
    byte and three more u32s after it; SuperNOVA has neither. A 46-byte Extreme
    2 reply therefore leaves 12 bytes over, and the client reads a phantom
    second entry out of them. Same two-file hard limit.

    Fields are read with 0x279b90 (SIGNED s32 BE), not 0x279c70 (unsigned) as
    the SvrList uses.
    """
    out = struct.pack('>I', status & 0xffffffff)
    for f in files[:2]:
        nm = f['name'].encode('ascii', 'replace')[:16].ljust(16, bytes(1))
        out += (bytes([f['slot'] & 0xff])
                + struct.pack('>i', f.get('id', f['slot'] + 1))
                + nm
                + bytes([f.get('dancer', 0) & 0xff])
                + struct.pack('>ii', f.get('sn1c', 0), f.get('sn20', 0)))
    return out


def playerfile_list(files, status=0, probe=False):
    """The 0x3012 GetPlayerFileList payload, from the parser at 0x008573e0.

    Destination is `ctx+0x8fdc`, zeroed to 0x60 first = **exactly two** 0x30-byte
    entries, and the read loop is `while (i < 2)`. Two player files is a hard
    client-side limit, not a convention.

        u32 BE  -> ctx+0x4900      status for the whole reply (0 = OK)
        then, until the payload is spent (max 2):
          u8      -- SLOT INDEX; the parser uses it to pick which entry to fill
                     (`entry = base + slot*0x30`), so entries are addressed, not
                     ordered, and it also lands at entry+0x00
          u32 BE  -> entry+0x04
          16 B    -> entry+0x0c    name, fixed width
          u32 BE  -> entry+0x08
          u8      -> entry+0x1d    dancer/character id
          u32 BE  -> entry+0x20
          u32 BE  -> entry+0x24
          u32 BE  -> entry+0x2c
          u32 BE  -> entry+0x28    NB the last two are written OUT of address order

    42 bytes per entry. The name and dancer id are the two fields the client
    itself sent in 0x3020, which is what ties the two messages together.

    The five unidentified u32s (wire positions 4, 6, 7, 8, 9) drive the
    SELECT PROFILE screen -- POINTS / TIME / WIN / LOSS / DRAW. It was blank
    for exactly that reason: five blanks, five unknown u32s. Probed from a
    400+N band so they cannot be confused with any other record on screen.
    """
    out = struct.pack('>I', status & 0xffffffff)
    for f in files[:2]:
        nm = f['name'].encode('ascii', 'replace')[:16].ljust(16, bytes(1))

        def w(key, wire_n):
            return (400 + wire_n) if probe else f.get(key, 0)

        out += (bytes([f['slot'] & 0xff])
                + struct.pack('>I', f.get('id', f['slot'] + 1))
                + nm
                + struct.pack('>I', w('w08', 4))
                + bytes([f.get('dancer', 0) & 0xff])
                + struct.pack('>IIII', w('w20', 6), w('w24', 7),
                              w('w2c', 8), w('w28', 9)))
    return out


PROBE_SMALL = False    # set from --stat-probe-small; see probe_value()


def probe_value(n, size):
    """A sentinel whose own field number is readable on screen.

    Field 7 -> 777 (u32) / 77 (u16); field 14 -> 141414 / 1414. Every value is
    unique within a message, so one screenshot maps many fields at once. This is
    much cheaper than chasing each field through the UI code, and it is the only
    method that survives the client reformatting a value (a percentage, a
    thousands separator, a grade) -- the digits still say which field it was.
    """
    if PROBE_SMALL:
        # Second pass. Several displays are only four or five digits wide and
        # CLAMP: 0x4212 fields 11/16/18 all showed "99999" because 111111 /
        # 161616 / 181818 overflow the widget, which tells you nothing about
        # which field is which. 100+n is unique, three digits, and cannot clamp.
        return (100 + n) & (0xff if size == 1 else
                            0xffff if size == 2 else 0xffffffff)
    if size == 1:
        return n & 0xff
    s = str(n) * (2 if size == 2 else 3)
    return int(s) & (0xffff if size == 2 else 0xffffffff)


# ── 0x4212 GetPlayerList record ──────────────────────────────────────────────
# Parser 0x0085b240, destination ctx+0x9f00 (`ori $at,$zero,0x9f00` at
# 0x0085bd88), 80-byte stride, u16 running count at +0x00, hard cap 1000.
#
# (wire #, reader size, where it lands in the 80-byte record)
PLAYERLIST_FIELDS = [
    (1,  4, 0x08), (2, 16, 0x24), (3,  1, 0x04), (4,  4, 0x0c), (5,  4, 0x10),
    (6,  4, 0x14), (7,  4, 0x38), (8,  4, 0x3c), (9,  4, 0x40), (10, 4, 0x44),
    (11, 4, 0x48), (12, 2, 0x4c), (13, 2, 0x4e), (14, 2, 0x50), (15, 2, 0x52),
    (16, 4, 0x18), (17, 4, 0x1c), (18, 4, 0x20), (19, 2, 0x06),
]
# NOTE fields 14 and 15 land at +0x50/+0x52 -- PAST the 80-byte stride, i.e. in
# the NEXT record's +0x00/+0x02. Verified in the assembly (`addiu $s3,$s3,0x50`
# is the increment; the two writes are `$s4+0x4c`/`$s4+0x4e` with $s4 = base+4).
# It is harmless -- a record's own iteration never writes its first four bytes,
# and the count at +0x00 of record 0 is stored after the loop -- but it means
# whatever reads a record's +0x00/+0x02 is reading the PREVIOUS record's fields
# 14/15. Expect those two stats to appear shifted by one player on screen.


# Field names confirmed ON SCREEN 2026-08-27 from a --stat-probe run, on the
# head-to-head player detail view:
#
#   POINT      THIS WEEK RANKING 99999   TOTAL RANKING 99999   <- both CLAMPED
#              POINT(S) 00001919 -> 19            POINT(S) 00171717 -> 17
#   HEAD-TO-HEAD
#              THIS WEEK RANKING 99999   <- CLAMPED
#              1313 / 1515 / 1414        -> win 13, LOSS 15, DRAW 14
#              TOTAL RANKING 00666 -> 6
#              MATCH 777 -> 7   WIN 888 -> 8   LOSS 101010 -> 10  DRAW 999 -> 9
#              MATCHES TERMINATED 000555 -> 5
#
# Field 3, the record's only u8, is the DANCER / character id -- the portrait
# next to the name. Spotted because the probe was setting it to 3 and drawing
# the wrong character. It is the same value the player file carries (0x3020
# sends it as a u8, observed 0x12), so it is served from the player file now and
# is never probed.
#
# Again WIN, DRAW, LOSS on the wire (8/9/10 and 13/14/15) against WIN/LOSS/DRAW
# on screen. Third independent confirmation of that ordering.
#
# STILL UNKNOWN: 4, 11, 12, 16, 18. Fields 11/16/18 are the three "RANKING"
# numbers that all showed 99999 -- their sentinels are six digits and the widget
# is five, so the pass could not tell them apart. Re-run with
# --stat-probe-small.
# The three "RANKING" numbers that all clamped to 99999 were read cleanly by the
# --stat-probe-small pass: 00111 / 00116 / 00118.
PLAYERLIST_NAMES = {
    1: 'id', 2: 'name', 3: 'dancer',
    5: 'matches_terminated', 6: 'h2h_total_ranking',
    7: 'h2h_match', 8: 'h2h_win', 9: 'h2h_draw', 10: 'h2h_loss',
    11: 'h2h_week_ranking',
    13: 'h2h_week_win', 14: 'h2h_week_draw', 15: 'h2h_week_loss',
    16: 'point_total_ranking', 17: 'point_total',
    18: 'point_week_ranking', 19: 'point_week',
}   # still unknown: 4, 12


def playerlist_entry(ident, name, dancer=0, probe=False, stats=None):
    """One 0x4212 GetPlayerList record -- 75 bytes, 19 fields.

    Wire order (which is NOT the struct order -- see PLAYERLIST_FIELDS):

        u32 / 16 fixed / u8 / u32 u32 u32 u32 u32 u32 u32 u32
        / u16 u16 u16 u16 / u32 u32 u32 / u16

    Field 1 is the id and field 2 the name, both confirmed on screen. The other
    17 are the stats the client displays -- opening a player's detail view sends
    no further opcode, so everything shown comes from this one record. With
    `probe=True` each unknown field carries its own number as a sentinel.
    """
    nm = name.encode('ascii', 'replace')[:16].ljust(16, bytes(1))

    def v(n, size):
        if stats and n in stats:
            return _fit(stats[n], size)
        return probe_value(n, size) if probe else 0

    return (struct.pack('>I', ident)
            + nm
            + bytes([dancer & 0xff])
            + struct.pack('>8I', *[v(n, 4) for n in (4, 5, 6, 7, 8, 9, 10, 11)])
            + struct.pack('>4H', *[v(n, 2) for n in (12, 13, 14, 15)])
            + struct.pack('>3I', *[v(n, 4) for n in (16, 17, 18)])
            + struct.pack('>H', v(19, 2)))


def parse_sn_createroom(payload):
    """The SuperNOVA `0x4330 CreateRoom` request body -- 17 bytes.

    Field order and types from the builder at `0x0026ff50`, which parks each
    argument on its own stack slot and then writes them in this order through
    the send-side codec (`0x27a070` s32, `0x27a210` u16, `0x27a270` u8,
    `0x27a2b0` u8):

        s32 / u16 / u8 / u8 / s32 / u8 / s32          = 17 bytes

    Observed live over several rooms:

        00 00 00 0a  00 4d  00 00  00 00 00 00  01  00 00 00 00
        00 00 00 0a  00 4a  00 00  00 00 00 00  01  00 00 00 00
        00 00 00 0a  00 01  00 00  00 00 00 00  01  00 00 04 4c
        00 00 00 0b  00 02  01 04  00 00 00 01  01  00 00 00 00

    The leading s32 is the creator's player id, matching everything else that
    client sends. The u16 is the song and tracks `0x4392` exactly.

    **`f7` IS THE ROOM PASSWORD.** It is zero on every room made without one
    and came through as `0x44c` = 1100 on the run where a PIN was set
    (2026-09-14). The joiner's `0x4323` carries a third s32 for its attempt,
    which was zero because the client was never prompted -- see
    roomlist_entry_sn for why the padlock is not simply a flag to set.

    `f3`, `f4` and `f5` are the room's SETTINGS. All three were zero on every
    default room and moved together to 1, 4 and 1 on the run whose options were
    reported as "Difficult mode / difficulty fixed on / Random" -- three
    options, three fields -- so they are the rule toggles rather than flags.
    Which is which is not established. `f6` has been 1 on every room seen.
    """
    if len(payload) < 17:
        return None
    f1, f2, f3, f4, f5, f6, f7 = struct.unpack('>iHBBiBi', payload[:17])
    return {'id': f1, 'song': f2, 'f3': f3, 'f4': f4, 'f5': f5,
            'f6': f6, 'f7': f7}


def roomlist_entry_sn(room, name):
    """One SuperNOVA `0x4310 GetRoomList` record -- 36 bytes.

    Parser `0x002704b0`, a read-until-empty loop like every other list:

        s32 / u16 / s32 / char[16] / u8 / s32 / u8 / u16 / u8 / u8

    `0x4322` (parser `0x00270070`) is the single-record push of the same 36
    bytes, into the same array -- the room-list counterpart of `0x4222`.

    **WIRE +31 MUST HAVE BIT 0 SET OR THE ROOM IS NOT DRAWN.** Serving it as
    zero is why a created room did not appear on the other client even though
    the record was on the wire and counted. The room-list screen walks all 100
    slots at `0x00a6262c` and the whole of its filter is

        entry = ctx + 0xd2ac + i * 40
        if (entry[0x22] & 1) { keep }

    and struct `+0x22` is this byte. The value is also copied to the display
    struct at `+0x96`, so it is more than a validity flag, but bit 0 is what
    decides whether the row exists at all. Whatever the creator sent is ORed
    with 1 rather than replaced, so any other bits it set survive.

    Wire order is the parser's call order and the struct order is NOT the same
    (parser `0x002704b0`, entry stride 40, count at block `+0x14` capped at 100):

    | wire | size | struct | is |
    |---|---|---|---|
    | s32 | 4 | `+0x00` | creator's player id |
    | u16 | 2 | `+0x0e` | **the song**, compared against `0x5a` (90) at `0x00a626e4`, which picks a different display path, so 90 is a sentinel of some kind |
    | s32 | 4 | `+0x04` | |
    | fixed | 16 | `+0x10` | the name shown for the room |
    | u8 | 1 | `+0x21` | |
    | s32 | 4 | `+0x08` | |
    | u8 | 1 | `+0x22` | **listed flag, bit 0** |
    | u16 | 2 | `+0x0c` | **the song the row DISPLAYS** |
    | u8 | 1 | `+0x23` | **locked, bit 0**, set and the room cannot be entered |
    | u8 | 1 | `+0x24` | |

    **THERE ARE TWO SONG FIELDS AND BOTH HAVE TO BE SET.** Observed on screen
    2026-09-13: with only `+0x0e` filled, the room listed correctly in every
    respect except the song, which drew as random. The renderer converges on

        display[+0x80] = entry[+0x0c]        ; 0x00a626f8, both branches

    and `+0x80` is what it hands to the banner lookup `0x00277d70`, so `+0x0c`
    -- wire offset 32 -- is the song the row actually shows. `+0x0e` is only
    tested against 90 and passed to the availability filter `0x0027ec80`, whose
    result lands in `+0x82`; on the `== 90` path the filter is skipped entirely
    and `+0x82` is set to 79, which is what makes 90 look like a "random"
    sentinel. Both fields are served with the same song id.

    **WIRE +34 BIT 0 LOCKS THE ROOM.** Observed 2026-09-13: the room listed,
    but selecting it drew a padlock and "you cannot enter this room". The join
    handler at `0x00a63c1c` is

        if (display[0x97] & 1) { message(0xf); state = 4; }   // refuse
        else                   { ...the normal join... }

    and display `+0x97` is entry `+0x23`, which is this byte. It was being
    filled by echoing CreateRoom's sixth field, which happens to be 1 -- a
    reminder that echoing a request field into a response field of the same
    WIDTH is not the same as echoing it into a field of the same MEANING. It is
    served as zero now, and the room is joinable.

    The id, both song fields, the name, the listed flag and the lock are placed
    with confidence. The rest are given the CreateRoom values whose types line up,
    in order, on the reasoning that a room record is mostly an echo of the room
    created -- a structural guess, but one that round-trips what the client
    said.
    """
    r = room or {}
    nm = (name or '').encode('ascii', 'replace')[:16].ljust(16, bytes(1))
    return (struct.pack('>i', r.get('id', 0))
            + struct.pack('>H', r.get('song', 0) & 0xffff)
            + struct.pack('>i', r.get('f5', 0))
            + nm
            + bytes([r.get('f3', 0) & 0xff])
            # NOT f7: that is the room's PASSWORD (see parse_sn_createroom) and
            # broadcasting it to every browser would hand out the PIN. It was
            # only ever echoed here because the types lined up.
            + struct.pack('>i', 0)
            # Exactly 1, not `f4 | 1`. f4 is a room SETTING, not a flag word --
            # it read 4 the first time a room was created with non-default
            # options (2026-09-14), which would have set a second bit in a byte
            # whose only known meaning is bit 0 = listed. 1 is the value every
            # working room list has used.
            + bytes([1])
            + struct.pack('>H', r.get('song', 0) & 0xffff)   # the DISPLAYED song
            + bytes([0])                             # LOCKED bit -- must be 0
            + bytes([0]))


def playerlist_entry_sn(ident, name, dancer=0, probe=False):
    """One SuperNOVA `0x4212` record -- **61 bytes**, not Extreme 2's 75.

    Parser `0x00270a50`. The first three fields are identical to Extreme 2's --
    `s32` id, 16-byte name, `u8` dancer -- and then SuperNOVA reads eight `s32`
    and four `u16` and STOPS. Extreme 2 continues with three more `u32` and a
    `u16`; those four fields do not exist here.

        s32 / 16 fixed / u8 / s32 x8 / u16 x4          = 61 bytes

    OBSERVED 2026-09-13, and this is why it matters. Serving the 75-byte
    Extreme 2 record put **a phantom second player** in the list: the client
    showed the real player in row 001 and a nameless "NO DATA" row 002. The
    mechanism is the documented one -- `0x4212` is a LOOPING list with no count
    and no delimiter, so after 61 bytes the parser asks "anything left?", finds
    the 14 bytes of Extreme 2 tail still unread, and parses them as the start
    of a second record. The readers bounds-check the read CURSOR against the
    0x400 buffer and not the message length, so the remaining 47 bytes are
    taken from whatever the buffer held -- zeros here, hence a blank row rather
    than garbage.

    It is exactly the `0x3012` phantom-entry bug one message over: same cause,
    same shape, and the same lesson that a record which is "the same fields
    plus a few more" is not a compatible record.

    The 12 stat fields are served as zero. The player list draws four of them
    as MATCH / WIN / LOSE / DRAW; which four is not established, and
    `--stat-probe` is the way to settle it.
    """
    nm = name.encode('ascii', 'replace')[:16].ljust(16, bytes(1))

    def v(n, size):
        return probe_value(n, size) if probe else 0

    return (struct.pack('>i', ident)
            + nm
            + bytes([dancer & 0xff])
            + struct.pack('>8i', *[v(n, 4) for n in (4, 5, 6, 7, 8, 9, 10, 11)])
            + struct.pack('>4H', *[v(n, 2) for n in (12, 13, 14, 15)]))


# ── 0x4103 GetPlayerInfo record ──────────────────────────────────────────────
# Parser 0x0085a750, called with a1 = ctx+0x4900 (status) and a2 = ctx+0x1d784
# (the record). The status u32 comes FIRST and gates everything: non-zero and
# the parser stops without reading a single field, so a private server must send
# 0 here or the whole record is discarded.
#
# The shape is the interesting part: a 4 x 4 u32 block at +0x28..+0x67, read by
# an explicit `do { 4 x u32 } while (i < 4)` loop with a 0x10 stride. Four
# groups of four is the shape of DDR's four difficulties -- INFERRED from the
# loop, not confirmed.
PLAYERINFO_FIELDS = (
    [(1, 4), (2, 16), (3, 1), (4, 2), (5, 4), (6, 4), (7, 4), (8, 4)]
    + [(9 + i, 4) for i in range(16)]                    # the 4 x 4 block
    + [(25, 4), (26, 4)]
    + [(27, 2), (28, 2), (29, 2), (30, 2)]
    + [(31, 4), (32, 4), (33, 4), (34, 4), (35, 4)]
    + [(36, 2)]
)


# Field names confirmed ON SCREEN 2026-08-27 from a --stat-probe run (the
# "PERSONAL DATA" page of the ONLINE PLAY / DATA tab):
#
#     POINTS 333333          -> field 33
#     SCORE  MATCH 131313    -> field 13
#            WIN   141414    -> field 14
#            LOSS  161616    -> field 16
#            DRAW  151515    -> field 15
#
# NOTE the display order is MATCH / WIN / LOSS / DRAW but the wire order is
# MATCH / WIN / DRAW / LOSS -- 15 is DRAW and 16 is LOSS, not the other way
# round. Reading them off the screen left-to-right would swap them.
#
# Fields 13-16 are the SECOND group of the 4 x 4 block (the groups land at
# struct +0x28, +0x38, +0x48, +0x58; 13-16 are the +0x38 one). The screen says
# "Page 1/4", so the remaining three groups are almost certainly the other three
# pages -- unconfirmed.
# A SECOND screen (the lobby name banner) pinned the u16 half of the record:
#
#     POINTS           003636   -> field 36  (zero-padded to 6 digits)
#     WIN/LOSS/DRAW    2828 / 3030 / 2929
#                               -> win 28, LOSS 30, DRAW 29
#     RANKING POINTS   9999     -> field 31, CLAMPED (probe sent 313131)
#     RANKING H-T-H    9999     -> field 32, CLAMPED (probe sent 323232)
#
# So the record carries TWO sets of win/draw/loss: a u32 set (13-16, on the
# PERSONAL DATA page) and a u16 set (28-30, on the lobby banner), plus two
# separate points totals (33 u32, 36 u16). Lifetime vs current-event is the
# obvious reading; unconfirmed.
#
# **The wire order is WIN, DRAW, LOSS in both sets** while the UI prints
# WIN / LOSS / DRAW. Confirmed twice (14/15/16 and 28/29/30). Transcribing the
# screen left-to-right swaps draw and loss -- do not.
#
# 31 and 32 are inferred from a clamp, not read directly: the display is four
# digits wide and both showed 9999. Serve something under 10000 to confirm.
# CORRECTION 2026-08-27: 31 and 32 were guessed from a 9999 clamp and were
# WRONG. A --stat-probe-small pass (100+N, three digits, cannot clamp) read them
# straight off the screen instead:
#
#   banner        RANKING POINTS 0134 -> 34   HEAD-TO-HEAD 0125 -> 25
#                 POINTS 000136 -> 36   WIN/LOSS/DRAW 0128/0130/0129
#   THIS WEEK     RANKING 125 -> 25
#   head-to-head  MATCH/WIN/LOSS/DRAW 0127/0128/0130/0129 -> match 27
#                 and the trailing "100.79%" is computed, 128/127, not a field
#
# So the record carries a TOTAL set (13-16 u32, page 1 "SCORE") and a THIS WEEK
# set (27-30 u16, the banner and the weekly board), each ordered
# match, win, DRAW, loss. Two points totals to match: 33 (u32, total) and
# 36 (u16, this week). Two rankings: 34 (points) and 25 (head-to-head).
#
# The lesson is worth keeping: a clamped display is not a reading. Both guesses
# from the 9999 pass were wrong, and the three-digit pass cost one run.
# The ranking boards named six more (2026-08-27):
#   TOTAL head-to-head board   RANKING 107 -> 7
#                              0109/0110/0112/0111 -> match 9, win 10,
#                                                     DRAW 11, LOSS 12
#                              (100.92% is computed: win / match)
#   TOTAL point board          RANKING 131 -> 31,  points 000133 -> 33
#   THIS WEEK point board      RANKING 134 -> 34,  points 000136 -> 36
#
# So there are THREE match/win/draw/loss groups, all in the 4x4 block:
#   9-12   head-to-head TOTAL      (the TOTAL board)
#   13-16  the "SCORE" row on PERSONAL DATA page 1
#   27-30  head-to-head THIS WEEK  (u16, the banner and the weekly board)
# and four rankings: 7 h2h total, 25 h2h week, 31 point total, 34 point week.
# 17-20 and 21-24 are the two remaining 4x4 groups and have never appeared.
PLAYERINFO_NAMES = {
    1: 'id', 2: 'name', 3: 'dancer',
    7: 'ranking_h2h_total',
    9: 'match_total', 10: 'win_total', 11: 'draw_total', 12: 'loss_total',
    13: 'score_match', 14: 'score_win', 15: 'score_draw', 16: 'score_loss',
    25: 'ranking_h2h_week',
    27: 'match_week', 28: 'win_week', 29: 'draw_week', 30: 'loss_week',
    31: 'ranking_point_total', 33: 'points_total',
    34: 'ranking_point_week', 36: 'points_week',
}


def playerinfo_record_sn(ident, name, dancer=0, status=0, total=145):
    """SuperNOVA's 0x4103 GetPlayerInfo, from its own parser at 0x0026f3f0.

    The first three fields are ordered DIFFERENTLY from Extreme 2's, and that is
    the whole bug: Extreme 2 writes ident, name, dancer; SuperNOVA reads ident,
    **dancer**, name. Sending Extreme 2's record shifts the name one byte late,
    so "Cas" displays as "as" and the dancer byte lands inside the name --
    leaving the avatar generic. Reported on screen and confirmed here.

        +0   u32    status (0 = OK; non-zero and the parser reads nothing else)
        +4   s32    player id      -> struct +0x14
        +8   u8     dancer         -> struct +0x18
        +9   char[16] name         -> struct +0x19
        +25  u32, s32, u16 x4, s32 x5, u16, s32, char[16], s32, s32, u16 ...

    The parser reads ~93 fixed bytes; Extreme 2's record is 145, so the length
    is already sufficient and only the ordering had to change. The trailing
    fields are stats we do not have yet and are served as zero.
    """
    out = struct.pack('>I', status)
    if status != 0:
        return out
    out += struct.pack('>i', ident)
    out += bytes([dancer & 0xff])
    out += name.encode('ascii', 'replace')[:16].ljust(16, bytes(1))
    return out.ljust(total, bytes(1))


def playerinfo_record(ident, name, dancer=0, status=0, probe=False, stats=None):
    """The 0x4103 GetPlayerInfo body -- u32 status + 141 bytes = 145 total."""
    out = struct.pack('>I', status)
    if status != 0:
        return out                       # the parser reads nothing else
    for n, size in PLAYERINFO_FIELDS:
        if n == 1:
            out += struct.pack('>I', ident)
        elif n == 2:
            out += name.encode('ascii', 'replace')[:16].ljust(16, bytes(1))
        elif n == 3:
            out += bytes([dancer & 0xff])
        else:
            if stats and n in stats:
                val = _fit(stats[n], size)
            else:
                val = probe_value(n, size) if probe else 0
            out += (bytes([val]) if size == 1
                    else struct.pack('>H' if size == 2 else '>I', val))
    return out


def info_stats(s):
    """Kept results by 0x4103 field number, see PLAYERINFO_NAMES. The SCORE
    row on PERSONAL DATA page 1 (13-16) gets the same totals as 9-12, which
    is a guess: nothing yet says what distinguishes the two."""
    return {7: s['ranking_h2h_total'],
            9: s['match_total'], 10: s['win_total'],
            11: s['draw_total'], 12: s['loss_total'],
            13: s['match_total'], 14: s['win_total'],
            15: s['draw_total'], 16: s['loss_total'],
            25: s['ranking_h2h_week'],
            27: s['match_week'], 28: s['win_week'],
            29: s['draw_week'], 30: s['loss_week'],
            31: s['ranking_point_total'], 33: s['points_total'],
            34: s['ranking_point_week'], 36: s['points_week']}


def list_stats(s):
    """Kept results by 0x4212 field number, see PLAYERLIST_NAMES. Field 12 is
    unnamed and sits with the weekly win/draw/loss, so it gets the weekly
    match count, unconfirmed."""
    return {6: s['ranking_h2h_total'], 7: s['match_total'],
            8: s['win_total'], 9: s['draw_total'], 10: s['loss_total'],
            11: s['ranking_h2h_week'], 12: s['match_week'],
            13: s['win_week'], 14: s['draw_week'], 15: s['loss_week'],
            16: s['ranking_point_total'], 17: s['points_total'],
            18: s['ranking_point_week'], 19: s['points_week']}


def probe_legend():
    """Printed at startup under --stat-probe so a screenshot can be decoded."""
    out = ['stat probe ON -- each field carries its own number as its value:',
           '  0x4212 GetPlayerList (75 B, 19 fields):']
    for n, size, off in PLAYERLIST_FIELDS:
        if n in (1, 2):
            continue
        out.append('    field %-2d  u%-2d  record+0x%02x  -> %d'
                   % (n, size * 8, off, probe_value(n, size)))
    out.append('  0x4103 GetPlayerInfo (145 B, 36 fields):')
    for n, size in PLAYERINFO_FIELDS:
        if n in (1, 2):
            continue
        tag = '  (4x4 block)' if 9 <= n <= 24 else ''
        out.append('    field %-2d  u%-2d -> %d%s'
                   % (n, size * 8, probe_value(n, size), tag))
    return '\n'.join(out)


# ── The three PERSONAL DATA log lists ────────────────────────────────────────
# Pages 2 and 3 of PERSONAL DATA were blank because they are NOT part of
# 0x4103 -- they are these, and we had been answering all three with empty
# bodies. Each is a three-part group: an opener carrying the record count, one
# or more data messages, and a terminator.
#
#   0x4108 -> 0x4109 / 0x4110 / 0x4111   GetPlyerHtoHLog   <= 60 records
#   0x4112 -> 0x4113 / 0x4114 / 0x4115   GetPlyerPointLog  <= 60 records
#   0x4116 -> 0x4117 / 0x4118 / 0x4119   GetPlyerRCLog     <= 120 records
#
# The OPENER (parser 0x00859ee0 for HtoH, and the other two are structurally
# identical) is `u32 status` + `u8 count`:
#   - it first zeroes the whole destination array (0x2d0 = 720 = 60 x 12 for
#     HtoH, which is how the record size and the cap were confirmed),
#   - a non-zero status aborts before the count is even read,
#   - and a count >= the cap makes the client manufacture **-0x262 (-610)**
#     with no server involvement -- the same self-inflicted error family as the
#     -266 from 0x4101. Keep the count under the cap.
#
# Record layouts are the parsers' call order (0x00859dd0 / 0x00859bf0 /
# 0x008599e0). Note the RC record reads its second field into +0x10, i.e. OUT of
# address order, and that its struct stride (0x14) is wider than its 17 wire
# bytes.
# Field names confirmed ON SCREEN 2026-08-27 with --stat-probe (values read
# RRRFF, so the row is unambiguous too):
#
#   PAGE 2/4  =  the HtoH log.  Rows labelled "1st/2nd/3rd WEEK".
#       MATCH 1002  WIN 1003  LOSS 1005  DRAW 1004
#     -> wire field 2 = match, 3 = win, 4 = DRAW, 5 = LOSS.
#     Field 1 (the u32) is NOT displayed -- week id or date, unconfirmed. The
#     row label tracks the record index, so it may just be positional.
#     WIN, DRAW, LOSS on the wire again: fourth independent confirmation.
#
#   PAGE 3/4  =  the RC log.  Columns TITLE / RANKING / SCORE / TIME / COMBO.
#       RANKING 1002   SCORE 00001003   TITLE, TIME and COMBO all BLANK
#     -> wire field 2 = ranking, 3 = score.
#     Field 1 is a u8 and almost certainly the TITLE (song) id -- 11/21/31 do
#     not resolve to a song, which is why the column is empty. TIME and COMBO
#     stayed blank even though fields 4/5 carried values, so those two columns
#     are probably gated on a valid title. Unresolved.
#
#   PAGE 4/4 not yet captured -- by elimination it should be the Point log.
HTOH_LOG_NAMES = {2: 'match', 3: 'win', 4: 'draw', 5: 'loss'}
# PAGE 4/4 is the Point log: columns RANKING / POINT, rows 1st/2nd/3rd WEEK.
#   RANKING 1001/2001/3001 -> field 1     POINT 001002/002002/003002 -> field 2
# Both fields identified, so this record is completely known.
POINT_LOG_NAMES = {1: 'ranking', 2: 'point'}
RC_LOG_NAMES = {1: 'title?', 2: 'ranking', 3: 'score'}

HTOH_LOG_SIZES = [4, 2, 2, 2, 2]          # 12 wire bytes, struct stride 0x0c
POINT_LOG_SIZES = [4, 2]                  #  6 wire bytes, struct stride 0x08
RC_LOG_SIZES = [1, 4, 4, 4, 2, 2]         # 17 wire bytes, struct stride 0x14

LOG_GROUPS = {
    0x4109: ('HtoH', HTOH_LOG_SIZES, 60),
    0x4113: ('Point', POINT_LOG_SIZES, 60),
    0x4117: ('RC', RC_LOG_SIZES, 120),
}
LOG_DATA_OF = {0x4110: HTOH_LOG_SIZES, 0x4114: POINT_LOG_SIZES,
               0x4118: RC_LOG_SIZES}
LOG_KIND_OF = {0x4110: 'HtoH', 0x4114: 'Point', 0x4118: 'RC'}


def _fit(v, size):
    """Clamp a value to what an unsigned field of `size` bytes can hold."""
    return max(0, min(int(v), (1 << (8 * size)) - 1))


def log_rows(sizes, rows):
    """Real personal-log records: each row a tuple in wire field order."""
    out = b''
    for row in rows:
        for size, val in zip(sizes, row):
            val = _fit(val or 0, size)
            out += (bytes([val]) if size == 1
                    else struct.pack('>H' if size == 2 else '>I', val))
    return out


def log_open(count, status=0):
    """The 0x4109 / 0x4113 / 0x4117 body -- u32 status, u8 count."""
    return struct.pack('>IB', status, count & 0xff)


def log_records(sizes, n, probe=False):
    """`n` log records. Under --stat-probe each value reads as RRRFF: the
    thousands are the record index (1-based) and the units the field number, so
    one screenshot gives both the field order AND the row order."""
    out = b''
    for rec in range(n):
        for f, size in enumerate(sizes, 1):
            if not probe:
                val = 0
            elif size == 1:
                val = (rec + 1) * 10 + f        # u8 cannot hold RRRFF
            else:
                val = (rec + 1) * 1000 + f
            out += (bytes([val & 0xff]) if size == 1
                    else struct.pack('>H' if size == 2 else '>I', val))
    return out


# ── 0x6002 ranking record ────────────────────────────────────────────────────
# Shared by all three ranking RPCs (NetPrgGet{HtoH,Point,RC}Ranking all answer
# 0x6001 / 0x6002 / 0x6003). Opener 0x00857b90 is a plain u32 status into
# ctx+0x4900, which then zeroes one record and resets the count at ctx+0x2a494;
# records go to ctx+0x2a498. Parser 0x00857a40: stride 0x34, cap 100.
#
# Wire order is the parser's call order and is NOT the struct order -- note the
# name lands at +0x01 with the dancer byte squeezed in at +0x00, the same
# dancer+name pairing the player list uses.
#
#   (wire #, size, struct offset)
RANKING_FIELDS = [
    (1, 4, 0x14), (2, 4, 0x1c), (3, 16, 0x01), (4, 1, 0x00), (5, 4, 0x20),
    (6, 4, 0x24), (7, 4, 0x28), (8, 4, 0x2c), (9, 4, 0x30), (10, 4, 0x18),
]
# Named on screen 2026-08-27 from the 200+N band:
#   row "001  Cas  0618 / 0205 / 0207 / 0206 / 33.17%"
#     -> field 1 rank, 5 win, 6 DRAW, 7 LOSS, and 0618 is NOT a field:
#        205+206+207 = 618, so MATCH is computed client-side as win+draw+loss
#        (33.17% = 205/618 confirms it).
#   point board row "001  Cas  000208" -> field 8 = points.
# Still unknown: 2, 9, 10.
#   RC challenge board showed 209 for both challenges -> field 9 = RC score.
# So the three boards share one record but read DIFFERENT value fields out of
# it: 8 for the point board, 9 for the RC board, 5/6/7 for head-to-head.
RANKING_NAMES = {1: 'rank', 3: 'name', 4: 'dancer',
                 5: 'win', 6: 'draw', 7: 'loss',
                 8: 'points', 9: 'rc_score'}
RANKING_WIRE = 49
RANKING_CAP = 100


def ranking_entry(rank, name, dancer=0, probe=False, values=None):
    """One 0x6002 record, 49 bytes.

    Probe values live in their own 200+N band so a ranking screen can never be
    confused with the 100+N of 0x4103 / 0x4212 -- both can be on screen at once.
    Field 3 (name) and field 4 (dancer) are always real: the dancer byte drives
    the portrait, and probing it draws the wrong character.
    """
    def v(n):
        if values and n in values:
            return _fit(values[n], 4)
        return (200 + n) if probe else 0

    out = b''
    for n, size, _ in RANKING_FIELDS:
        if n == 3:
            out += name.encode('ascii', 'replace')[:16].ljust(16, bytes(1))
        elif n == 4:
            out += bytes([dancer & 0xff])
        elif n == 1:
            out += struct.pack('>I', rank)
        else:
            out += struct.pack('>I', v(n))
    return out


# ── Ranking Challenge ────────────────────────────────────────────────────────
# The RC tab shows two challenge cards ("NORMAL NO:0", "00/00") and a ten-row
# song list. Every row read "1998 / NAOKI" because the song id is a u16 we were
# sending as zero, ten times over -- not ten copies of a song, one song id
# repeated.
#
# 0x5001 GetRCInfo   parser 0x00857fb0 -> ctx+0x2a390, struct 0x8c, body 138 B:
#       u32 status
#       u32 -> R+0x04     u8 -> R+0x00      u32 -> R+0x08
#       u8  -> R+0x0c     u8 -> R+0x0d      u8  -> R+0x0e
#       u8  -> R+0x0f     u8 -> R+0x10
#       then TEN entries, base advancing 0x0c each time:
#         u16 -> R+0x1c   <- the SONG ID (the ten rows on screen)
#         u8 x10 -> R+0x12 .. R+0x1b
#     so each entry is [u16 song][10 x u8] = 12 bytes on the wire.
#
# 0x5003 GetRCTrycount  parser 0x00857e80 -> ctx+0x2a381:
#       u32 status / u8 / u8      <- this is the "00/00" on each card
#
# 0x5010 GetRCIdList    parser 0x00857800 -> count at ctx+0x2a384, ids at
#       ctx+0x2a41c:  u8 count (1..120, 0 or >120 skips the list entirely)
#       then `count` u8 ids.
#
# 0x5005 GetRCEntry and 0x5007 GetRCRegist are plain u32-status parse thunks
# (0x00857df0 / 0x00857d30) -- nothing to fill in.
#
# The header and the per-entry bytes were IDENTIFIED 2026-08-28, not by
# sweeping them at the client but by reading the two places the client copies
# them out to. `NetPrgGetRCInfo` (0x001dd5a0) copies the parsed struct into a
# 0x84-byte per-challenge record:
#
#     dst+0x04  s16 <- R+0x04     the challenge id, echoed back
#     dst+0x06  u8  <- R+0x00     challenge CLASS, 0..7 -> message ids 89..96
#     dst+0x07  s8  <- R+0x08
#     dst+0x08  u8  <- R+0x0c     RULE MASK, four bits -> message ids 0x4c..0x50
#     dst+0x09  u8  <- R+0x0d     0..2 -> message ids 82..84
#     dst+0x0a  u8  <- R+0x10     0..2 -> message ids 86..88   <- DIFFICULTY
#     dst+0x0b  u8  <- R+0x0e
#     then ten entries of 12 bytes: u16 song (mapped through FUN_001e7060) and
#     the ten u8s from R+0x12..R+0x1b.
#
# R+0x0f is parsed and then never copied out -- it reaches nothing.
#
# **There are TWO difficulty fields and they are not the same thing.**
#
#   R+0x10, header, per CHALLENGE -- the difficulty the CARD DISPLAYS. In
#   FUN_001f75b0 and FUN_001f44e0 it is the index that decides which of a song's
#   three per-difficulty values every row shows: 2 -> song+0x20, 1 -> song+0x24,
#   0 -> song+0x28, passed to the row widget as class 3 / 2 / 1. One value for
#   all ten rows, and it is a DISPLAY selector -- it is only ever read by the
#   two card builders.
#
#   R+0x12, per ENTRY -- the chart actually PLAYED, on the live evidence from
#   a sweep recorded while testing: with it set to 2
#   the play screen read HEAVY, and 4 HARD-FROZE the game on the Practice tab
#   (a worse hang than the 31..40 one -- no keepalives afterwards), so its legal
#   range is at most 0..3. That it is the odd one out here is corroboration
#   rather than coincidence: it is the one byte of the ten that the client's own
#   "options changed" comparison SKIPS, because a difficulty is not an option.
#
# Set the display one with --rc-difficulty and the played one with the first
# value of --rc-flags. Serving them inconsistently is legal and will simply draw
# one difficulty and play another.
#
# **The client tells you the default for the ten per-entry bytes.** Both
# FUN_00262c40 (the two featured cards) and FUN_001f5770 (the id-list cards)
# decide whether to light the "this challenge changes the options" marker by
# comparing nine of the ten against a fixed tuple:
#
#     R+0x13 == 2, R+0x14 == 0, R+0x15 == 0, R+0x16 == 1, R+0x17 == 0,
#     R+0x18 == 1, R+0x19 == 0, R+0x1a == 0, R+0x1b == 0
#
# so (2,0,0,1,0,1,0,0,0) is the game's own idea of "default play options" and
# the all-zero record we used to send is three bytes away from it in the
# direction of "the player did something strange". R+0x12, the tenth, is
# excluded from that comparison -- it is not one of the options.
RC_ENTRIES = 10
RC_TRY_MAX = 3
# FUN_001e7060 maps a wire song id through the table at 0x002e7850. The table
# was dumped 2026-08-28 and it is **a permutation of 0..73**: 74 wire ids onto
# 74 internal song ids, one to one, no gaps and no duplicates. Entries 74..79
# are all ZERO -- not a terminator, a valid internal id -- so serving a wire id
# in 74..79 silently maps to internal song 0 and shows the same song several
# times. 80 was the old bound and it was six too many.
#
# (The banner loader FUN_001f4af0 clamps the MAPPED id at 0x4a = 74 on top of
# this, which is the same 74 songs seen from the other side.)
RC_SONG_IDS = 74
# R+0x13..R+0x1b, the nine play options, as the client itself defines them.
RC_DEFAULT_OPTS = (2, 0, 0, 1, 0, 1, 0, 0, 0)
# A song id the table maps to -1 ENDS the list: both card builders break out of
# the ten-entry loop on `song == -1`. FUN_001e7060 returns -1 for a negative
# index and the wire field is read as a signed short, so any id with the top bit
# set terminates. This is how a challenge with fewer than ten stages is served.
RC_END_SONG = 0xffff
RC_DIFFICULTIES = 3


# The ranking-challenge calendar and generator live in schedule.py, so that
# the operator page can show exactly what the gate will serve.
import content
import db
import results
import udprelay
import publicaddr
from schedule import (RC_BAD_SONG_IDS, RC_TESTED_SONG_IDS,
                      RC_WEEK_SECONDS, RC_WEEKS,
                      rc_week, rc_auto_songs)


def rc_info(status=0, first_song=1, hdr=None, flags=None, vary=None,
            stages=RC_ENTRIES, songs=None):
    """The 0x5001 GetRCInfo body -- 138 bytes.

    Header, in WIRE order (which is not struct order -- see the table above):

        u32 R+0x04   challenge id, echoed into the card
        u8  R+0x00   challenge class, 0..7
        u32 R+0x08
        u8  R+0x0c   rule mask, four bits
        u8  R+0x0d   0..2
        u8  R+0x0e
        u8  R+0x0f   parsed, then never read by anything
        u8  R+0x10   DIFFICULTY, 0..2

    then ten entries of `u16 song` + ten u8s. `flags` supplies those ten; its
    first byte is R+0x12 (not one of the play options) and the other nine
    default to RC_DEFAULT_OPTS, the tuple the client itself treats as "options
    unchanged". Serving them as zero -- which is what this did until the
    defaults were recovered -- puts three of the nine off their default value,
    which is why every challenge came up marked as modified and playing
    something nobody chose.

    `stages` under 10 terminates the list early with RC_END_SONG, the way the
    client's own loop expects; the entries past it are still on the wire because
    the body is fixed-length, they are just never read.

    The one thing here that has ever frozen the client is an out-of-range INDEX
    (a --rc-flags sweep of 31..40 hung it on entering the lobby, 2026-08-27), so
    the ranges above are enforced by the caller, not trusted.
    """
    out = struct.pack('>I', status)
    if status != 0:
        return out
    h = list(hdr or [0] * 8) + [0] * 8
    out += (struct.pack('>I', h[0] & 0xffffffff) + bytes([h[1] & 0xff])
            + struct.pack('>I', h[2] & 0xffffffff)
            + bytes(x & 0xff for x in h[3:8]))
    base = (list(flags) + [0] * 10)[:10] if flags else [0] + list(RC_DEFAULT_OPTS)
    for i in range(RC_ENTRIES):
        if i >= stages:
            song = RC_END_SONG
        elif songs is not None:
            song = songs[i] & 0xffff
        else:
            song = (first_song + i) & 0xffff
        out += struct.pack('>H', song)
        fl = list(base)
        if vary is not None and 0 <= vary < 10:
            # Give each of the ten entries a DIFFERENT value in one byte, so a
            # single run covers ten values instead of one. Entry i is stage i of
            # the challenge, so the effect shows up stage by stage.
            fl[vary] = i
        out += bytes(x & 0xff for x in fl)
    return out


def rc_challenge(sel):
    """Which challenge the two 0x5000 selector bytes are asking for.

    The builder (0x00858180) sends `u8 a, u8 b` and the RC scene state machine
    (FUN_001e7950) picks them:

        case 4  (0, 0)          the first featured card
        case 5  (1, 0)          the second featured card
        case 8  (i & 1, i/2+1)  entry i of the 0x5010 id list

    so `b == 0` addresses a featured card and `b >= 1` addresses a list entry.
    Answering every selector with the same record is what made both cards show
    the same songs and the same "NORMAL NO:0"; the earlier a*2+b guess got the
    two featured cards right and every list entry wrong.
    """
    a, b = sel
    return a if b == 0 else 2 + (b - 1) * 2 + a


def rc_trycount(card0=0, card1=0, status=0):
    """0x5003: u32 status, then one u8 per featured card.

    Read as entries so far this week on each card. The client asks once per
    visit with only a player id, and the two cards drew different numbers from
    one reply, which rules out the older reading of used/allowed for both.
    Unconfirmed on screen.
    """
    return struct.pack('>IBB', status, card0 & 0xff, card1 & 0xff)


def rc_idlist(ids):
    """0x5010 -- u8 count then that many u8 ids. Count must be 1..120 or the
    client reads no ids at all."""
    ids = list(ids)[:120]
    return bytes([len(ids)]) + bytes(i & 0xff for i in ids)


# ── 0x441e GetRuleMask, which head-to-head rules are on ─────────────────────
# Extreme 2's parser is FUN_00859820: a u32 status, and if the status is zero,
# **THREE** u8s into ctx+0x2a37e..0x2a380 -- not the four the SuperNOVA parser
# reads. Seven bytes, and we were sending none.
#
# FUN_001e7950 case 1 folds them into one bitmask, DAT_01047cb5:
#     bit 0 <- byte 0 == 1
#     bit 1 <- byte 1 == 1
#     bit 2 <- byte 2 == 1
# and the result column list at FUN_00298040 NAMES them: it draws a row per
# enabled rule with the header strings "SCORE" (0x00306be0), "COMBO"
# (0x00306bf0, drawn only when bit 1 is set), "SURVIVAL" (0x00306bf8, only when
# bit 2 is set) and "TOTAL" (0x00306c08). So this is the set of win conditions a
# head-to-head match is scored on. Note each byte is tested `== 1` exactly:
# anything else is off, so these are booleans and not counts.
RULE_NAMES = ('score', 'combo', 'survival')


def rule_mask_body(rules=(1, 1, 1), status=0):
    """The 0x441e body -- u32 status + three u8 rule flags."""
    out = struct.pack('>I', status)
    if status != 0:
        return out
    r = (list(rules) + [0, 0, 0])[:3]
    return out + bytes(1 if x else 0 for x in r)


# ── SuperNOVA: the online song list (0x8000 / 0x8004 / 0x7000) ───────────
#
# THIS IS THE "EXTRA SONGS OVER THE NETWORK" FEATURE FROM THE MANUAL.
# Full write-up in docs/supernova-online-songs.md.
#
# SuperNOVA ships 79 songs on the disc as an array of 0xa8-byte records at
# 0x002c1b90 in SLUS_213.77, each starting with a 4-character code. The last
# five are the online-only ones, and THEIR CHARTS ARE ON THE DISC TOO --
# `online/ssq/00_felw_b.bin` .. `04_trim_b.bin` have real 8-24 KB entries in the
# file index at 0x001ab9a0. They are LOCKED, not missing, and the lock is the
# server's to open:
#
#   FUN_0027ec80(song, difficulty, mode) searches ctx+0x26b0 for a record whose
#   id matches, and returns -1 -- "not available" -- unless the flag for that
#   difficulty is set. The ONLY thing that ever writes ctx+0x26b0 is the 0x8002
#   parser, netlby_mas4 calls the gate 56 times, and no other module calls it at
#   all. So inside the online lobby the song list is entirely server-driven, and
#   the empty list we have been serving unlocks nothing.
#
# 0x8002 record, from the parser at 0x0026b5a0 -- 13 bytes, NO delimiter and no
# count. The loop just reads until the payload runs out (0x00279a60 is a pure
# "anything left?" probe that consumes nothing), so records are simply
# concatenated:
#
#     s32  song id            0..78, index into the 0xa8-byte table
#     u8   available[5]       one per difficulty; the gate tests `== 1`
#     s32  UNIDENTIFIED       returned by FUN_0027e970 and summed across all
#                             records into ctx+0x2c60 as a total. Served as 0.
#
# Records accumulate across messages and the client caps the array at 0x5a = 90.
# One frame holds 78, so all 79 needs two 0x8002 messages -- see the chunked
# DATA path in on_frame.
SN_SONG_COUNT = 79
SN_SONG_RECORD = 13
SN_SONGS_PER_MESSAGE = MAX_PAYLOAD // SN_SONG_RECORD      # 78
SN_SONG_MAX = 90                                          # client-side array cap

# The five online songs, in the order the boot sequence downloads them -- the
# table at 0x002d1290 is 0x4a, 0x4c, 0x4b, 0x4d, 0x4e, which matches the 00_..04_
# numbering of the ssq filenames exactly. That agreement is what identifies the
# table as this feature's and not some other five-entry list.
SN_ONLINE_SONGS = (
    (0x4a, 'felw', "Feelings Won't Fade(Extend Trance Mix)"),
    (0x4c, 'nizi', 'NIJIIRO'),
    (0x4b, 'punc', 'HONEY PUNCH'),
    (0x4d, 'silv', 'Silver Platform - I wanna get your heart -'),
    (0x4e, 'trim', 'Trim'),
)

# Responses carrying a chunkable list: payload_for may return a LIST of bodies
# and on_frame sends one frame per entry. Only 0x8002 needs it today.
SN_CHUNKED = (0x8002, 0x3122)


# ── The news feed (SuperNOVA) ────────────────────────────────────────────────
#
# ONLINE PLAY -> Information. Not an HTTP page, which is where this was looked
# for first: the service table does hold an info URL, and the disc patch does
# rewrite it to our web server, but `ddr-web` has never been asked for it once.
# The feed is `0x3120`, and the client requests it **at login** -- immediately
# before `0x3010 GetPlayerFileList`, once per session -- so the list is fetched
# then and the Information screen only renders what was cached.
#
# Served BEGIN + END with no records until 2026-09-13, and the screen drew one
# row of garbage: a title of `.0.60` and a date of `1995.08.13 17:28`, which is
# an uninitialised record being rendered rather than an empty list.
#
#   0x3122  parser 0x00272b50:  s32 / s32 / s32 / char[64] / cstring
#
# 76 bytes fixed plus the NUL-terminated body. The record is a LOOP member with
# no count and no delimiter, so a zero-length 0x3122 is worse than none at all
# -- the parser would read its fields off the end of the message. payload_for
# returns an EMPTY LIST when there is no news, which sends no frame for that
# part of the group at all.
#
# **The THIRD s32 is a UNIX TIMESTAMP.** Settled on screen 2026-09-13 by a
# probe that was wrong in a useful way: the fields went out as
# (index, 20260913, 2219) on a guess of (index, YYYYMMDD, HHMM), and the
# Individual Information page rendered "1970.01.01 00:36". 2219 seconds past
# the epoch is 00:36:59 UTC, so the third field is seconds-since-1970 and the
# clock is UTC with no offset applied. The second field went out as 20260913
# and reached nothing on that page, so whatever it is, it is not the date.
#
# The first field is served as the 1-based index and the second as zero; both
# are still unidentified. --sn-news-fields overrides all three for probing.
SN_NEWS_TITLE = 64
SN_NEWS_BODY = 512


def wrap_news(text, width=0):
    """Hard-wrap a news body.

    **The client does not wrap.** Observed 2026-09-13: a one-line body ran
    straight off the right edge of the Individual Information page and was
    simply cut. So the line breaks have to be in the text the server sends, and
    0x0a is the separator on the assumption that this ASCII renderer treats it
    the way everything else does -- if it turns out to draw as a glyph instead,
    that will be obvious on screen and the separator is the only thing to
    change.

    width 0 leaves the text exactly as given.
    """
    if not width or width <= 0:
        return text
    out, line = [], ''
    for word in text.split():
        if line and len(line) + 1 + len(word) > width:
            out.append(line)
            line = word
        else:
            line = (line + ' ' + word) if line else word
        # A single word longer than the line just gets its own long line;
        # breaking mid-word would be worse than a slight overrun.
    if line:
        out.append(line)
    return chr(10).join(out)


def sn_news_record(index, title, body, fields=None, wrap=0):
    """One `0x3122` news record."""
    if fields is None:
        # field 3 is seconds since the Unix epoch, rendered as UTC -- see above.
        fields = (index, 0, int(time.time()))
    t = title.encode('ascii', 'replace')[:SN_NEWS_TITLE]
    b = wrap_news(body, wrap).encode('ascii', 'replace')[:SN_NEWS_BODY]
    return (struct.pack('>iii', *[int(x) for x in fields[:3]])
            + t.ljust(SN_NEWS_TITLE, bytes(1))
            + b + bytes(1))


def sn_news_bodies(items, fields=None, wrap=0):
    """One frame per news item -- see SN_CHUNKED.

    Records are 77 bytes at minimum and the payload cap is 1024, so more than a
    couple of long items would not fit in one frame anyway. One per frame is
    within what the parser accepts: it resumes from its own count across the
    messages of a group, the same way 0x8002 does.
    """
    out = []
    for i, item in enumerate(items or []):
        title, _, body = item.partition('|')
        out.append(sn_news_record(i + 1, title.strip(),
                                  body.strip() or title.strip(), fields, wrap))
    return out


def sn_song_ids(mode):
    """Which song ids to mark available, for the --sn-songs setting."""
    if mode == 'online':
        return [i for i, _, _ in SN_ONLINE_SONGS]
    if mode == 'all':
        return list(range(SN_SONG_COUNT))
    return []


def sn_song_avail_bodies(ids, extra=0, difficulties=(1, 1, 1, 1, 1)):
    """The 0x8002 bodies -- a LIST, one per frame, since 79 records do not fit.

    Returns [b''] for an empty list rather than [], so the group still sends its
    DATA message: 0x8002 leads with the "anything left?" probe, which makes an
    empty body a well-formed empty list rather than a short read.
    """
    flags = bytes(1 if x else 0 for x in (list(difficulties) + [0] * 5)[:5])
    recs = [struct.pack('>i', i) + flags + struct.pack('>i', extra)
            for i in list(ids)[:SN_SONG_MAX]]
    if not recs:
        return [b'']
    return [b''.join(recs[i:i + SN_SONGS_PER_MESSAGE])
            for i in range(0, len(recs), SN_SONGS_PER_MESSAGE)]


def sn_song_name_body(entries):
    """The 0x8006 body -- s32 id + a fixed 32-byte name, max 20 records.

    Same read-until-empty loop as 0x8002 (parser 0x0026b2b0). 20 * 36 = 720
    bytes, so one frame always suffices. WHAT this list names is not
    established, which is why it is served empty by default.
    """
    out = b''
    for ident, name in list(entries)[:20]:
        out += struct.pack('>i', ident)
        out += name.encode('ascii', 'replace')[:32].ljust(32, b'\x00')
    return out


def sn_rule_mask_body(rules=(1, 1, 1, 1), status=0):
    """The SuperNOVA 0x441e body -- u32 status + FOUR u8, from 0x0026e570.

    Extreme 2's parser reads THREE (see rule_mask_body); SuperNOVA's reads four,
    into ctx+0x12e3c..0x12e3f. Eight bytes. This is the gap docs/protocol.md
    lists under "Known gaps" -- we have been answering it empty.

    The four are almost certainly the same win-condition booleans Extreme 2
    names SCORE / COMBO / SURVIVAL plus one more, but SuperNOVA ships no
    equivalent of the header strings that proved that, so the fourth is a guess
    and the mapping is unconfirmed.
    """
    out = struct.pack('>I', status)
    if status != 0:
        return out
    return out + bytes(1 if x else 0 for x in (list(rules) + [0] * 4)[:4])


# ── SuperNOVA: the competition list (0x5030 / 0x5034) ────────────────────
#
# "The competition event is not being held at the moment. Please wait until the
# next event." -- UI string 0x06b, seen 2026-08-28 on entering Ranking
# Challenge, immediately after the client sent 0x5030 and 0x5034 and we
# answered both with an EMPTY list. The message is not an error: it is what an
# empty competition list looks like.
#
# Both groups have the SAME record layout, from the parsers at 0x00269550
# (0x5032) and 0x002692a0 (0x5036). Max TEN records, stride 60 in the client's
# array, 50 bytes on the wire, no delimiter -- the usual read-until-empty loop:
#
#     s32   id
#     char[32] name          (the parser NUL-terminates at [32], so 32 on the wire)
#     s32   UNIDENTIFIED     served 0
#     u8    UNIDENTIFIED     served 0
#     s32   start            unix seconds
#     s32   end              unix seconds
#     u8    UNIDENTIFIED     served 0
#
# The two adjacent s32s are read as the window because netlby_mas4 carries
# exactly one pair of format strings for them --
#     "%04d/%02d/%02d %02d:%02d - %04d/%02d/%02d %02d:%02d"   (0x000241ac)
# -- and the client is already polling 0x2006 SvrTime, which we answer with
# unix seconds. INFERRED FROM SHAPE, not proven: if the event still reads as
# not-held with a wide-open window, this pair is the first thing to doubt.
#
# The three unidentified fields are served as ZERO deliberately. The Extreme 2
# Ranking Challenge lesson applies unchanged: these are almost certainly table
# INDICES, and probing them with plausible-looking values froze the game
# outright. Zero is the only value known not to.
#
# 0x5030 is the list you can enter now and 0x5034 the future one -- UI strings
# 0x0ae "Display all competitions you can participate in" and 0x0af "...planned
# for the future", in that request order. So the entry goes in 0x5032 and
# 0x5036 stays empty, which is what 0x0b1 "There are no future competitions
# currently planned" is for.
SN_COMP_RECORD = 50
SN_COMP_MAX = 10


def sn_comp_body(entries):
    """The 0x5032 / 0x5036 body -- 50 bytes per record, at most ten."""
    out = b''
    for ident, name, start, end in list(entries)[:SN_COMP_MAX]:
        out += struct.pack('>i', ident)
        out += name.encode('ascii', 'replace')[:32].ljust(32, b'\x00')
        out += struct.pack('>i', 0)              # unidentified
        out += bytes([0])                        # unidentified
        out += struct.pack('>ii', start, end)
        out += bytes([0])                        # unidentified
    return out


SN_STAGES = 10          # stage records in a 0x5001 competition detail
SN_STAGE_BYTES = 11     # u8 settings after each stage's u16 song
SN_DETAIL_LEN = 61 + SN_STAGES * (2 + SN_STAGE_BYTES)     # 191
SN_STAGE_OPTIONS = (2, 0, 0, 1, 0, 1, 0, 0, 1, 1)   # "options unchanged"
SN_DEFAULT_DIFFICULTY = 1                            # chart, 0..4


def sn_detail_body(comp):
    """The 0x5001 body for one SuperNOVA competition, 191 bytes.

    Read field by field out of the parser FUN_0026a0f0:

        u32 status / s32 id / char[32] name / s32 / u8 / s32 start
        / s32 end / u8 x4 / s32                          61-byte header
        then TEN stage records: u16 song / u8 x11        13 bytes each

    The song is the u16 at the start of each stage, and -1 (0xffff) leaves
    a stage empty (DATA08 0x00a4996c skips it). The eleven u8 after it are
    the chart difficulty (0..4, handed to the availability check as 1..5)
    and then ten play options. DATA08 0x00a49a28 lights the "options
    changed" marker by comparing those ten against (2,0,0,1,0,1,0,0,1,1),
    the same trick Extreme 2 uses, so that tuple is the normal setting.
    Option 1 is the speed (masked with 0x1f); serving it as 0 made the
    arrows crawl up the screen packed together (2026-09-14).
    """
    nm = comp['name'].encode('ascii', 'replace')[:32]
    songs = list(comp.get('songs') or [0])
    out = (struct.pack('>I', 0) + struct.pack('>i', comp['id'])
           + nm.ljust(32, bytes(1))
           + struct.pack('>i', 0) + bytes([0])
           + struct.pack('>ii', comp['start'], comp['end'])
           + bytes(4) + struct.pack('>i', 0))
    diff = comp.get('difficulty')
    diff = SN_DEFAULT_DIFFICULTY if diff is None else diff
    opts = list(comp.get('options') or SN_STAGE_OPTIONS)[:10]
    opts += list(SN_STAGE_OPTIONS)[len(opts):]
    stage = bytes([diff & 0xff] + [o & 0xff for o in opts])
    for i in range(SN_STAGES):
        song = songs[i] if i < len(songs) else 0xffff
        out += struct.pack('>H', song & 0xffff) + stage
    return out


def sn_comp_store(comp, pid, name, dancer, stage, score):
    """Keep one SuperNOVA tournament STAGE result. Returns the player's total.

    A 0x5006 is one stage: player, competition, stage number (1-based) and the
    value the competition's rule selects, which is the score under rule 0. The
    board ranks by the sum of each player's best score per stage. results.py
    owns this once its SQLite store is deployed; until then it lives in STATE.
    """
    if hasattr(results, 'sn_comp_record'):
        results.sn_comp_record(comp, pid, name, stage, score)
        mine = [r for r in sn_comp_rows(comp) if r['player'] == pid]
        return mine[0]['score'] if mine else score
    with STATE_LOCK:
        c = STATE.setdefault('sn_comp', {}).setdefault(str(comp), {})
        e = c.setdefault(str(pid), {'stages': {}})
        e['name'], e['dancer'] = name, dancer
        if score > e['stages'].get(str(stage), -1):
            e['stages'][str(stage)] = score
        e['total'] = sum(e['stages'].values())
        state_save()
        return e['total']


def sn_comp_rows(comp, limit=100):
    """One competition's board: dicts of rank, player, name, dancer, score
    (the total) and stages, best first."""
    if hasattr(results, 'sn_comp_board'):
        rows = [dict(r) for r in results.sn_comp_board(comp, limit)]
        with STATE_LOCK:
            for r in rows:
                pf = find_player(pid=r['player'])
                r.setdefault('dancer', (pf or {}).get('dancer', 0))
        return rows
    with STATE_LOCK:
        c = STATE.get('sn_comp', {}).get(str(comp), {})
        ents = sorted(((int(p), dict(e)) for p, e in c.items()),
                      key=lambda pe: (-pe[1].get('total', 0), pe[0]))
    return [{'rank': i + 1, 'player': p, 'name': e.get('name', ''),
             'dancer': e.get('dancer', 0), 'score': e.get('total', 0),
             'stages': len(e.get('stages', {}))}
            for i, (p, e) in enumerate(ents[:limit])]


def sn_competitions(args, now):
    """Every SuperNOVA competition the server knows about, open or not.

    From sn_competitions.json beside state.json when that file exists, or
    from --sn-comp-file. It is read on every request, so it can be edited
    without a restart. Each entry:

        {"id": 3, "name": "MARATHON MIX", "songs": [30, 35, 40],
         "start_days": -1, "length_days": 30}

    start_days is relative to now (negative means already open); absolute
    unix "start" and "end" override it. Without the file, the --sn-comp flags
    give one open competition and optionally one future one, as before.
    """
    path = args.sn_comp_file or (
        os.path.join(os.path.dirname(STATE_PATH), 'sn_competitions.json')
        if STATE_PATH else '')
    if path and os.path.exists(path):
        try:
            with open(path, encoding='utf-8') as f:
                raw = json.load(f)
            comps = []
            for e in raw[:SN_COMP_MAX]:
                start = int(e.get('start',
                                  now + e.get('start_days', -1) * 86400))
                end = int(e.get('end',
                                start + e.get('length_days', 30) * 86400))
                songs = [int(s) & 0xffff for s in e.get('songs', [0])]
                comps.append({'id': int(e['id']),
                              'name': str(e.get('name', '')),
                              'songs': songs[:SN_STAGES] or [0],
                              'start': start, 'end': end,
                              'difficulty': e.get('difficulty'),
                              'options': e.get('options')})
            return comps
        except (OSError, ValueError, KeyError, TypeError) as e:
            print('!! %s is unreadable (%s); using the --sn-comp flags'
                  % (path, e), flush=True)
    comps = []
    if args.sn_comp == 'open':
        comps.append({'id': 1, 'name': args.sn_comp_name,
                      'songs': args.sn_comp_songs,
                      'start': now - args.sn_comp_back,
                      'end': now + args.sn_comp_ahead})
    if args.sn_comp_future > 0:
        start = now + args.sn_comp_future
        comps.append({'id': 2,
                      'name': args.sn_comp_future_name
                      or (args.sn_comp_name + ' 2'),
                      'songs': args.sn_comp_songs,
                      'start': start, 'end': start + args.sn_comp_ahead})
    return comps


# ── The two RC PLAY requests, entering a challenge and posting a result ────
# Read out of the builders in DATA07 on 2026-09-13. Both are pure client->server
# and both were being logged as an undecoded hex blob.
#
# 0x5004 GetRCEntry   builder 0x00857e00, FIVE bytes:
#       s32  <- **(u32 **)0x01045edc      the selected player file's id; every
#                                         RC, log and ranking RPC sends the same
#                                         word, so it is the account key
#       u8   <- DAT_0104bf34              WHICH FEATURED CARD, 0 or 1. The RC
#                                         tab's cursor handler (0x00261828,
#                                         0x00261888) only ever does
#                                         `v = (v + 1) & 1`, so it is the
#                                         left/right toggle between the two
#                                         cards the 0x5000 selector calls
#                                         (0,0) and (1,0) -- not an id-list index.
#
# 0x5006 GetRCRegist  builder 0x00857d40, SIXTEEN bytes -- the result upload:
#       s32  <- the same player-file id
#       s32  <- DAT_00644a6c    = PLAY+0x15c   SCORE
#       s32  <- DAT_00644944    = PLAY+0x34    play time in milliseconds
#       s16  <- DAT_00644b44    = PLAY+0x234   MAX COMBO
#       s16  <- DAT_0064492c == 2 ? DAT_00644952        (PLAY+0x42)
#                                 : DAT_00644954 + 1    (PLAY+0x44), clamped >=0
#
# PLAY is the per-player play record at 0x00644910, stride 0x5427c, two players
# (the stride is spelled out by the init loop decompiled in out/x2_offline.log).
# `DAT_0064492c` is PLAY+0x1c, the play STYLE: the same init sets it to 1 or 2
# alongside the online-mode global [0x006f1698], so the last field is chosen by
# style and the `+1` is a 0-based counter made 1-based -- a stage number.
#
# TWO OF THE FOUR ARE SETTLED, by exact match against the results screen:
# PLAY+0x15c is the SCORE and PLAY+0x234 is the MAX COMBO. A play scoring
# 015945888 with 59 max combo sent exactly 15945888 and 59.
#
# PLAY+0x34 looks like elapsed play time in milliseconds. Two samples agree
# with that and nothing else: 118101 for a full song, 15965 for one failed
# almost immediately. It is not shown on the results screen, so it has not been
# matched against anything, only inferred.
#
# The last field has been 0 in every sample so far.
#
# THE ORIGINAL NOTE, KEPT BECAUSE THE METHOD IS THE POINT: They are only ever written
# through a base pointer from an overlay, so no string or label names them
# statically. They do not need to be guessed: the client SENDS them, so one
# real Ranking Challenge play labels all four at once -- a score is six or seven
# digits, a stage is 1..10, a combo is in the hundreds. That is what this
# decoder is for. Follow the project's own rule and let the client tell us.
def describe_rc_play_request(opcode, payload):
    """Decode 0x5004 GetRCEntry / 0x5006 GetRCRegist into log lines."""
    out = ['0x%04x %s request %s'
           % (opcode, 'GetRCEntry' if opcode == 0x5004 else 'GetRCRegist',
              payload.hex())]
    if opcode == 0x5004:
        if len(payload) < 5:
            out.append('!! short: expected 5 bytes, got %d' % len(payload))
            return out
        ident, card = struct.unpack('>iB', payload[:5])
        out.append('ENTER challenge: player id %d, featured card %d' % (ident, card))
        if card > 1:
            out.append('!! card %d -- the cursor only ever produces 0 or 1' % card)
        return out
    if len(payload) < 16:
        out.append('!! short: expected 16 bytes, got %d' % len(payload))
        return out
    ident, score, ms, combo, stage = struct.unpack('>iiihh', payload[:16])
    out.append('REGIST result: player id %d' % ident)
    out.append('   score %d, max combo %d, %d ms (%d.%03ds), stage field %d'
               % (score, combo, ms, ms // 1000, ms % 1000, stage))
    return out


def parse_ranking_request(payload):
    """The 0x6000 body, from the builder at 0x00857bf0:
        u8 type (<3) / u16 period (-2..60) / u8 (<2) / u32 start / u32 count
    `type` selects WHICH board -- head-to-head, point or RC -- which is the
    only thing distinguishing the three ranking RPCs on the wire."""
    if len(payload) < 12:
        return None
    return {'type': payload[0],
            'period': struct.unpack_from('>h', payload, 1)[0],
            'flag': payload[3],
            'start': struct.unpack_from('>I', payload, 4)[0],
            'count': struct.unpack_from('>I', payload, 8)[0]}


# ── Player options, a 32-byte blob the CLIENT hands us ──────────────────────
# 0x4105 GetPlayerOption is `u32 status` + **32 fixed bytes** (parser 0x0085a090
# -> ctx+0x2b8e8; note the status is read into a stack local and thrown away).
# 0x4106 SavePlayerOption sends the same blob back the other way.
#
# This is the cheap way to learn the option layout. Sweeping the RC entry bytes
# by hand froze the game twice, because they are indices with small legal
# ranges. The client already knows every legal value -- so let it tell us:
# change one setting in the OPTIONS menu, let it save, and diff the blob.
# `--log-options` prints each blob with a diff against the previous one.
OPTION_BLOB_LEN = 32


def playeroption_body(blob=None, status=0):
    """The 0x4105 body -- u32 status + exactly 32 bytes."""
    b = bytes(blob or b'')[:OPTION_BLOB_LEN].ljust(OPTION_BLOB_LEN, bytes(1))
    return struct.pack('>I', status) + b


def diff_blobs(old, new):
    """Byte offsets that changed, as 'off: old -> new'."""
    if not old or len(old) != len(new):
        return []
    return ['+0x%02x: %d -> %d' % (i, a, b)
            for i, (a, b) in enumerate(zip(old, new)) if a != b]


def ranking_entry_sn(rank, name, ident=0, dancer=0):
    """One SuperNOVA `0x6002` ranking row -- **45 bytes**, not Extreme 2's 49.

    Parser `0x0026dbc0`, a read-until-empty loop:

        s32 rank / s32 / char[16] name / u8 dancer / s32 x5

    The four-byte difference from Extreme 2's row is enough to leave a partial
    record on the end of the board, and the loop reads it: two real players
    drew four rows on screen, the last two nameless "NO DATA" (2026-09-14).

    The screen prints a rank number, the dancer icon, the name and four
    counters labelled MATCH / WIN / LOSE / DRAW, so four of the five trailing
    s32 are those. WHICH four, and in what order, is not established -- Extreme
    2's equivalent famously runs WIN, DRAW, LOSS while the UI prints
    WIN / LOSS / DRAW, so the order here is not worth guessing. All five are
    served as zero until a real result exists to put in them.
    """
    nm = (name or '').encode('ascii', 'replace')[:16].ljust(16, bytes(1))
    return (struct.pack('>i', rank)
            + struct.pack('>i', ident)
            + nm
            + bytes([dancer & 0xff])
            + struct.pack('>iiiii', 0, 0, 0, 0, 0))


def parse_setmyaddr(payload):
    """The 0x411a SetMyAddr body -- 39 bytes, the client's P2P candidate pair.

    From the builder at 0x0085994c:
        u8 / 16 fixed bytes / u16 BE / 16 fixed bytes / u16 BE / u16 BE

    Observed live, with the client behind an emulator's virtual network:
        00 | "192.0.2.100" | 5730 | "10.0.0.5" | 5730 | 177
    i.e. the PS2's own address inside that virtual network, then the address
    the server sees the connection from: a local/public candidate pair, which
    is what the STUN step exists to produce. Gameplay is peer-to-peer, so this
    is the value a private server MUST relay to the opponent; nothing else in
    the protocol carries it.
    """
    if len(payload) < 39:
        return None
    def s16(o):
        return payload[o:o + 16].split(b'\x00')[0].decode('ascii', 'replace')
    return {'flag': payload[0],
            'local': s16(1), 'local_port': struct.unpack_from('>H', payload, 17)[0],
            'public': s16(19), 'public_port': struct.unpack_from('>H', payload, 35)[0],
            'tail': struct.unpack_from('>H', payload, 37)[0]}


def build_match_record(opponent, tail=None):
    """The `0x44b0` body -- 61 bytes. THE MATCH MESSAGE.

    This is what tells a searching client who its opponent is and where to find
    it, and it is the piece that was missing for the whole project. Pushed
    unsolicited on the lobby connection (slot 2) while the client is
    advertising a room, it moves the client out of "searching for opponent".

    Parser `0x0085a190`, called from the slot-2 dispatch at `0x0085bf80` with
    `a1 = ctx + 0x2a338`. Wire order is the parser's CALL order, which is NOT
    the struct order:

    | wire | size | struct   | is                                    |
    |------|------|----------|---------------------------------------|
    | u32  |  4   | R+0x08   | opponent player id                    |
    | str  | 16   | R+0x0c   | opponent NAME                         |
    | str  | 16   | R+0x30   | opponent LOCAL address                |
    | u16  |  2   | R+0x42   | opponent LOCAL port                   |
    | str  | 16   | R+0x1d   | opponent PUBLIC address               |
    | u16  |  2   | R+0x2e   | opponent PUBLIC port                  |
    | u8   |  1   | R+0x00   | ? -> DAT_0104c094                     |
    | u8   |  1   | R+0x01   | ? (not read by the bridge)            |
    | u16  |  2   | R+0x04   | ? -> FUN_001e7060() -> DAT_0104c090   |
    | u8   |  1   | R+0x02   | ? (not read by the bridge)            |

    The local/public split is not a guess. `FUN_00235d40` (the lobby->versus
    bridge) runs BOTH strings through `inet_addr` (`0x00852b60`), and the peer
    setup at `0x002c33a8` then compares OUR public address (`0x0104c00c`)
    against the one from `R+0x1d`: equal means both PS2s are behind the same
    NAT, so it dials the `R+0x30`/`R+0x42` pair instead. That is a textbook
    hairpin check, which fixes which field is which -- and it mirrors
    `0x411a SetMyAddr` exactly, local pair first, so the server can simply echo
    an opponent's SetMyAddr values straight back out in the same relative order.
    """
    ep = (opponent.get('endpoint') or {}) if opponent else {}

    def s16(v):
        return (v or '').encode('ascii', 'replace')[:16].ljust(16, bytes(1))

    # The four TAIL fields, in wire order: u8 R+0x00, u8 R+0x01, u16 R+0x04,
    # u8 R+0x02. IDENTIFIED 2026-08-28 by following the two the lobby->versus
    # bridge FUN_00235d40 copies out, into the play block FUN_00237270 builds
    # and FUN_00233f60 consumes:
    #
    #   R+0x00 -> DAT_0104c094 -> play block +0x0c -> **_DAT_006f1698, THE
    #     ONLINE GAME MODE**, through a permutation: 0 -> 1, 1 -> 3, 2 -> 2,
    #     3 -> 4. Every match this server has ever run used 0, i.e. mode 1.
    #     FUN_00233f60 also sets DAT_00644923 = 1 for a mode outside 2..4, so
    #     mode 1 is a real, handled case and not a fallback.
    #   R+0x04 -> FUN_001e7060() -> DAT_0104c090, +1 -> play block +0x10 ->
    #     **THE SONG THE MATCH PLAYS**, as `dance_num`. FUN_00233f60 looks it
    #     up, and when the lookup fails it prints "reset dance_num : %d < %d"
    #     (0x003044f0) and forces dance_num = 1 -- which is the client naming
    #     the field for us, and also means a bad song id here is recoverable
    #     rather than fatal.
    #
    # R+0x01 and R+0x02 are read by NOTHING. The bridge is the only consumer of
    # this record and it touches +0x00, +0x04, +0x08, +0x0c, +0x1d, +0x2e,
    # +0x30 and +0x42; neither binary materialises the offsets of the other two
    # anywhere else. They are the two fields that never meant anything.
    #
    # FUN_001e7060 is the same lookup the RC song ids go through: it reads
    # *(s16 *)(0x002e7850 + id*2), a table with exactly 80 valid entries, and
    # returns -1 for a negative id. Above 79 it walks off the end of the table
    # and the read is SIGNED, so anything >= 0x8000 is negative. Clamp rather
    # than trust input: an out-of-range index is the exact shape of value that
    # has frozen this client before.
    t = list(tail or (0, 0, 0, 0))[:4] + [0] * 4
    song = t[2] & 0xffff
    if song >= RC_SONG_IDS:
        song = 0
    if not 0 <= t[0] <= 3:                  # game mode; anything else is not a
        t[0] = 0                            # mode the client has a case for
    return (struct.pack('>I', opponent.get('id', 0))
            + s16(opponent.get('name'))
            + s16(ep.get('local')) + struct.pack('>H', ep.get('local_port', 0))
            + s16(ep.get('public')) + struct.pack('>H', ep.get('public_port', 0))
            + bytes([t[0] & 0xff, t[1] & 0xff])
            + struct.pack('>H', song)
            + bytes([t[3] & 0xff]))


def build_sn_match_record(opponent, song=0):
    """The SuperNOVA match push body -- 67 bytes. THE `0x44b0` COUNTERPART.

    Both `0x4a04` (parser `0x0026cf30`) and `0x4a13` (`0x0026cd60`) take this
    exact record; they differ only in which event flag they raise afterwards.

    **SuperNOVA does not matchmake the way Extreme 2 does.** Extreme 2 has one
    test of "last received opcode" -- `netwk+0x8d8 == 0x44b0` in
    `FUN_001e8330` -- which is why finding that one opcode unlocked the match.
    SuperNOVA keeps an ARRAY of event-flag bytes at `ctx+0x142f4`..`0x14306`:
    each push parser sets its own byte to 1, and `netlby_mas4` polls the byte,
    acts on it, and clears it. `tools/snblocks.py` prints the whole table.

    That difference has a practical consequence worth stating plainly: **the
    Extreme 2 push-timing trap does not apply here.** `netwk+0x8d8` is a single
    word that every arriving message overwrites, which is why `0x4412` has to
    be delayed. A flag byte is not overwritten by the next message -- only the
    overlay clears it, after it has acted -- so a SuperNOVA push cannot be lost
    by arriving too close to a reply. `--sn-pair-delay` exists to test that
    claim, not because anything is known to need it.

    The record fills TWO structures before the flag goes up, which is why it is
    one message and not two:

        ctx+0x1422c   the match record   (the song, and three unread fields)
        ctx+0x141b0   the opponent record (id, name, dancer, and the stats)

    Wire order is the parser's call order:

    | wire | size | lands at        | is                                    |
    |------|------|-----------------|---------------------------------------|
    | u32  |  4   | ctx+0x2350      | status                                |
    | s32  |  4   | match  +0x14    |                                       |
    | u16  |  2   | match  +0x1a    | **the song**                          |
    | u8   |  1   | match  +0x18    |                                       |
    | s32  |  4   | match  +0x1c    |                                       |
    | u8   |  1   | *a stack local* | read and DROPPED -- reaches nothing   |
    | u16  |  2   | oppo   +0x50    |                                       |
    | s32  |  4   | oppo   +0x18    | opponent **id**                       |
    | str  | 16   | oppo   +0x1c    | opponent **name**                     |
    | u8   |  1   | oppo   +0x2d    | opponent **dancer**                   |
    | s32  |  4   | oppo   +0x30    |                                       |
    | s32  |  4   | oppo   +0x34    |                                       |
    | s32  |  4   | oppo   +0x38    |                                       |
    | s32  |  4   | oppo   +0x3c    |                                       |
    | s32  |  4   | oppo   +0x40    |                                       |
    | u8   |  1   | oppo   +0x44    |                                       |
    | s32  |  4   | oppo   +0x48    |                                       |
    | u16  |  2   | oppo   +0x4c    |                                       |
    | u8   |  1   | oppo   +0x4e    |                                       |

    The id / name / dancer naming is not a guess about those three: the
    opponent record has the same field order as one `0x4222` player-list entry
    shifted by 0x18 (`s32` id, `char[16]` name, `u8` dancer, then the stats),
    and the consumer at `0x00a47938` copies exactly those out. The unnamed
    numeric fields are the player's stats and are served as zero.

    The consumer is blunt, and it is what makes these two opcodes the match
    message rather than just another push:

        if      (ctx+0x142fd == 1) { scene->0x18 = 1; }        // 0x4a04
        else if (ctx+0x142fe == 1) { scene->0x18 = 2;          // 0x4a13
            scene->+0x04 = (s16) match+0x1a;                   //   the song
            strncpy(scene->+0xa9, oppo+0x1c, 16);              //   the name
            ... the rest of the opponent record ... }

    So the two opcodes SELECT A MODE the same way Extreme 2's `0x44b0` tail
    field `R+0x00` does, and only the `0x4a13` path copies the opponent out.
    That is why `--sn-match-push` defaults to `0x4a13`.

    UNVERIFIED against the client. Every offset here is read out of
    `SLUS_213.77` and `DATA04.BIN`; none of it has been put in front of the
    game. Serving a wrong value in an unnamed field is the likely failure, and
    on this client that shows up as a freeze rather than an error.
    """
    def s16(v):
        return (v or '').encode('ascii', 'replace')[:16].ljust(16, bytes(1))

    o = opponent or {}
    # The song is a raw index here, NOT put through the 0x002e7850 table the
    # Extreme 2 record and the RC ids go through -- that table is Extreme 2's.
    # Nothing bounds-checks this one in the parser, so clamp to a u16 and leave
    # the range question to whoever runs the experiment.
    return (struct.pack('>I', 0)                 # status
            + struct.pack('>i', 0)               # match +0x14
            + struct.pack('>H', song & 0xffff)   # match +0x1a  THE SONG
            + bytes([0])                         # match +0x18
            + struct.pack('>i', 0)               # match +0x1c
            + bytes([0])                         # dropped on the floor
            + struct.pack('>H', 0)               # oppo  +0x50
            + struct.pack('>i', o.get('id', 0))  # oppo  +0x18  id
            + s16(o.get('name'))                 # oppo  +0x1c  NAME
            + bytes([o.get('dancer', 0) & 0xff])  # oppo +0x2d  dancer
            + struct.pack('>iiiii', 0, 0, 0, 0, 0)   # oppo +0x30..+0x40
            + bytes([0])                         # oppo  +0x44
            + struct.pack('>i', 0)               # oppo  +0x48
            + struct.pack('>H', 0)               # oppo  +0x4c
            + bytes([0]))                        # oppo  +0x4e


def build_sn_join_record(player):
    """The `0x4325` body -- 50 bytes. **A PLAYER JOINED YOUR ROOM.**

    Parser `0x0026f9b0`. This is the other half of matchmaking and the piece
    the host was missing: `0x4a13` moves the SEARCHER into the match, and this
    moves the HOST. Observed 2026-09-13 -- a searcher matched into a room ran
    all the way to the results screen while the host sat on the room screen
    with no start option and eventually sent `0x4340 OutRoom`. The host had
    received the same `0x4a13` and ignored it, because the flag that opcode
    raises is only polled on the searching path.

    The record is **exactly the opponent-record tail of `0x4a13`**, into the
    same context offsets -- `ctx+0x141c8` onward -- with no room fields at all,
    which is what makes it "here is a player" rather than "here is a match":

        s32 id / char[16] name / u8 dancer / s32 x5 / u8 / s32 / u16 / u16

    Its flag is `ctx+0x142ff`, and the consumer at `0x00a53b88` is the state
    change the host needs:

        if (flag == 1 && !s0 && s1->0x64 == 0) {
            s1->0x64 = 1; s1->0x54 = 7; [s1->0x38]->0x8ea = 1; s1->0x28 = 1; }

    The second consumer, `0x00a57bf8`, reads `ctx+0x141b0` -- the opponent
    record this very message fills.

    UNVERIFIED: the layout is read out of the binary and the consumers are
    identified, but the host side has not yet been driven through a match.
    """
    def s16(v):
        return (v or '').encode('ascii', 'replace')[:16].ljust(16, bytes(1))

    p = player or {}
    return (struct.pack('>i', p.get('id', 0))          # +0x141c8
            + s16(p.get('name'))                       # +0x141cc  NAME
            + bytes([p.get('dancer', 0) & 0xff])       # +0x141dd  dancer
            + struct.pack('>iiiii', 0, 0, 0, 0, 0)     # +0x141e0..+0x141f0
            + bytes([0])                               # +0x141f4
            + struct.pack('>i', 0)                     # +0x141f8
            + struct.pack('>H', 0)                     # +0x141fc
            + struct.pack('>H', 0))                    # +0x14200


def build_sn_joinreply_record(host, song):
    """The `0x4324` body -- 55 bytes. The reply to `0x4323`, JOIN A ROOM.

    `0x4323` is what browsing and picking a room sends: 12 bytes,
    `s32 me / s32 the room owner / s32 0` (observed 2026-09-13,
    `00 00 00 0b  00 00 00 0a  00 00 00 00`). The reply was going out EMPTY,
    which is why a joiner landed in the room with the song showing as random --
    the parser bounds-checks the read cursor and not the message, so every
    field came from whatever the buffer last held.

    Parser `0x0026fb10`. It is the `0x4325` player record with a status in
    front and **the song on the end**:

        u32 status
        s32 id / char[16] name / u8 dancer / s32 x5 / u8 / s32 / u16 / u8
                                                     -> ctx+0x141c8 onward
        u16 song                                     -> ctx+0x14246

    and `ctx+0x14246` is the same match-record song field `0x4a13` fills, which
    is what ties the joiner's screen to the room it just entered.
    """
    def s16(v):
        return (v or '').encode('ascii', 'replace')[:16].ljust(16, bytes(1))

    h = host or {}
    return (struct.pack('>I', 0)                       # status
            + struct.pack('>i', h.get('id', 0))        # +0x141c8
            + s16(h.get('name'))                       # +0x141cc
            + bytes([h.get('dancer', 0) & 0xff])       # +0x141dd
            + struct.pack('>iiiii', 0, 0, 0, 0, 0)     # +0x141e0..+0x141f0
            + bytes([0])                               # +0x141f4
            + struct.pack('>i', 0)                     # +0x141f8
            + struct.pack('>H', 0)                     # +0x141fc
            + bytes([0])                               # +0x141fe
            + struct.pack('>H', song & 0xffff))        # +0x14246  THE SONG


def build_sn_peeraddr_record(player, dial=None):
    """The `0x4b01` body -- 44 bytes. **WHERE THE OPPONENT IS.**

    Parser `0x0026d900`, and it is the missing half of a SuperNOVA match:

        u32 status
        char[16] -> ctx+0x14202   u16 -> ctx+0x14214     candidate pair 1
        char[16] -> ctx+0x14216   u16 -> ctx+0x14228     candidate pair 2
        s32      -> ctx+0x141c8   the opponent's player id

    `netlby_mas4` reads those two string offsets at `0x00a4a988` and
    `0x00a4a9d0`. Nothing else in SuperNOVA's protocol carries an address:
    the match record `0x4a13`, the join reply `0x4324` and the room record all
    have none, so this request is how a client finds its opponent.

    Observed 2026-09-13: two clients matched, both reached the play screen and
    played the whole song with **no inputs reaching each other**, because
    `0x4b01` was going out empty and neither ever learned where the other was.

    **PAIR 1 IS THE PUBLIC PAIR AND PAIR 2 IS THE LOCAL ONE.** This is the
    opposite of `0x411a SetMyAddr` and of Extreme 2's `0x44b0`, both of which
    put the local candidate first, and assuming the convention carried over is
    what made the first attempt useless. The consumer `FUN_00a4a4f0` spells it
    out -- it copies our record into the connect block as

        blk+0x370  (local port)   <- ctx+0x14228     pair 2
        blk+0x372  (public port)  <- ctx+0x14214     pair 1
        blk+0x374  (LOCAL addr)   <- ctx+0x14216     pair 2
        blk+0x385  (PUBLIC addr)  <- ctx+0x14202     pair 1

    and `FUN_0027bb30` then does the hairpin check on those slots:

        if (my_public == blk+0x385) dial blk+0x374 : blk+0x370   // same NAT
        else                        dial blk+0x385 : blk+0x372

    Served local-first, `blk+0x385` received 192.0.2.100 -- the address inside
    PCSX2's virtual network -- so the client dialled a host it could never
    reach and the two consoles never connected, which is exactly what a whole
    song played with no inputs crossing looked like.

    With the pairs the right way round the hairpin check is also meaningful
    again: two consoles on one PCSX2 share a local address but have distinct
    public ones, so the comparison fails and the public pair is used, which is
    the reachable one.
    """
    ep = ((player or {}).get('endpoint') or {})
    if dial is not None:
        # Relayed: BOTH candidates point at the relay, so it does not matter
        # which branch the hairpin check takes -- the console dials the relay
        # either way. See server/udprelay.py.
        ep = {'public': dial[0], 'public_port': dial[1],
              'local': dial[0], 'local_port': dial[1]}

    def s16(v):
        return (v or '').encode('ascii', 'replace')[:16].ljust(16, bytes(1))

    return (struct.pack('>I', 0)
            # pair 1 -> blk+0x385 / blk+0x372, which the connect treats as the
            # PUBLIC candidate
            + s16(ep.get('public')) + struct.pack('>H', ep.get('public_port', 0))
            # pair 2 -> blk+0x374 / blk+0x370, the LOCAL candidate
            + s16(ep.get('local')) + struct.pack('>H', ep.get('local_port', 0))
            + struct.pack('>i', (player or {}).get('id', 0)))


def parse_create_playerfile(payload):
    """The 0x3020 NewCreatePlayerFile request body -- 18 bytes.

    From the builder at 0x0085737c: `u8` / `16 fixed bytes` / `u8`. Observed live
    2026-08-27 as `00 | "Cas" + NULs | 0x12`. The leading u8 is the slot the file
    is being created in (the 0x3012 parser uses the same value as its entry
    index); the trailing u8 is the chosen dancer.
    """
    if len(payload) < 18:
        return None
    return {'slot': payload[0],
            'name': payload[1:17].split(b'\x00')[0].decode('ascii', 'replace'),
            'dancer': payload[17]}


class Session(threading.Thread):
    def __init__(self, conn, addr, args, keybox, local_port=0):
        super().__init__(daemon=True)
        self.conn = conn
        self.addr = addr
        self.local_port = local_port
        # Which GAME is on the other end. SuperNOVA and Extreme 2 share this
        # server but differ in several payload layouts (0x2002, 0x3012), so
        # every divergence keys off this one flag. The gate connection is
        # distinguishable by port (19573 vs 9573); the account connection is
        # only distinguishable because we hand SuperNOVA its own port in the
        # SvrList -- see --sn-svr-port.
        self.is_sn = local_port in args.sn_ports
        self.args = args
        self.keybox = keybox
        self.buf = b''
        self.serial = 0
        self.acct = None          # 0x3003 credential blob, hex
        self.login_user = None    # 0x3003 username field (32B), hex, NULs trimmed
        self.login_digest = None  # 0x3003 password digest (bytes 32..48), hex
        self.player = None        # player file selected on this connection
        self.send_lock = threading.Lock()
        self.in_room = False
        self.sn_room = None   # SuperNOVA: the 0x4330 CreateRoom body, while it lasts
        self.friend_target = None  # name echoed back by 0x4522 / 0x4528
        self.sn_searching = False  # sent 0x4a00, no 0x4a02 yet
        self.pending_join_host = None  # 0x4323: push 0x4325 after the reply
        self.relay_pair = None     # udprelay.Pair for this match
        self.relay_dial = None     # (addr, port) THIS console should dial
        self.pending_sn_search = False
        self.pending_pair = False
        self.peer = None          # paired opponent Session, once 0x44b0 is sent
        self.rc_sel = (0, 0)      # last 0x5000 GetRCInfo selector (two u8s)
        self.rc_try_req = b''     # last 0x5002 GetRCTrycount body
        self.rc_card = 0          # featured card of the last 0x5004 entry
        self.rc_songs = {}        # challenge -> song ids served in 0x5001
        self.rank_req = None      # last 0x6000 ranking request, parsed
        self.endgame = None       # our 0x4430 report, until the peer's arrives
        self.endgame_peer = None  # who we were playing when we reported
        self.start_ready = False  # has sent 0x4410 GetStartStaus
        self.start_sent = False   # has been given the 0x4412 PLAY START gate
        self.start_held = False   # SuperNOVA: 0x4411 withheld until the peer readies
        self.sn_comp_sel = None   # SuperNOVA: competition id from the last 0x5000
        self.sn_board_req = (None, 100)   # SuperNOVA: (competition, rows), 0x5040
        self.sn_standing_comp = None      # SuperNOVA: competition from 0x5020

    def log(self, *a):
        print('[%s:%d ->:%d]' % (self.addr[0], self.addr[1], self.local_port),
              *a, flush=True)

    def run(self):
        self.log('connected  *** on port %d ***' % self.local_port)
        self.conn.settimeout(1.0)
        try:
            while True:
                try:
                    data = self.conn.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                self.buf += data
                self.pump()
        except OSError as e:
            self.log('socket closed:', e)
        finally:
            self.sn_part('disconnected')
            self.leave_room()
            self.leave_lobby()
            self.log('disconnected')
            self.conn.close()

    def pump(self):
        if self.keybox['key'] is None:
            key = recover_key(self.buf)
            if key is None:
                self.log('key not recovered yet (%d bytes buffered); '
                         'waiting for a complete frame' % len(self.buf))
                return
            self.keybox['key'] = key
            self.log('*** XOR KEY RECOVERED: %s ***' % binascii.hexlify(key).decode())
            with open(self.args.keyfile, 'wb') as f:
                f.write(key)
            self.log('    saved to %s' % self.args.keyfile)

        key = self.keybox['key']
        while len(self.buf) >= HDR:
            hdr = xor(self.buf[:HDR], key)
            opcode, length, serial = struct.unpack('>HHI', hdr[:8])
            if length > MAX_PAYLOAD:
                self.log('!! length %d > %d -- wrong key or desync; dropping buffer'
                         % (length, MAX_PAYLOAD))
                self.buf = b''
                return
            if len(self.buf) < HDR + length:
                return  # wait for the rest of the frame
            payload = xor(self.buf[HDR:HDR + length], key, HDR)
            self.buf = self.buf[HDR + length:]
            ok = digest(hdr[0:8], payload) == hdr[8:HDR]
            self.log('RECV opcode=0x%04x %-30s len=%-4d serial=0x%08x md5=%s'
                     % (opcode, name_of(opcode), length, serial, 'ok' if ok else 'BAD'))
            if length:
                print(hexdump(payload), flush=True)
            self.on_frame(opcode, serial, payload)

    def on_frame(self, opcode, serial, payload):
        if not self.args.reply_empty:
            return
        # Header-only replies (length == 0 is explicitly legal -- the client
        # jumps straight to state 7, "message complete", without reading a
        # payload). For a multi-part RPC we must send the WHOLE sequence: the
        # opener alone only resets the client's timeout and leaves it waiting.
        if opcode == 0x4400:
            self.relay_peer(payload)
            return
        if opcode in NO_REPLY:
            self.log('     (0x%04x is a notification -- not replying)' % opcode)
            return
        self.observe(opcode, payload)
        if opcode == 0x4410 and self.is_sn and self.hold_sn_start():
            return
        seq, known = response_sequence(opcode, self.is_sn)
        if not known and opcode not in QUIET_GUESS:
            self.log('!! request 0x%04x is not in REQUEST_RESPONSES -- replying '
                     '0x%04x as a GUESS (+1). Add the real mapping from '
                     'tools/reqmap.py.' % (opcode, seq[0]))
        for i, resp in enumerate(seq):
            # A DATA response may need MORE THAN ONE FRAME. The payload cap is
            # 1024 bytes and the 0x8002 record is 13, so the full 79-song
            # availability list is 1027 -- two over. The client accumulates
            # records across messages (the parser resumes from its own count),
            # so several DATA frames inside one group are legal; payload_for
            # returns a list for those opcodes and one body for everything else.
            bodies = self.payload_for(resp, opcode, payload)
            if not isinstance(bodies, list):
                bodies = [bodies]
            for j, body in enumerate(bodies):
                with self.send_lock:
                    self.serial += 1
                    self.conn.sendall(build(resp, self.serial, body,
                                            self.keybox['key']))
                if i == len(seq) - 1:
                    tag = 'terminator'
                else:
                    tag = 'part %d/%d' % (i + 1, len(seq))
                    if len(bodies) > 1:
                        tag += ' chunk %d/%d' % (j + 1, len(bodies))
                self.log('SENT opcode=0x%04x %-30s len=%-4d serial=0x%08x  (%s)'
                         % (resp, name_of(resp), len(body), self.serial, tag))
                if body:
                    print(hexdump(body), flush=True)
        # The push MUST go out AFTER the reply. netwk+0x8d8 holds "last received
        # opcode" and the notification pump tests it directly, so a push sent
        # first is overwritten by the reply before the client can act on it.
        # That is exactly what the first attempt did -- PUSH 0x4351 then SENT
        # 0x4331, and neither client reacted. The experiment was invalid, not
        # the hypothesis.
        if self.pending_pair:
            self.pending_pair = False
            self.enter_room()
        if self.pending_sn_search:
            self.pending_sn_search = False
            self.try_sn_search()
        if self.pending_join_host is not None:
            host, self.pending_join_host = self.pending_join_host, None
            if self.args.sn_host_push:
                self.log('     telling %s that %s joined (0x4325 + 0x4b01)'
                         % (host.who(), self.who()))
                with WAITING_LOCK:
                    self.peer, host.peer = host, self
                self.relay_link(host)
                host.push(0x4325, build_sn_join_record(self.player))
                # **AND WHERE THE JOINER IS.** Only the joiner ever sends
                # 0x4b00; the host never asks, so it never learns the address
                # and nothing it sends can reach anyone. Observed 2026-09-14:
                # one 0x4b00 in a whole match, from the joiner, and inputs went
                # one way at best. 0x4b01 has no in-flight request check -- it
                # is in the dispatch's unsolicited set -- so pushing it is
                # well-formed, and the host is evidently meant to be told
                # rather than to ask.
                # LATER, not in the same breath as 0x4325. The host is the
                # room owner, and its consumer (0x00a57e1c in FUN_00a57bc0)
                # takes the address only if the id at the end of 0x4b01
                # matches slot B, blk->0x3a0, which 0x4325 fills with the
                # guest. Otherwise it clears the flag and drops the record.
                # Accepting it only stores the address; the host dials once
                # its own 0x4411 arrives, which hold_sn_start times.
                self.push_later(host, 0x4b01,
                                build_sn_peeraddr_record(self.player,
                                                         host.relay_dial),
                                self.args.sn_addr_delay)
        if opcode == 0x4410:
            # BOTH games. SuperNOVA's 0x4411 only acknowledges the ready; the
            # "other player is ready" signal is 0x4412 exactly as in Extreme 2
            # (one u8 -> ctx+0x14268, read at 0x00a4a8b4).
            self.maybe_start_match()

    def try_unseen_pushes(self):
        """Fire the two push-only opcodes NOTHING has ever sent, if asked.

        `0x4222` and `0x4500` both have a parser in the slot-2 dispatch and no
        builder anywhere in the 0x00856b30 request inventory, so the client can
        only ever RECEIVE them. Both LAYOUTS are now read out of the binary
        (2026-08-28); what is still unobserved is the client's reaction.

        **0x4222 is a player-list UPDATE.** FUN_0085b020 parses one record with
        the reader sequence of a 0x4212 entry -- checked field by field, all 19,
        including the two that land past the 80-byte stride -- into a 0x50-byte
        stack copy, then walks the same 1000-entry array 0x4212 fills and either
        overwrites every entry whose id matches or, if none does, fills the
        first free one. So it is an upsert keyed on the player id, and it is how
        a real server told a lobby that somebody arrived or changed without
        making everyone re-run GetPlayerList.

        **The id must not be zero.** A free slot is one whose id is 0, and the
        match loop runs over all 1000 entries before the insert path is even
        considered: a record with id 0 matches every empty slot and fills the
        entire list with copies of it.

        `0x4500` is read in FUN_001e84c0, in the lobby tick:

            if (netwk+0x8d8 == 0x4500) {
                _DAT_0104c0b4 = (float)*(uint *)(ctx + 0x2b90c);
                _DAT_0104c0b8 |= 1;
            }

        Note the cast: the parser (FUN_008597a0) reads a big-endian u32 and the
        consumer CONVERTS that integer to float. It is not an IEEE float on the
        wire -- this used to send `struct.pack('>f', ...)`, which would have
        arrived as 1114636288 for 60.0. The value is then decremented by
        0.016683351 -- one frame at 59.94 Hz -- per tick, so the unit is
        SECONDS, and the flag clears once it falls to 60.0 or below. Values at
        or under 60 therefore arm and disarm in the same frame; use something
        larger to see anything. FUN_001e8330 dismisses a widget on the match
        path if the flag is still set, which is what makes this look like the
        "searching" countdown.

        Both are pushed AFTER a delay for the reason every push in this protocol
        needs one: `netwk+0x8d8` holds the LAST RECEIVED OPCODE, the waiting RPC
        polls it once per 60 Hz frame, and a push that lands too soon overwrites
        the reply the client is still waiting on.
        """
        jobs = []                       # of (target Session, opcode, body)
        if self.args.push_4222:
            ident = self.player.get('id', 0)
            if not ident:
                self.log('!! refusing to push 0x4222 with id 0 -- it would '
                         'match every empty slot in the list')
            else:
                rec = playerlist_entry(ident, self.who(),
                                       self.player.get('dancer', 0))
                # To EVERY other player in the lobby: this is the arrival
                # announcement the opcode exists for, and the only push that
                # can produce a visible change (a new row in their list).
                with WAITING_LOCK:
                    others = [w for w in LOBBY
                              if w is not self and w.player is not None
                              and not w.is_sn]
                jobs += [(w, 0x4222, rec) for w in others]
                # And back to ourselves, where the id already matches an entry:
                # the upsert overwrites in place, so no row should appear. That
                # is the canary -- if OUR list grows, the id match is not doing
                # what the parser says it does.
                jobs.append((self, 0x4222, rec))
        if self.args.push_4500 is not None:
            jobs.append((self, 0x4500,
                         struct.pack('>I', self.args.push_4500 & 0xffffffff)))
        # 0x5013 -- the WEEK ROLLOVER push. One u8, parser 0x008578f0, writing
        # the same ctx+0x2a383 the GetSchedule reply fills. The online scene's
        # tick tests it directly at 0x001e8540:
        #
        #     if (netwk+0x8d8 == 0x5013) {
        #         printf("UPDATE WEEK:%d===...", ctx[0x2a383]);
        #         scene->state = 0x002c0f60;      // -> 0x002c0c00
        #         DAT_0104c0b8 &= ~1;
        #     }
        #
        # THIS IS NOT A REFRESH -- IT LOGS THE PLAYER OUT. 0x002c0c00 is a
        # ten-case state machine whose own error string names it
        # "NetGameShutdownMain" (0x0030bba0): it puts up a modal, waits for the
        # confirm, calls NetPrgOutRoom (0x001df4b0) and then tears the network
        # down (0x001d3e00). So this is how a real server rotated the Ranking
        # Challenge period out from under a live lobby: announce the new week,
        # and every online client walks itself back out.
        #
        # Push it to ONE session, never to a whole lobby by accident.
        if self.args.push_5013 is not None:
            jobs.append((self, 0x5013, bytes([self.args.push_5013 & 0xff])))
        if not jobs:
            return

        def fire():
            for target, opcode, body in jobs:
                time.sleep(self.args.push_delay)
                self.log('     EXPERIMENT: pushing push-only opcode 0x%04x '
                         '(%d B) to %s -- REACTION unobserved'
                         % (opcode, len(body),
                            'self' if target is self else target.who()))
                target.push(opcode, body)

        threading.Thread(target=fire, daemon=True).start()

    def push(self, opcode, body=b''):
        """Send an UNSOLICITED frame. Serials are per-connection and the reply
        path runs on this session's own thread, so both take send_lock."""
        try:
            with self.send_lock:
                self.serial += 1
                self.conn.sendall(build(opcode, self.serial, body,
                                        self.keybox['key']))
            self.log('PUSH opcode=0x%04x %-30s len=%-4d serial=0x%08x'
                     % (opcode, name_of(opcode), len(body), self.serial))
        except OSError as e:
            self.log('push failed: %s' % e)

    def rc_now_week(self):
        """The week number the client is being shown, for filing results."""
        if self.args.rc_flag is not None:
            return self.args.rc_flag
        return rc_week(self.args.svr_time or None)[0]

    def record_rc(self, opcode, payload):
        """Keep a Ranking Challenge entry (0x5004) or result (0x5006)."""
        week, now = self.rc_now_week(), self.args.svr_time or None
        if opcode == 0x5004:
            e = results.parse_rc_entry(payload)
            if e:
                self.rc_card = e['card'] if e['card'] in (0, 1) else 0
                results.record_rc_entry(e['player'], week, self.rc_card, now)
            return
        r = results.parse_rc_regist(payload)
        if not r:
            return
        songs = self.rc_songs.get(self.rc_card) or []
        stage = r['stage']
        song = (songs[stage] if 0 <= stage < len(songs)
                else (songs[0] if songs else None))
        results.record_rc(r['player'], self.who(),
                          (self.player or {}).get('dancer', 0), week,
                          self.rc_card, r['score'], r['combo'], r['ms'],
                          stage, song, now)
        self.log('     kept: week %d, card %d, score %d, song %s'
                 % (week, self.rc_card, r['score'], song))

    def record_endgame(self, payload):
        """Keep a head-to-head result once both players have reported.

        Each side sends its own 0x4430 at the end of the song. The first report
        waits on its session and the second pairs with it; the higher score
        wins. The opponent is remembered at report time, because the pairing
        can be torn down by OutRoom before the other report arrives.
        """
        g = results.parse_endgame(payload)
        if not g or self.player is None:
            return
        me = {'player': self.player.get('id', 0), 'name': self.who(),
              'dancer': self.player.get('dancer', 0), 'score': g['score']}
        with results.LOCK:
            self.endgame, self.endgame_peer = me, self.peer
            other = self.peer
            if other is None:
                with WAITING_LOCK:
                    other = next((w for w in LOBBY if w is not self and
                                  getattr(w, 'endgame_peer', None) is self), None)
            theirs = getattr(other, 'endgame', None) if other is not None else None
            if theirs is None or getattr(other, 'endgame_peer', None) not in (self, None):
                self.log('     endgame: score %d, waiting for the opponent'
                         % g['score'])
                return
            self.endgame = other.endgame = None
            self.endgame_peer = other.endgame_peer = None
        mine, _ = results.record_h2h(self.rc_now_week(), me, theirs,
                                     self.args.svr_time or None)
        self.log('     kept: head-to-head %s %d vs %s %d, %s'
                 % (me['name'], me['score'], theirs['name'], theirs['score'],
                    mine))

    def x2_stats(self, pid):
        return results.player_stats(pid, self.rc_now_week(),
                                    self.args.svr_time or None)

    def personal_log(self, kind):
        """Records for one personal log, in wire field order."""
        pid = (self.player or {}).get('id', 0)
        now = self.args.svr_time or None
        if kind == 'HtoH':
            return [(r['week'], r['match'], r['win'], r['draw'], r['loss'])
                    for r in results.h2h_log(pid, 59, now)]
        if kind == 'Point':
            return [(r['ranking'], r['points'])
                    for r in results.point_log(pid, 59, now)]
        # RC columns: TITLE, RANKING, SCORE, TIME, COMBO and one unnamed u16.
        # The title goes out as the wire song id and the time in ms; neither
        # has been checked on screen yet.
        return [(r['song'] if r['song'] is not None else 0, r['ranking'],
                 r['score'], r['ms'], r['combo'], 0)
                for r in results.rc_log(pid, 119, now)]

    def x2_ranking_body(self, fallback_rows):
        """0x6002 rows for Extreme 2, from kept results.

        Request type 0 is head-to-head, 1 Ranking Challenge (per week and
        card) and 2 points, read from the three RPCs' calls into the 0x6000
        builder. A positive period is a week number. 0 or less is taken as all
        time, which the client has not been seen to send yet.
        """
        rq = self.rank_req or {}
        kind, period = rq.get('type', 0), rq.get('period', 0)
        card, now = rq.get('flag', 0), self.args.svr_time or None
        if kind == 1:
            board = results.rc_board(period, card, now)
        elif kind == 2:
            board = results.points_board(period, now)
        else:
            board = results.h2h_board(period, now)
        start = max(1, rq.get('start', 1))
        board = board[start - 1:start - 1 + RANKING_CAP - 1]
        if not board:
            # Nothing kept for this board yet: the online players on zero,
            # which is what every board served before results were kept.
            return b''.join(ranking_entry(i + 1, w.who(),
                                          (w.player or {}).get('dancer', 0))
                            for i, w in enumerate(fallback_rows))
        self.log('     %s board, period %d: %d row(s) from kept results'
                 % (('head-to-head', 'ranking challenge', 'points')[kind % 3],
                    period, len(board)))
        return b''.join(ranking_entry(r['rank'], r['name'], r['dancer'],
                                      values={5: r.get('win', 0),
                                              6: r.get('draw', 0),
                                              7: r.get('loss', 0),
                                              8: r.get('points', 0),
                                              9: r.get('rc_score', 0)})
                        for r in board)

    def advertised_host(self):
        """The address to put in SvrInfo and SvrList, as the client sees us.

        The client has just connected, so the local end of that socket is by
        definition an address it can reach. Echoing it back means a server
        needs no configuration to work on any network, which is what "auto"
        selects.

        Except behind a port forward, where the local end is a LAN address an
        internet client cannot dial. A client arriving from a global address is
        given our public address instead (publicaddr.py), so one server serves
        the LAN and the internet at once. An explicit --svr-addr / --svr-host
        still wins, for every client.
        """
        want = self.args.svr_host or self.args.svr_addr
        if want and want != 'auto':
            return want
        try:
            local = self.conn.getsockname()[0]
        except OSError:
            return '127.0.0.1'
        if PUBLIC is None:
            return local
        return PUBLIC.for_client(self.addr[0], local)

    def who(self):
        return self.player['name'] if self.player else '?'

    def enter_room(self):
        with WAITING_LOCK:
            if self not in WAITING:
                WAITING.append(self)
            self.in_room = True
            others = [w for w in WAITING if w is not self and w.in_room
                      and w.peer is None]
            partner = others[0] if (others and self.peer is None) else None
            if partner is not None:
                self.peer, partner.peer = partner, self
            advertising = len(WAITING)
        self.log('     waiting in room (%d advertising)' % advertising)
        if partner is None:
            return
        if self.args.pair_sweep:
            self.log('     PAIRING with %s -- SWEEP mode, pushing %s'
                     % (partner.who(),
                        ' '.join('0x%04x' % o for o in self.args.pair_push)))
            threading.Thread(target=self._sweep, args=(partner,),
                             daemon=True).start()
            return
        # THE MATCH PUSH. `0x44b0` is the message the whole project was missing.
        #
        # FUN_001e8330, the online-mode-1 handler, is four lines:
        #
        #     if (_DAT_0104bf0c == 1 && netwk+0x8d8 == 0x44b0) { ...
        #         DAT_0104bd08 = 2; }        // -> the lobby->versus bridge
        #
        # `netwk+0x8d8` is "last received opcode" and `_DAT_0104bf0c` is set to
        # 1 in exactly one place -- FUN_001f0c50, the searching task, the same
        # one that calls CreateRoom. So an unsolicited 0x44b0, delivered while
        # the client is advertising, is precisely the join notification, and
        # every push-only opcode swept earlier (0x4351/0x441c/0x4450/0x44a1)
        # was inert because none of them is tested anywhere on this path.
        #
        # After that: bridge FUN_00235d40 reads the opponent record we just
        # sent out of ctx+0x2a338 -> NetGameVs_LobbyMain -> NetGamePrgGetOption
        # (peer type 4 over the 0x4400 relay) -> NetGameVs_PlayMain -> the match
        # state machine -> "PLAY START".
        if self.is_sn or partner.is_sn:
            self.pair_sn(partner)
            return
        self.log('     PAIRING with %s -- pushing 0x44b0 both ways'
                 % partner.who())
        for a, b in ((self, partner), (partner, self)):
            if b.player is None:
                a.log('!! partner %s has no player file -- 0x44b0 will be empty'
                      % b.who())
            a.push(0x44b0, build_match_record(b.player or {},
                                               self.args.match_tail))

    def push_later(self, sess, opcode, body, delay):
        """Push after a delay, off the receive thread.

        The recurring trap in this protocol: a message the client is not yet in
        a state to accept is not queued, it is discarded. Delaying is the only
        lever the server has.
        """
        if delay <= 0:
            sess.push(opcode, body)
            return

        def fire():
            time.sleep(delay)
            sess.push(opcode, body)

        threading.Thread(target=fire, daemon=True).start()

    def relay_link(self, other):
        """Give this pair of consoles a relayed peer endpoint each.

        SuperNOVA dials the opponent directly (see server/udprelay.py), which
        two consoles behind one emulator cannot do. Handing each of them a
        different port on THIS server, and forwarding between the two, makes
        both connections outbound and removes the requirement entirely.

        Each side is told to dial its OWN port -- A sends to portA, and what
        arrives there goes out of portB to B.
        """
        if RELAY is None or self.relay_dial or other.relay_dial:
            return
        pair = RELAY.alloc()
        if pair is None:
            self.log('!!   udp relay pool exhausted -- falling back to the '
                     'addresses the consoles reported, which needs them to be '
                     'genuinely reachable')
            return
        # Each side gets the address IT can reach us on. They differ when one
        # console is on our LAN and the other is out on the internet.
        self.relay_pair = other.relay_pair = pair
        self.relay_dial = (self.args.relay_addr or self.advertised_host(), pair.a)
        other.relay_dial = (self.args.relay_addr or other.advertised_host(),
                            pair.b)
        self.log('     relay %s:%d <-> %s:%d for %s / %s'
                 % (self.relay_dial + other.relay_dial
                    + (self.who(), other.who())))

    def sn_comp_request(self, opcode, payload):
        """SuperNOVA tournament requests, every one a run of s32s.

            0x5004  player, competition            entering (builder 0x00269ea0)
            0x5006  player, competition, stage, score        (0x00269d60)
            0x5020  player, competition            my standing (0x00269c30)
            0x5040  competition, rows (<= 100)     the board   (0x002699a0)

        These share opcodes with Extreme 2's Ranking Challenge and nothing
        else: the bodies are different, and 0x5006 used to be logged through
        the Extreme 2 decoder as "score 1, 1 ms".
        """
        v = [struct.unpack_from('>i', payload, o)[0]
             for o in range(0, len(payload) - 3, 4)]
        if opcode == 0x5040:
            rows = min(max(v[1], 0), 100) if len(v) > 1 else 100
            self.sn_board_req = (v[0] if v else None, rows)
            self.log('     tournament board requested: competition %s, %d rows'
                     % self.sn_board_req)
            return
        comp = v[1] if len(v) > 1 else None
        if opcode == 0x5004:
            self.log('     entering tournament %s' % comp)
        elif opcode == 0x5020:
            self.sn_standing_comp = comp
        elif opcode == 0x5006 and len(v) >= 4:
            p = self.player or {}
            total = sn_comp_store(comp, v[0], p.get('name', ''),
                                  p.get('dancer', 0), v[2], v[3])
            self.log('     tournament %s: stage %d scored %d, total now %d'
                     % (comp, v[2], v[3], total))

    def sn_comp_standing(self):
        """The 0x5021 body: status, then three s32s into ctx+0x1302c..0x13034.
        Nothing in the overlays reads those three back, so the order is served
        as rank, total, entrants and logged, to be checked on screen."""
        comp = self.sn_standing_comp
        pid = (self.player or {}).get('id')
        rows = sn_comp_rows(comp) if comp is not None else []
        mine = [r for r in rows if r['player'] == pid]
        rank, total = (mine[0]['rank'], mine[0]['score']) if mine else (0, 0)
        self.log('     tournament %s standing: rank %d, total %d, %d entrant(s)'
                 % (comp, rank, total, len(rows)))
        return struct.pack('>Iiii', 0, rank, total, len(rows))

    def sn_part(self, why):
        """SuperNOVA: tell the opponent this player is gone.

        `0x4351` is a bare u32 status (parser FUN_0026f760 via 0x00271530).
        Status 0 zeroes the whole opponent record at ctx+0x141b0, including
        the id at ctx+0x141c8, and raises ctx+0x14300. Both room scenes poll
        that flag (0x00a4a858 guest, 0x00a581d0 owner), and with the id now 0
        they clear the other player's slot, drop the peer address and blank
        the opponent panel. Nothing sent it before, so a player who left or
        dropped stayed on the other screen.
        """
        if not self.is_sn or self.peer is None:
            return
        peer = self.peer
        self.relay_release()
        with WAITING_LOCK:
            if peer.peer is self:
                peer.peer = None
            self.peer = None
            for s in (self, peer):
                s.start_ready = s.start_held = s.start_sent = False
        self.log('     %s: telling %s (0x4351)' % (why, peer.who()))
        peer.push(0x4351, struct.pack('>I', 0))

    def relay_release(self):
        if self.relay_pair is not None and RELAY is not None:
            RELAY.release(self.relay_pair)
        peer = self.peer
        if peer is not None:
            peer.relay_pair = peer.relay_dial = None
        self.relay_pair = self.relay_dial = None

    def try_sn_search(self):
        """Answer an auto-search by pushing the match record for a live room.

        Browsing the room list and auto-searching are two different paths to
        the same place: the browser picks a room out of 0x4310, the searcher
        expects the server to pick one for it. Only the first was served, so
        "search for a game" ran forever while "browse" worked.

        The room's host becomes the opponent and the room's song the match
        song, so a searcher lands in the same game a browser would have joined.
        UNVERIFIED end to end -- the push itself is still the static reading
        described in build_sn_match_record.
        """
        if self.args.sn_match_push == 'off':
            return
        with WAITING_LOCK:
            hosts = [w for w in LOBBY
                     if w is not self and w.is_sn and w.sn_room is not None
                     and w.player is not None]
            host = hosts[0] if hosts else None
        if host is None:
            self.log('     auto-search: no room to match into')
            return
        song = (host.sn_room or {}).get('song', self.args.sn_match_song)
        # The searcher joins as a GUEST. FUN_00a47880 turns 0x4a04 into scene
        # mode 1 and 0x4a13 into mode 2, and FUN_00a49b70 then opens the guest
        # room scene (FUN_00a4f210) for mode 1 and the OWNER's (FUN_00a5d1c0)
        # for mode 2; 0x4a04 also files the opponent in slot A and the
        # searcher in slot B, the guest's slot. Pushing 0x4a13 here made the
        # searcher a second owner of a room the server never listed, so when
        # the real owner left it sat in an "open" room nobody could find
        # (observed 2026-09-14). --sn-search-push overrides it.
        ops = [int(self.args.sn_search_push, 0)]
        self.log('     auto-search: matching into the room held by %s '
                 '(song %d), pushing %s' % (host.who(), song,
                                 ' '.join('0x%04x' % o for o in ops)))
        with WAITING_LOCK:
            self.peer, host.peer = host, self

        def fire():
            if self.args.sn_pair_delay:
                time.sleep(self.args.sn_pair_delay)
            # The two sides need DIFFERENT messages. The searcher gets the
            # match record, which is what moved it all the way to the results
            # screen on 2026-09-13. The host is not searching -- it is sitting
            # in its own room -- and the flag 0x4a13 raises is only polled on
            # the searching path, so the host ignored it and eventually sent
            # OutRoom. 0x4325 is its counterpart: "a player joined your room".
            self.relay_link(host)
            for op in ops:
                self.push(op, build_sn_match_record(host.player, song))
            if self.args.sn_host_push:
                host.push(0x4325, build_sn_join_record(self.player))
                # LATER, not in the same breath as 0x4325. The host is the
                # room owner, and its consumer (0x00a57e1c in FUN_00a57bc0)
                # takes the address only if the id at the end of 0x4b01
                # matches slot B, blk->0x3a0, which 0x4325 fills with the
                # guest. Otherwise it clears the flag and drops the record.
                # Accepting it only stores the address; the host dials once
                # its own 0x4411 arrives, which hold_sn_start times.
                self.push_later(host, 0x4b01,
                                build_sn_peeraddr_record(self.player,
                                                         host.relay_dial),
                                self.args.sn_addr_delay)

        if self.args.sn_pair_delay:
            threading.Thread(target=fire, daemon=True).start()
        else:
            fire()

    def pair_sn(self, partner):
        """The SuperNOVA match push. See build_sn_match_record.

        Until now this path pushed `0x44b0` at SuperNOVA clients too, because
        `--pair` keys on `0x4330 CreateRoom` and BOTH games send that. SuperNOVA
        has no `0x44b0` parser anywhere in its dispatch, so the message was
        silently dropped -- not an error, just a push that could never do
        anything. That is the whole reason SuperNOVA "advertises a room
        forever".
        """
        if self.args.sn_match_push == 'off':
            self.log('     PAIRING with %s -- SuperNOVA, push disabled'
                     % partner.who())
            return
        ops = ([0x4a04, 0x4a13] if self.args.sn_match_push == 'both'
               else [int(self.args.sn_match_push, 0)])
        song = self.args.sn_match_song
        self.log('     PAIRING with %s -- SuperNOVA, pushing %s both ways '
                 '(song %d)'
                 % (partner.who(),
                    ' '.join('0x%04x' % o for o in ops), song))
        pairs = [(self, partner), (partner, self)]
        for a, b in pairs:
            if b.player is None:
                a.log('!! partner %s has no player file -- the opponent record '
                      'will be empty' % b.who())

        def fire():
            if self.args.sn_pair_delay:
                time.sleep(self.args.sn_pair_delay)
            for op in ops:
                for a, b in pairs:
                    a.push(op, build_sn_match_record(b.player or {}, song))

        if self.args.sn_pair_delay:
            threading.Thread(target=fire, daemon=True).start()
        else:
            fire()

    def sn_start_body(self):
        """The 8-byte SuperNOVA `0x4411` body: status 0, the room's song and
        two zero bytes. See the `0x4411` branch of payload_for."""
        song = 0
        for w in (self, self.peer):
            if w is not None and w.sn_room:
                song = w.sn_room.get('song', 0)
                break
        return (struct.pack('>I', 0)
                + struct.pack('>H', song & 0xffff)
                + bytes([0, 0]))

    def forward_room_setting(self, opcode, payload):
        """SuperNOVA: pass a room-setting change on to the opponent.

        The player changing a setting sends a request and gets a bare status
        back (`0x4393`, `0x4395`). The other console only learns about it
        from a push, and each push is a single bare value with no status in
        front:

            0x4392 u16 song       ->  0x43b2  FUN_0026d640  u16 -> ctx+0x14246
            0x4394 u8 difficulty  ->  0x43b5  FUN_0026d490  u8  -> ctx+0x141fe

        `0x43b2` raises ctx+0x14303, which both room scenes poll (0x00a4a528
        guest, 0x00a57e84 owner) to redraw the song; 0x5a is random and
        passes through untouched. `0x43b5` raises ctx+0x14304 (0x00a4a83c,
        0x00a581b4), and each scene copies ctx+0x141fe into the OPPONENT's
        slot, so the value is the sender's own difficulty. Nothing was
        forwarded before, which is why neither change showed up on the other
        screen.
        """
        if opcode == 0x4392:
            if len(payload) < 2:
                return
            song = struct.unpack('>H', payload[:2])[0]
            if self.sn_room is not None:
                self.sn_room['song'] = song
            push, body, what = 0x43b2, payload[:2], 'song %d' % song
        else:
            if len(payload) < 1:
                return
            push, body, what = 0x43b5, payload[:1], 'difficulty %d' % payload[0]
        peer = self.peer
        if peer is None:
            self.log('     %s (no opponent to tell)' % what)
            return
        self.log('     %s -> %s (0x%04x)' % (what, peer.who(), push))
        peer.push(push, body)

    def hold_sn_start(self):
        """SuperNOVA: hold this side's `0x4411` until the opponent readies.

        Returns True when the reply is being held; the caller then sends
        nothing.

        Each side starts its peer connect as soon as its own `0x4411` lands:

            guest  0x4410 -> 0x00a4c5a0 polls ctx+0x142f4 -> 0x00a4c490
                   -> 0x00a4c1f0 (message 0xb3) -> 0x00a4c100  connect
            owner  0x4410 from 0x00a59160 state 5 -> 0x00a5a430 polls
                   ctx+0x142f4 -> 0x00a5a340 -> 0x00a5a0a0 (0xb3)
                   -> 0x00a59fb0  connect

        and the connect (0x0027b900) gives up after about 300 ticks.
        Answering every `0x4410` at once starts the two connects as far apart
        as the two players press their buttons. The guest readies, dials the
        relay alone, times out and plays the song by itself, and the host's
        connect starts seconds later with nobody on the other end. That is the
        2026-09-14 trace: `relay 19600: A is ...` and never a B.

        Neither wait has a timeout. Both poll the flag once a frame and leave
        only on the player's cancel, which sends 0x4416 (see observe). So the
        first reply can be held for as long as the second player takes, and
        both released together. A non-zero status is not a way to say "wait":
        it un-readies the client (tried 2026-09-13).
        """
        if self.args.sn_start_open:
            return False
        with WAITING_LOCK:
            peer = self.peer
            if peer is None:
                return False          # no opponent, nothing to wait for
            release = peer.start_held and peer.start_ready
            if release:
                peer.start_held = False
            else:
                self.start_held = True
        if release:
            self.log('     both sides ready, releasing the 0x4411 held for '
                     '%s alongside this reply' % peer.who())
            peer.push(0x4411, peer.sn_start_body())
            return False
        self.log('     ready held until %s readies too' % peer.who())
        # Light the opponent-ready indicator on the other side now. On the
        # host it is the only sign that the guest is waiting on them.
        self.push_later(peer, 0x4412, b'\x01', self.args.start_delay)
        return True

    def maybe_start_match(self):
        """Open the PLAY START gate once BOTH clients have run GetStartStaus.

        The match state machine `FUN_00236440` case 1 is three steps:

            if      (!(bfc4 & 0x1000)) { if (GetStartStaus() == 1) bfc4 |= 0x1000; }
            else if (!(bfc4 & 0x2000)) { if (netwk+0x8d4 == 1)     bfc4 |= 0x2000; }
            else                       { FUN_001a7508("PLAY START      "); }

        `netwk+0x8d4` is written by exactly one thing: the parser `0x0085a510`,
        reached from the slot-2 dispatch at `0x0085bf18` for opcode **`0x4412`**,
        which reads a single u8 (`0x008567a0`) straight into `netwk + 0x8d4`.

        This byte was once thought to be "set from outside the main ELF, the
        peer/UDP layer", because every writer *in the ELF* is `sb $zero` (the
        seven CreateRoom sites clearing it). That was a scanning artifact: the
        one writer that matters is in the DATA07 overlay, and it is fed by the
        server. There is no builder for `0x4412` anywhere, so it is push-only --
        the client can never send it, only receive it.

        TIMING MATTERS, and it is the same trap as every other push here.
        `netwk+0x8d8` holds the last received opcode, and the GetStartStaus RPC
        spins on `netwk+0x8d8 == 0x4411`. Pushing `0x4412` too soon after the
        `0x4411` reply overwrites that word before the RPC's poll loop -- which
        runs once per 60 Hz frame -- ever observes it, so the RPC would hang on
        step one instead of step two. Hence the deliberate delay, and hence
        waiting for BOTH sides: they should also start in sync, because from
        here on the two clients drive each other over the 0x4400 relay.
        """
        with WAITING_LOCK:
            peer = self.peer
            if (peer is None or self.start_sent or peer.start_sent
                    or not (self.start_ready and peer.start_ready)):
                return
            self.start_sent = peer.start_sent = True
            pair = (self, peer)
        delay = self.args.start_delay
        self.log('     both sides ran GetStartStaus -- 0x4412 PLAY START in %.2fs'
                 % delay)

        def fire():
            time.sleep(delay)
            for sess in pair:
                sess.push(0x4412, b'\x01')

        threading.Thread(target=fire, daemon=True).start()

    def relay_peer(self, payload):
        """Forward one 0x4400 peer-channel frame to the paired opponent.

        The peer protocol is NOT peer-to-peer for control: `FUN_001d6a50(type,
        payload)` in the client builds `[u32 type][body]` and hands it to
        `0x0085a6b0`, which sets opcode **0x4400** and sends it on `ctx+0x40`
        -- slot 2, the lobby TCP connection. The receive side (`0x0085a610`)
        takes 128 fixed bytes off the same opcode. So both directions of the
        in-game peer protocol run THROUGH the server, and relaying verbatim is
        all that is required.

        Frame sizes come from the 44-entry table at 0x002e6ec0 (body = 4 +
        table[type], max 80), and the client's receive buffer is zeroed before
        every message, so a short frame read as 128 bytes simply tails off into
        zeros. Relay it unchanged.
        """
        peer = self.peer
        # The type word is LITTLE-endian. Everything in the message HEADER is
        # big-endian, but a peer body is a raw memcpy of client structs
        # (FUN_001d6a50 writes `[netwk+0x7c4] = type` with a plain `sw`), so it
        # comes out in R5900 native order. Read live: type 4 arrived as
        # 0x04000000 big-endian.
        ptype = struct.unpack_from('<I', payload)[0] if len(payload) >= 4 else -1
        if peer is None:
            self.log('     0x4400 peer type %d dropped -- no partner' % ptype)
            return
        self.log('     0x4400 peer type %d -> %s (%d bytes)'
                 % (ptype, peer.who(), len(payload)))
        peer.push(0x4400, payload)

    def leave_room(self):
        with WAITING_LOCK:
            self.in_room = False
            if self in WAITING:
                WAITING.remove(self)
            if self.peer is not None:
                self.peer.peer = None
                self.peer = None
            self.start_ready = self.start_sent = self.start_held = False

    def leave_lobby(self):
        with WAITING_LOCK:
            if self in LOBBY:
                LOBBY.remove(self)

    # Which operation each request pair performs. ADD is confirmed; the rest
    # are a structural guess -- see the FRIENDS block above.
    FRIEND_OPS = {0x4520: ('add', FRIEND_LIST), 0x4521: ('add', FRIEND_LIST),
                  0x4523: ('del', FRIEND_LIST), 0x4524: ('del', FRIEND_LIST),
                  0x4526: ('add', IGNORE_LIST), 0x4527: ('add', IGNORE_LIST),
                  0x4529: ('del', IGNORE_LIST), 0x452a: ('del', IGNORE_LIST)}

    def friend_op(self, opcode, payload):
        """Apply one friend operation and remember who it named.

        The reply for two of the four pairs echoes a name back (`0x4522` and
        `0x4528` are `u32 status, u8, char[16]`), so the target is stashed for
        the body builder rather than recomputed there.
        """
        by_name = opcode in (0x4521, 0x4524, 0x4527, 0x452a)
        me = (self.player or {}).get('id')
        with STATE_LOCK:
            if by_name:
                nm = payload[:16].split(bytes(1))[0].decode('ascii', 'replace')
                other = find_player(name=nm)
            else:
                tid = struct.unpack_from('>i', payload)[0] if len(payload) >= 4 else 0
                other = find_player(pid=tid)
            op, which = self.FRIEND_OPS.get(opcode, ('?', FRIEND_LIST))
            if me is None or other is None:
                self.log('!!   %s %s (0x%04x): target not found'
                         % (which, op, opcode))
                self.friend_target = None
                return
            oid = other['id']
            self.friend_target = other.get('name', '')
            fresh = op == 'add' and friends_of(me).get(str(oid)) != which
            if op == 'add':
                friend_add(me, oid, which)
            else:
                friend_remove(me, oid, which)
            state_save()
        self.log('     %s %s (0x%04x) %s -> %s'
                 % (which, op, opcode, self.who(), other.get('name', '')))
        # The client asks for the list once (0x3080) and never again, so a
        # friend added afterwards stayed invisible until the next login, even
        # after backing out of the screen. A bare 0x3084 APPENDS at the
        # client's own count (ctx+0x2c78, reset only by the request builder
        # 0x0026c610), which is why pushing the whole list (--friend-push)
        # duplicated every entry. Pushing just the new record appends exactly
        # the one that was added. It goes out after the 0x4522 reply.
        if self.args.friend_push:
            self.push(0x3084, friendlist_body(me, online_ids(),
                                              self.args.friend_bytes))
        elif fresh:
            nm = other.get('name', '').encode('ascii', 'replace')[:16]
            rec = (struct.pack('>i', oid) + nm.ljust(16, bytes(1))
                   + bytes([0, LIST_BYTE.get(which, 0),
                            1 if oid in online_ids() else 0]))
            self.log('     adding the new %s entry on the client (0x3084)'
                     % which)
            self.push_later(self, 0x3084, rec, 0.3)

    def observe(self, opcode, payload):
        """Requests that CHANGE server state, applied before the reply is built."""
        # The four friend operations, each in an id and a name flavour. Only
        # ADD is confirmed (observed live as 0x4520 carrying the target's id);
        # the other three mappings are a guess and every one logs its opcode so
        # a pass through the UI settles which button sent what.
        if opcode in (0x4520, 0x4521, 0x4523, 0x4524,
                      0x4526, 0x4527, 0x4529, 0x452a) and self.is_sn:
            self.friend_op(opcode, payload)
            return
        # 0x4323 -- JOIN A ROOM from the browser. The reply carries the room
        # for the joiner, but the HOST is told nothing, so it sat in its own
        # room with no start option while the joiner got one. Observed
        # 2026-09-13, and it is the same split as the auto-search path: the
        # two sides need different messages, and the host needs 0x4325.
        if opcode == 0x4323 and self.is_sn:
            tgt = (struct.unpack_from('>i', payload, 4)[0]
                   if len(payload) >= 8 else 0)
            with WAITING_LOCK:
                self.pending_join_host = next(
                    (w for w in LOBBY if w.is_sn and w.player is not None
                     and w.player.get('id') == tgt), None)
            return
        # 0x4a00 / 0x4a02 -- AUTO SEARCH, the "find me a game" button, as
        # distinct from browsing the room list. 0x4a00 carries the searcher's
        # own player id and means "I am available"; 0x4a02 ends the search.
        # Nothing else answers it, so if the server does not act, the client
        # searches forever -- which is exactly what it did.
        if opcode == 0x4a00 and self.is_sn:
            self.sn_searching = True
            self.pending_sn_search = True          # deferred; see on_frame
            self.log('     auto-search started')
            return
        if opcode == 0x4a02 and self.is_sn:
            if self.sn_searching:
                self.log('     auto-search ended')
            self.sn_searching = False
            return
        if opcode == 0x4330:                        # CreateRoom
            if self.is_sn:
                self.sn_room = parse_sn_createroom(payload)
                self.log('     created room %s' % (self.sn_room,))
            if self.args.pair:
                self.pending_pair = True           # deferred; see on_frame
            return
        if opcode == 0x4106:                       # SavePlayerOption
            prev = (self.player or {}).get('options')
            prev = bytes.fromhex(prev) if prev else None
            self.log('     player options (%d B) %s' % (len(payload),
                                                        payload.hex()))
            d = diff_blobs(prev, payload)
            if d:
                self.log('     options CHANGED: %s' % '; '.join(d))
            if self.player is not None:
                self.player['options'] = payload.hex()
                with STATE_LOCK:
                    state_save()
            return
        if opcode == 0x5000 and self.is_sn:
            # SuperNOVA asks for ONE competition by id (s32), not for an
            # Extreme 2 card by two selector bytes.
            self.sn_comp_sel = (struct.unpack('>i', payload[:4])[0]
                                if len(payload) >= 4 else None)
            self.log('     competition detail requested for id %s'
                     % self.sn_comp_sel)
            return
        if opcode == 0x5000 and len(payload) >= 2:
            # TWO u8 SELECTORS, and the client asks for all four combinations:
            # 0000, 0001, 0100, 0101. Serving one record to all four is why both
            # challenge cards showed the same songs and the same "NORMAL NO:0".
            self.rc_sel = (payload[0], payload[1])
            self.log('     GetRCInfo selector %d,%d' % self.rc_sel)
            return
        if opcode == 0x5002:                       # GetRCTrycount -- 4-byte body
            self.rc_try_req = payload
            self.log('     GetRCTrycount request %s' % payload.hex())
            return
        if self.is_sn and opcode in (0x5004, 0x5006, 0x5020, 0x5040):
            self.sn_comp_request(opcode, payload)
            return
        if opcode in (0x5004, 0x5006):
            for line in describe_rc_play_request(opcode, payload):
                self.log('     ' + line)
            if not self.is_sn:
                self.record_rc(opcode, payload)
            return
        if opcode == 0x6000:                       # ranking board request
            rq = parse_ranking_request(payload)
            if rq:
                self.rank_req = rq
                self.log('     ranking request %s' % (rq,))
            return
        if opcode == 0x4430 and not self.is_sn:    # GetEndgame, the match result
            self.record_endgame(payload)
            return
        if opcode in (0x4392, 0x4394) and self.is_sn:
            self.forward_room_setting(opcode, payload)
            return
        if opcode == 0x4410:                       # GetStartStaus
            # Both games send this. Extreme 2 then needs the separate 0x4412
            # push; SuperNOVA's reply is timed by hold_sn_start.
            self.start_ready = True
            return
        if opcode == 0x4416 and self.is_sn:
            # The un-ready. FUN_00a4b180 sends it on the cancel button and on
            # a rejected ready alike, then drops back to the room, so a 0x4411
            # still held for this side must never be delivered.
            if self.start_held:
                self.log('     un-ready: dropping the held 0x4411')
            self.start_ready = self.start_held = False
            # Turn the opponent's ready light back off. hold_sn_start lit it
            # with 0x4412 = 1, and 0x4412 is just one u8 into ctx+0x14268,
            # which the room scenes read each frame (0x00a4a8b4, 0x00a58284).
            # Without this the other player kept seeing us as ready.
            peer = self.peer
            if peer is not None:
                self.log('     telling %s we are no longer ready (0x4412 = 0)'
                         % peer.who())
                peer.push(0x4412, b'\x00')
            return
        if opcode == 0x4340 and self.is_sn:
            self.sn_part('left the room')
        if opcode == 0x4340:                        # OutRoom -- gave up / left
            if self.is_sn and self.sn_room is not None:
                self.log('     left room')
                self.sn_room = None
            if self.args.pair:
                self.leave_room()
            return
        if opcode == 0x3003:                       # the credential blob
            # The account key stays the stable first 8 bytes (keeps existing
            # accounts). The full 32-byte username and the 16-byte digest that
            # follow are captured for optional password verification: the blob
            # is username[32] + MD5(username + challenge + password), and our
            # challenge is constant, so the digest is stable per password.
            self.acct = binascii.hexlify(payload[:8]).decode()
            if len(payload) >= 48:
                self.login_user = binascii.hexlify(
                    payload[:32].rstrip(b'\x00')).decode()
                self.login_digest = binascii.hexlify(payload[32:48]).decode()
            self.log('     account key %s (stable first 8 bytes)'
                     % self.acct)
            return
        if opcode == 0x4100:                       # SelectPlayerFile
            slot = payload[0] if payload else 0
            with STATE_LOCK:
                self.player = next((f for f in account(self.acct)['player_files']
                                    if f['slot'] == slot), None)
            with WAITING_LOCK:
                if self.player is not None and self not in LOBBY:
                    LOBBY.append(self)
            self.try_unseen_pushes()
            return
        if opcode == 0x411a:                       # SetMyAddr
            ep = parse_setmyaddr(payload)
            if ep and self.player is not None:
                self.player['endpoint'] = ep
                with STATE_LOCK:
                    state_save()
            self.log('     endpoint %s' % (ep,))
            return
        if opcode == 0x3020:                       # NewCreatePlayerFile
            pf = parse_create_playerfile(payload)
            if pf is None:
                self.log('!! 0x3020 body is %d bytes, expected 18' % len(payload))
                return
            with STATE_LOCK:
                acc = account(self.acct)
                files = [f for f in acc['player_files'] if f['slot'] != pf['slot']]
                files.append(pf)
                pf['id'] = alloc_id()
                acc['player_files'] = sorted(files, key=lambda f: f['slot'])[:2]
                state_save()
            self.log('     created player file slot %d name %r dancer %d'
                     % (pf['slot'], pf['name'], pf['dancer']))
        elif opcode == 0x3030:                     # DeletePlayerFile
            # Builder 0x008572f0 writes a single u8. By analogy with 0x4100,
            # which sends entry+0x00 (the slot byte), this is the slot.
            slot = payload[0] if payload else None
            with STATE_LOCK:
                acc = account(self.acct)
                before = len(acc['player_files'])
                acc['player_files'] = [f for f in acc['player_files']
                                       if f['slot'] != slot]
                if len(acc['player_files']) != before:
                    state_save()
            self.log('     deleted player file slot %s' % slot)

    def payload_for(self, resp_opcode, req_opcode=None, req_payload=b''):
        """Body for one response part. Empty unless we have something real."""
        # A 16-byte fixed-width field the client stores at ctx+0xe7 and then
        # CLEARS when 0x3004 arrives -- a login challenge. It feeds the 48-byte
        # 0x3003 blob. Zeros are accepted (the blob is still opaque to us) and
        # keep that blob deterministic, which is what a cipher attack needs.
        if resp_opcode == 0x3002:
            return bytes(16)
        # Parse thunks: a single u32 BE status into ctx+0x4900. 0 = OK -- the
        # client's error dispatch only reacts to a fixed set of negatives.
        if resp_opcode in (0x3004, 0x3022, 0x3032):
            if (resp_opcode == 0x3004 and self.args.verify_login
                    and self.login_user and self.login_digest):
                verdict = results.credential_verify(self.login_user,
                                                    self.login_digest)
                if verdict == 'mismatch':
                    self.log('!! login rejected: wrong password for account %s'
                             % self.acct)
                    return struct.pack('>i', self.args.login_reject_status)
                self.log('     login %s (%s)'
                         % ('accepted' if verdict == 'ok' else 'first seen',
                            self.acct))
            return struct.pack('>I', 0)
        # SelectPlayerFile. The client has ALREADY stashed the selected entry's
        # id (entry+0x04, straight out of the 0x3012 list) at ctx+0x8fd8 -- see
        # 0x001e248c -- and 0x0085b5e0 checks our second u32 against it:
        #     if (echo != ctx[0x8fd8]) status = -0x10a;    // -266
        # So this reply MUST echo the id we handed out for the slot the request
        # names, or the client invents "-266 the specified player does not
        # exist" on its own. An empty body echoes 0 and fails exactly that way.
        if resp_opcode == 0x4101:
            slot = req_payload[0] if req_payload else 0
            with STATE_LOCK:
                match = next((f for f in account(self.acct)['player_files']
                              if f['slot'] == slot), None)
            if match is None:
                self.log('!! 0x4100 selected slot %d, which we have no file for'
                         % slot)
                return struct.pack('>II', 0, 0)
            ident = match.get('id', match['slot'] + 1)
            self.log('     selected slot %d (%r), echoing id %d'
                     % (slot, match['name'], ident))
            return struct.pack('>II', 0, ident)
        # SvrTime: a single u32 BE -> ctx+0x26a4 (parser 0x00858a10). We answered
        # this with nothing for the whole session, so the client's server clock
        # has been 0 -- which matters the moment anything is scheduled.
        if resp_opcode == 0x2007:
            return struct.pack('>I', self.args.svr_time or int(time.time()))
        # GetSchedule: u8 -> ctx+0x2a383, u32 BE -> ctx+0x2a388, u32 BE ->
        # ctx+0x2a38c (parser 0x00857970). Nine bytes.
        #
        # THE THREE FIELDS ARE NOW READ OUT OF THE BINARY (2026-09-13), and the
        # old start/end-timestamp guess was wrong in a way that produced exactly
        # the "999:59" the log showed. The online scene copies all three out
        # (0x001e79ac, 0x001e8418, 0x001e70fc) into three globals:
        #
        #   ctx+0x2a383 -> DAT_01047cb4   the WEEK NUMBER
        #   ctx+0x2a388 -> DAT_01047ca8   INERT -- four stores, zero loads, in
        #                                 the ELF and every DATA0x overlay
        #   ctx+0x2a38c -> DAT_01047cac   SECONDS REMAINING (a duration)
        #
        # The week byte gates the tab: FUN_001ef640 at 0x001ef754 skips tab 1
        # unless `0 < DAT_01047cb4 < 0x3d`, and the widget setter FUN_0022f840
        # clamps the same way (>=61 -> 60, <0 -> 0), so the legal range is 1..60
        # and 0 means "no challenge running". It is the same scale as the
        # ranking board's `period` field (-2..60).
        #
        # The second u32 is a COUNTDOWN, not a timestamp. FUN_0022f790 takes it
        # as `a1` and does `a1 % 60` -> a float (the seconds digits) and
        # `a1 / 60` -> minutes, clamped at 59999; the draw path at 0x0022f9ac
        # divides THAT by 60 again and renders "%03d:%02d". So the display is
        # HOURS:MINUTES and 59999 minutes renders as 999:59 -- which is all the
        # old code was ever showing, because `now + 8h` is ~1.79e9 seconds.
        # a1 == 0 takes the early-out branch that sets bit 4 instead: no
        # countdown at all.
        if resp_opcode == 0x5012:
            auto_week, auto_secs = rc_week(self.args.svr_time or None)
            week = auto_week if self.args.rc_flag is None else self.args.rc_flag
            secs = (auto_secs if self.args.sched_remaining is None
                    else self.args.sched_remaining)
            secs = max(0, secs)
            # The countdown is drawn as hours:minutes and clamps at 999:59, so
            # a full week does not fit. Show the last day of it and let the
            # earlier part of the week read as a flat maximum.
            secs = min(secs, 999 * 3600 + 59 * 60)
            self.log('     schedule: week %d, %d s left (%d:%02d on screen)%s'
                     % (week, secs, secs // 3600, (secs // 60) % 60,
                        '' if self.args.rc_flag is not None else ' [auto]'))
            return (bytes([week & 0xff])
                    + struct.pack('>II', self.args.sched_inert, secs))
        # GetRCEntry / GetRCRegist. Both are status-only replies -- the RPCs
        # jump straight to the generic parse thunk 0x0085b710 (0x00857df0 and
        # 0x00857d30), which reads ONE s32 through 0x008565f0 and returns it as
        # the parse result. Serving an empty body is a SHORT READ, not an error:
        # 0x008565f0 bounds-checks the read cursor against 0x3fd, never the
        # message length, so the client would take four bytes of whatever the
        # 1 KB message buffer last held and hand them back as the RPC's status.
        # That is the friends-list bug's shape for the third time; these two
        # were reaching the client empty all along.
        if resp_opcode in (0x5005, 0x5007):
            return struct.pack('>i', 0)
        # GetBlockList. Parser 0x0085b4f0 -> ctx+0x9ee8, and it reads AT MOST
        # ONE block (no loop, unlike every other list):
        #     u16 -> +0x00  count
        #     if (more data) { u8 -> +0x02 ; 16 fixed -> +0x06 ; u16 -> +0x04 }
        # We have been answering this with nothing all session while the client
        # went on to EntryBlock(0) -- entering a block that does not exist. A
        # client in a world with no blocks has nothing to browse, which would
        # explain why "search for opponent" never calls GetRoomList or
        # GetPlayerList and just advertises a room forever.
        # EXPERIMENT: does a populated block change the matchmaking path?
        if self.is_sn and resp_opcode in SN_STATUS_ONLY:
            return struct.pack('>I', 0)
        if self.is_sn and resp_opcode in SN_STATUS_COUNT:
            return struct.pack('>Ii', 0, 0)
        # Two more fixed-size ENDs whose request the binary names (see
        # REQUEST_RESPONSES_SN). Both were reaching the client empty through
        # the +1 fallback, which is a short read: their parsers bounds-check
        # the read CURSOR, not the message, so the fields came from whatever
        # the message buffer last held rather than being rejected.
        if self.is_sn and resp_opcode == 0x0007:      # req 0x0006, 0x0026e360
            return struct.pack('>H', 0)
        if self.is_sn and resp_opcode == 0x5021:      # req 0x5020, 0x00269b40
            return self.sn_comp_standing()
        if resp_opcode == 0x4201 and self.args.serve_block and self.is_sn:
            # SuperNOVA's GetBlockList, parser 0x00270e90. SAME 21 bytes as
            # Extreme 2's but a DIFFERENT ORDER, which is exactly why this was
            # hard to spot -- the length matched while every field was shifted.
            #
            #   entry = ctx+0xb6f8 + count*24 + 2   (count is a u16 IN THE STRUCT,
            #                                        NOT on the wire)
            #   0x279e10 -> entry+0x16   u8      block id      <- FIRST on the wire
            #   0x279b10 -> entry+0x00   16 B    name
            #   0x279d30 -> entry+0x12   u16 BE
            #   0x279d30 -> entry+0x14   u16 BE
            #
            # Extreme 2 leads with a u16 "one block exists" and has only ONE
            # trailing u16. Feeding it that made SuperNOVA read the count's low
            # byte plus the id as the first two characters of the block name.
            nm = self.args.block_name.encode('ascii', 'replace')[:16]
            with WAITING_LOCK:
                here = len(LOBBY)
            return (bytes([0])                       # block id 0
                    + nm.ljust(16, b'\x00')
                    + struct.pack('>H', here)        # occupancy
                    + struct.pack('>H', self.args.sn_block_max))
        if resp_opcode == 0x4201 and self.args.serve_block:
            nm = self.args.block_name.encode('ascii', 'replace')[:16]
            # Occupancy was len(WAITING) -- only the players ADVERTISING a room --
            # so the block read "0000/1000" with two people in the lobby. LOBBY is
            # everyone who has selected a profile. Reported on screen 2026-08-27.
            with WAITING_LOCK:
                here = len(LOBBY)
            return (struct.pack('>H', 1)             # one block exists
                    + bytes([0])                     # block id 0 -- what EntryBlock asks for
                    + nm.ljust(16, b'\x00')
                    + struct.pack('>H', here))       # occupancy, best guess
        # GetPlayerList data part. Empty here is why the in-game "list" screen
        # shows nothing -- and with nothing to look at, matchmaking has no join
        # path and both clients just advertise rooms at each other forever.
        # Serve every OTHER player currently in the lobby.
        # ---- SuperNOVA chat -------------------------------------------
        #
        # 0x4511 (client -> server), from the wire:
        #     u8, u8, s32, s32, cstring        e.g. 01 01 00*8 "ssss" 00
        #
        # 0x4513 (server -> client), parser 0x0026df80:
        #     u32, u8, s32, s32 id, char[16] name, cstring text
        #
        # The parser ends in a debug printf whose format string at 0x002fa567 is
        #     "(RES:%d:%d;%d)<%s[%d]> %s"
        # taking (+0x00, +0x08, +0x0c, name@+0x14, id@+0x10, text@+0x25) -- which
        # names the fields outright: it renders as "<name[id]> text".
        #
        # 0x4513 has no in-flight request check, so it is a push. Using it as the
        # answer to 0x4511 echoes the speaker their own line; the same frame is
        # pushed to everyone else in the lobby.
        # **There are TWO chat requests and they are not the same shape.**
        # 0x4511 is the lobby line; 0x4512 is a WHISPER, and it was reaching
        # here through the +1 fallback with its body ignored -- so the text was
        # dropped and the recipient got an empty line under the sender's name.
        # Observed 2026-09-13:
        #
        #   0x4511  u8, u8, s32, s32, cstring             text at +10
        #   0x4512  u8, u8, s32, char[16], cstring        27 B on the wire:
        #           00 02 00000001 "aaa"+NULs "derp"
        #           builder 0x0026e090 -- writers 0x27a2b0 u8, 0x27a070 s32,
        #           0x279ec0 fixed string, 0x279e50 cstring.
        #
        # **A whisper addresses its target by NAME, not by id**: the 16-byte
        # field carries the recipient's dancer name, so it goes to that one
        # player rather than to the room.
        # WHICH CHANNEL. The sender is FUN_00273a70 case 9. It reads the chat
        # mode at scene->0x834 byte 1 (0 lobby, 1 room, 2 whisper; room also
        # needs byte 0, "in a room") and calls the builder with
        #     lobby (0, 1)    room (1, 1)    whisper (0, 2) through 0x4512
        # so the FIRST byte is the room flag and the second is the kind. The
        # receiver FUN_00287ac0 hands the push's u8 and s32 to the chat
        # widget, treats s32 == 1 as a whisper it can answer, and raises the
        # new-message alert for u8 == 1 or a whisper. This relay used to echo
        # the SECOND byte, which is 1 for every ordinary line, so lobby chat
        # arrived as room chat. The u8 is now the room flag, and a room line
        # goes only to the other player in the room.
        if resp_opcode == 0x4513:
            body = req_payload if req_opcode in (0x4511, 0x4512) else b''
            chan = body[0] if body else 0
            target = None
            if req_opcode == 0x4512 and len(body) > 22:
                arg = struct.unpack_from('>i', body, 2)[0]
                target = body[6:22].split(bytes(1))[0].decode('ascii', 'replace')
                text = body[22:].split(bytes(1))[0]
            else:
                arg = struct.unpack_from('>i', body, 2)[0] if len(body) >= 6 else 0
                text = body[10:].split(bytes(1))[0] if len(body) > 10 else b''
            nm = (self.who() or '?').encode('ascii', 'replace')[:16]
            pid = (self.player or {}).get('id', 0)
            frame = (struct.pack('>I', 0) + bytes([chan & 0xff])
                     + struct.pack('>ii', arg, pid)
                     + nm.ljust(16, bytes(1)) + text + bytes(1))
            self.log('     %s chat%s <%s[%d]> %r'
                     % ('room' if chan else 'lobby',
                        (' ->%s' % target) if target else '',
                        self.who(), pid, text.decode('latin1', 'replace')))
            with WAITING_LOCK:
                if target is not None:
                    others = [w for w in LOBBY if w is not self and w.is_sn
                              and w.who() == target]
                elif chan:
                    others = [self.peer] if self.peer is not None else []
                else:
                    others = [w for w in LOBBY if w is not self and w.is_sn]
            for w in others:
                w.push(0x4513, frame)
            if others:
                self.log('     relayed chat to %d other player(s)' % len(others))
            elif target:
                self.log('!!   whisper target %r is not in the lobby' % target)
            return frame

        # The competition lists. 0x5032 is what can be entered now and 0x5036
        # what is coming (UI strings 0x0ae / 0x0af). Both come from
        # sn_competitions and share the 50-byte record; a competition sits on
        # one shelf or the other by its window.
        if resp_opcode in (0x5032, 0x5036) and self.is_sn:
            now = self.args.svr_time or int(time.time())
            comps = sn_competitions(self.args, now)
            if resp_opcode == 0x5032:
                pick = [c for c in comps if c['start'] <= now < c['end']]
            else:
                pick = [c for c in comps if c['start'] > now]
            self.log('     %s competitions: %s'
                     % ('open' if resp_opcode == 0x5032 else 'future',
                        ', '.join('%d %r' % (c['id'], c['name'])
                                  for c in pick) or 'none'))
            return sn_comp_body([(c['id'], c['name'], c['start'], c['end'])
                                 for c in pick])

        # 0x3901 -- u32 status + a FIXED 32-byte string. The parser copies
        # 0x20 bytes whatever the payload length, so a short body is not
        # rejected, it is silently filled with stale message-buffer bytes. Send
        # the full 36 either way. Status 0 with an empty name is the honest
        # answer until we know what the string is.
        if resp_opcode == 0x3901 and self.is_sn:
            return struct.pack('>I', 0) + bytes(32)

        # 0x3084 -- the friends-list records, max 40, 23 bytes each:
        #     s32 id, char[16] name, u8, u8, u8
        # Served as an empty list: the loop leads with the "anything left?"
        # probe at 0x00279a60, which consumes nothing and returns -1 on an empty
        # payload, so zero records is well formed. We have no friend data to
        # serve yet -- the point of this branch is that the GROUP is now
        # complete, which is what stops the hang.
        # 0x4324 -- the reply to 0x4323 JOIN. The request names the room owner,
        # so the reply is that player's record plus the room's song.
        if resp_opcode == 0x4324 and self.is_sn:
            tgt = (struct.unpack_from('>i', req_payload, 4)[0]
                   if len(req_payload) >= 8 else 0)
            with WAITING_LOCK:
                host = next((w for w in LOBBY if w.is_sn and w.player is not None
                             and w.player.get('id') == tgt), None)
            song = ((host.sn_room or {}).get('song', 0)
                    if host is not None and host.sn_room else 0)
            self.log('     join room of id %d (%s), song %d'
                     % (tgt, host.who() if host else '?', song))
            return build_sn_joinreply_record(host.player if host else None, song)

        # 0x4431 GetEndgame -- FIVE bytes, u32 status + u8, not a bare status
        # (parser 0x0026ecc0, which also sets ctx+0x14264 = 3 and
        # ctx+0x1426c = 2). Served empty it was a short read like the rest of
        # the in-match handshake.
        if resp_opcode == 0x4431 and self.is_sn:
            return struct.pack('>I', 0) + bytes([0])

        # 0x4b00 -> 0x4b01: the opponent's address pair. The request names a
        # player id; answer with that player's SetMyAddr candidates.
        if resp_opcode == 0x4b01 and self.is_sn:
            tgt = (struct.unpack_from('>i', req_payload)[0]
                   if len(req_payload) >= 4 else 0)
            with WAITING_LOCK:
                who = next((w for w in LOBBY if w.is_sn and w.player is not None
                            and w.player.get('id') == tgt), None)
            if who is None and self.peer is not None:
                who = self.peer          # asked for someone we cannot see
            pl = who.player if who is not None else None
            ep = (pl or {}).get('endpoint') or {}
            if self.relay_dial:
                self.log('     peer address for id %d (%s): RELAYED via %s:%d'
                         % (tgt, who.who() if who else '?',
                            self.relay_dial[0], self.relay_dial[1]))
            else:
                self.log('     peer address for id %d (%s): local %s:%s '
                         'public %s:%s'
                         % (tgt, who.who() if who else '?',
                            ep.get('local'), ep.get('local_port'),
                            ep.get('public'), ep.get('public_port')))
                if not ep:
                    self.log('!!   no SetMyAddr on file -- the opponent will '
                             'not be reachable')
            return build_sn_peeraddr_record(pl, self.relay_dial)

        # 0x5042 -- the tournament board, 29 bytes a row (parser 0x00269830):
        #     s32 rank / s32 player / char[16] name / u8 dancer / s32 total
        # for the competition and row count the 0x5040 request named. The two
        # s32 roles and the total are this server's reading; the first s32
        # rendered as the rank when it was the row number.
        if resp_opcode == 0x5042 and self.is_sn:
            comp, limit = self.sn_board_req
            rows = sn_comp_rows(comp, limit) if comp is not None else []
            self.log('     tournament %s board: %d row(s)' % (comp, len(rows)))
            out = b''
            for r in rows:
                nm = r['name'].encode('ascii', 'replace')[:16]
                out += (struct.pack('>ii', r['rank'], r['player'])
                        + nm.ljust(16, bytes(1))
                        + bytes([r.get('dancer', 0) & 0xff])
                        + struct.pack('>i', r['score']))
            return out

        # ── 0x4411 GetStartStaus (SuperNOVA) -- THE READY GATE ──────────
        #
        # 8 bytes: u32 status / u16 song -> ctx+0x14246 / u8 / u8 -> ctx+0x14245.
        # It was being served EMPTY, so the client read all four out of a stale
        # buffer -- and the status is the whole decision. The arrival handler
        # at 0x00a4c658 is
        #
        #     if (ctx+0x142f4 == 1) {                 // the reply landed
        #         if (ctx+0x142f8 == 0) { s0->0x4c = 1; -> 0x00a4c490 }  // GO
        #         else                  { s0->0x4c = 0; -> 0x00a4b180 }  // not yet
        #     }
        #
        # and ctx+0x142f8 is that status word. Whenever the stale bytes
        # happened to be zero the client went straight to the play screen
        # without waiting for anyone -- which is what "it just sorta starts the
        # game" was. Extreme 2 gates the same moment with a separate 0x4412
        # push; SuperNOVA gates it inside the polled reply instead.
        #
        # **NON-ZERO DOES NOT MEAN "KEEP WAITING". It means the ready was
        # REJECTED.** Answering non-zero until both sides had arrived was tried
        # on 2026-09-13 and the second player's ready flag was cleared the
        # instant they pressed it -- `s0->0x4c = 0` on that branch is the
        # client un-readying itself, not parking on a wait screen.
        #
        # So the status is always 0, and the waiting is done by holding the
        # reply back until the opponent has readied too (hold_sn_start).
        # 0x4412, one u8 into ctx+0x14268, is only the opponent-ready
        # indicator on this game: 0x00a4a8b4 and 0x00a58284 read it and
        # nothing else in DATA04 does.
        if resp_opcode == 0x4411 and self.is_sn:
            peer = self.peer
            self.log('     ready accepted (peer ready=%s)'
                     % (peer.start_ready if peer else None))
            return self.sn_start_body()

        if resp_opcode == 0x3122 and self.is_sn:
            # The operator page wins when it has anything to say; otherwise
            # whatever was configured on the command line is used.
            items = ['%s|%s' % (n.get('title', ''), n.get('body', ''))
                     for n in (content.load().get('news') or [])]
            source = 'operator'
            if not items:
                items, source = self.args.sn_news, 'configured'
            bodies = sn_news_bodies(items,
                                    self.args.sn_news_fields,
                                    self.args.sn_news_wrap)
            if bodies:
                self.log('     news: %d item(s), %s' % (len(bodies), source))
            return bodies

        if resp_opcode == 0x3084 and self.is_sn:
            pid = (self.player or {}).get('id')
            if pid is None:
                return b''
            body = friendlist_body(pid, online_ids(),
                                   self.args.friend_bytes,
                                   self.args.friend_probe)
            if body:
                self.log('     friends list: %d record(s)' % (len(body) // 23))
            return body

        # Friend add/remove acknowledgements. 22 bytes: u32 status, u8, char[17].
        # The u8 and the name are echoed back so the UI can name what it acted on;
        # served empty they are simply blank, which is correct for "no such
        # friend" and harmless otherwise.
        if resp_opcode in (0x4522, 0x4528):
            # Echo the player the operation named, so the UI can say who it
            # acted on. The middle u8 is unidentified; zero is what it was
            # getting before and nothing has objected.
            if self.friend_target:
                nm = self.friend_target.encode('ascii', 'replace')[:16]
                return (struct.pack('>I', 0) + bytes([0])
                        + nm.ljust(16, bytes(1)))
            # 21 bytes: u32 status, u8, char[16]. Originally written as 22 with
            # a 17-byte name -- the string length lives in the CALL'S DELAY SLOT
            # and the first pass of tools/sndispmap.py read it as 17.
            return struct.pack('>I', 0) + bytes([0]) + bytes(16)

        # 0x4310 GetRoomList data part. Served empty until 2026-09-13, which is
        # why a room created on one client never appeared on the other: the
        # server was told about the room by 0x4330 and then never mentioned it
        # again. Serve every OTHER player's room.
        if resp_opcode == 0x4310 and self.is_sn:
            with WAITING_LOCK:
                rooms = [(w.sn_room, w.who()) for w in LOBBY
                         if w is not self and w.sn_room is not None]
            if not rooms:
                return b''
            self.log('     room list: %s'
                     % ', '.join('%s(song %d)' % (n, (r or {}).get('song', 0))
                                 for r, n in rooms))
            return b''.join(roomlist_entry_sn(r, n) for r, n in rooms)

        if resp_opcode == 0x4212:
            with WAITING_LOCK:
                others = [w for w in LOBBY
                          if w is not self and w.player is not None]
            if not others:
                return b''
            self.log('     player list: %s'
                     % ', '.join(w.who() for w in others))
            if self.is_sn:
                return b''.join(playerlist_entry_sn(
                                    w.player.get('id', 0), w.who(),
                                    w.player.get('dancer', 0),
                                    probe=self.args.stat_probe)
                                for w in others)
            return b''.join(playerlist_entry(
                                w.player.get('id', 0), w.who(),
                                w.player.get('dancer', 0),
                                probe=self.args.stat_probe,
                                stats=list_stats(
                                    self.x2_stats(w.player.get('id', 0))))
                            for w in others)
        # 0x4105 GetPlayerOption -- hand back whatever the client last saved,
        # so its own settings survive a re-login.
        if resp_opcode == 0x4105:
            blob = (self.player or {}).get('options')
            return playeroption_body(bytes.fromhex(blob) if blob else None)
        # 0x441e GetRuleMask -- Extreme 2 only; SuperNOVA's parser reads a
        # different number of bytes and its meanings are unconfirmed, so it
        # keeps the empty body it tolerates today.
        # SuperNOVA reads FOUR rule bytes where Extreme 2 reads three, so it
        # gets its own body. The two branches are mutually exclusive on is_sn,
        # so their order does not matter.
        if resp_opcode == 0x441e and self.is_sn:
            return sn_rule_mask_body(self.args.sn_rule_mask)
        # ---- SuperNOVA online song list -------------------------------
        #
        # 0x8002 unlocks songs; 0x8006 names something we have not identified;
        # 0x7002 is the 1 KB per-song blob the boot sequence fetches for every
        # song 0x8002 approved. All three are SuperNOVA-only.
        if resp_opcode == 0x8002 and self.is_sn:
            ids = sn_song_ids(self.args.sn_songs)
            if ids:
                self.log('     unlocking %d song(s): %s'
                         % (len(ids), ', '.join(
                             next((c for i, c, _ in SN_ONLINE_SONGS if i == n),
                                  str(n)) for n in ids[:8])
                            + (' ...' if len(ids) > 8 else '')))
            return sn_song_avail_bodies(ids, extra=self.args.sn_song_extra)
        if resp_opcode == 0x8006 and self.is_sn:
            return sn_song_name_body(())
        # 0x7002 copies EXACTLY 1024 bytes into a per-song buffer
        # (FUN_00279b10(msg, dst, 0x400)) and nothing advances the destination
        # between messages, so this is one frame of exactly 1024 bytes and never
        # two. A short body is not rejected -- the parser copies 1024 regardless
        # and the tail is whatever was left in the message buffer -- so serving
        # the full length matters even though we do not know what the contents
        # should be.
        if resp_opcode == 0x7002 and self.is_sn:
            return bytes(MAX_PAYLOAD)
        if resp_opcode == 0x441e and not self.is_sn:
            rules = self.args.rule_mask
            self.log('     rule mask: %s'
                     % (', '.join(n for n, v in zip(RULE_NAMES, rules) if v)
                        or 'none'))
            return rule_mask_body(rules)
        # Ranking Challenge.
        # ── SuperNOVA 0x5001 is NOT Extreme 2's Ranking Challenge card ──
        #
        # The two games share the 0x50xx opcodes and mean entirely different
        # things by them. In SuperNOVA the family is COMPETITIONS, and even the
        # request bodies differ: 0x5000 is FOUR bytes here (a competition id)
        # where Extreme 2 sends TWO (its card selector). The reply differs too
        # -- 74 bytes into ctx+0x12ed8.. against Extreme 2's 138-byte card --
        # and until 2026-09-13 this branch was not gated on is_sn, so a
        # SuperNOVA client asking for competition detail was handed a Ranking
        # Challenge card and read 74 bytes of the wrong record out of it.
        #
        # The layout is in sn_detail_body. The request (0x5000, four bytes)
        # names the competition by id, so each one gets its own card.
        if resp_opcode == 0x5001 and self.is_sn:
            now = self.args.svr_time or int(time.time())
            comps = sn_competitions(self.args, now)
            comp = (next((c for c in comps if c['id'] == self.sn_comp_sel),
                         None) or (comps[0] if comps else None))
            if comp is None:
                return struct.pack('>I', 0) + bytes(SN_DETAIL_LEN - 4)
            self.log('     competition detail %d %r, songs %s'
                     % (comp['id'], comp['name'], comp['songs']))
            return sn_detail_body(comp)
        if resp_opcode == 0x5001 and self.args.serve_rc and not self.is_sn:
            # One distinct record PER SELECTOR, so the two cards stop being
            # copies of each other: a different challenge number in the header
            # and a different block of ten songs.
            chal = rc_challenge(self.rc_sel)
            hdr = list(self.args.rc_hdr) or [chal, 0, 0, 0, 0, 0, 0,
                                             self.args.rc_difficulty]
            stages = max(1, min(RC_ENTRIES, self.args.rc_stages))
            if self.args.rc_first_song is None:
                # Nothing pinned on the command line, so the challenge comes
                # from the week. That means it changes on its own every seven
                # days and an unattended server still has a running event.
                # The operator page can override any part of it; whatever it
                # does not set stays generated.
                week, _ = rc_week(self.args.svr_time or None)
                songs = rc_auto_songs(week, chal, RC_ENTRIES)
                o_songs, o_diff, o_stages = content.rc_override(week, chal)
                source = 'generated'
                if o_songs:
                    # Short lists are topped up from the generated lineup, so a
                    # partial override never shortens the card by accident.
                    songs = (list(o_songs) + songs)[:RC_ENTRIES]
                    source = 'operator'
                if o_diff is not None:
                    hdr[7] = o_diff
                if o_stages:
                    stages = max(1, min(RC_ENTRIES, o_stages))
                bad = sorted(set(songs[:stages]) & RC_BAD_SONG_IDS)
                if bad:
                    self.log('!! challenge %d contains song id(s) %s, which hang'
                             ' the client -- see docs/protocol.md'
                             % (chal, ','.join(str(x) for x in bad)))
                self.log('     RC info: challenge %d (sel %d,%d), %s, difficulty'
                         ' %d, week %d, songs %s'
                         % (chal, self.rc_sel[0], self.rc_sel[1], source,
                            hdr[7], week,
                            ','.join(str(x) for x in songs[:stages])))
                self.rc_songs[chal] = list(songs[:stages])
                return rc_info(hdr=hdr, songs=songs, flags=self.args.rc_flags,
                               vary=self.args.rc_vary, stages=stages)
            first = self.args.rc_first_song + chal * RC_ENTRIES
            if first + RC_ENTRIES > RC_SONG_IDS:
                first = self.args.rc_first_song
            bad = sorted(set(range(first, first + stages)) & RC_BAD_SONG_IDS)
            if bad:
                self.log('!! serving song id(s) %s, which hang the client -- see'
                         ' docs/protocol.md'
                         % ','.join(str(x) for x in bad))
            self.log('     RC info: challenge %d (sel %d,%d), difficulty %d, '
                     'songs %d..%d'
                     % (chal, self.rc_sel[0], self.rc_sel[1],
                        hdr[7], first, first + stages - 1))
            self.rc_songs[chal] = [first + i for i in range(stages)]
            return rc_info(first_song=first, hdr=hdr,
                           flags=self.args.rc_flags,
                           vary=self.args.rc_vary, stages=stages)
        if resp_opcode == 0x5003 and self.is_sn:
            # u32 status, then one u8 into ctx+0x12e61, which DATA08 copies
            # into the card's counter (0x00a4b89c). It was going out empty.
            return struct.pack('>I', 0) + bytes([0])
        if resp_opcode == 0x5003 and self.args.serve_rc and not self.is_sn:
            pid = (struct.unpack('>i', self.rc_try_req[:4])[0]
                   if len(self.rc_try_req) >= 4
                   else (self.player or {}).get('id', 0))
            c0, c1 = results.rc_tries(pid, self.rc_now_week(),
                                      self.args.svr_time or None)
            self.log('     tries this week: card 0 %d, card 1 %d' % (c0, c1))
            return rc_trycount(c0, c1)
        if resp_opcode == 0x5010 and self.args.serve_rc and not self.is_sn:
            return rc_idlist(range(self.args.rc_entries))
        # 0x6001/0x6002/0x6003 -- the ranking tables, shared by all three
        # ranking RPCs.
        #
        # **THE OPENER IS NEVER OPTIONAL.** This block used to be gated on
        # --stat-probe entirely, on the comment "an empty body already reads as
        # status 0 / no rows, which is a legitimate empty board". That was an
        # assumption, never tested, and it is WRONG: with --stat-probe off, a
        # 0x6000 request answered with three zero-length parts **killed the
        # PCSX2 process outright** (2026-08-28). Not a guest hang -- the
        # emulator died, TCP RST to the gate, and emulog.txt simply stops one
        # keepalive after the empty 0x6003, with no exception logged.
        #
        # The opener 0x00857b90 reads a u32 status into ctx+0x4900 and then
        # zeroes a record and resets the count at ctx+0x2a494. Handing it a
        # zero-length payload means that u32 is read from past the end of the
        # payload, and the count it is supposed to reset never gets reset.
        # Serve the four status bytes ALWAYS; --stat-probe now only decides
        # whether the row VALUES are sentinels, never whether a body exists.
        if resp_opcode == 0x6001:
            return struct.pack('>I', 0)
        if resp_opcode == 0x6002:
            with WAITING_LOCK:
                rows = [w for w in LOBBY if w.player is not None]
            rows = rows[:RANKING_CAP - 1] or [self]
            self.log('     ranking board: %d row(s)%s'
                     % (len(rows), ' (probe values)' if self.args.stat_probe
                        else ''))
            # SuperNOVA's row is 45 bytes, Extreme 2's is 49, and 0x6002 is a
            # read-until-empty loop -- so serving the Extreme 2 row put a
            # PHANTOM entry on the end of the board. Observed on screen
            # 2026-09-14: two real players drew four rows, the last two
            # nameless "NO DATA". Same bug as the 0x4212 player list, one
            # message over.
            if self.is_sn:
                return b''.join(
                    ranking_entry_sn(i + 1, w.who(),
                                     (w.player or {}).get('id', 0),
                                     (w.player or {}).get('dancer', 0))
                    for i, w in enumerate(rows))
            if self.args.stat_probe:
                return b''.join(
                    ranking_entry(i + 1, w.who(),
                                  (w.player or {}).get('dancer', 0),
                                  probe=True)
                    for i, w in enumerate(rows))
            return self.x2_ranking_body(rows)
        # The three PERSONAL DATA logs -- same rule, same reason. log_open() is
        # `u32 status + u8 count`, so an empty body delivers NEITHER. A player
        # with no history has count 0, which still needs those five bytes on
        # the wire. Only the RECORDS are conditional on having any.
        if resp_opcode in LOG_GROUPS:
            name, sizes, cap = LOG_GROUPS[resp_opcode]
            if self.args.stat_probe:
                n = min(self.args.stat_probe_logs, cap - 1)
            elif self.is_sn:
                n = 0
            else:
                n = min(len(self.personal_log(name)), cap - 1)
            self.log('     %s log: %d record(s)' % (name, n))
            return log_open(n)
        if resp_opcode in LOG_DATA_OF:
            sizes = LOG_DATA_OF[resp_opcode]
            cap = (120 if resp_opcode == 0x4118 else 60) - 1
            if self.args.stat_probe:
                return log_records(sizes, min(self.args.stat_probe_logs, cap),
                                   probe=True)
            if self.is_sn:
                return b''
            rows = self.personal_log(LOG_KIND_OF[resp_opcode])[:cap]
            return log_rows(sizes, rows) if rows else b''
        # 0x4103 GetPlayerInfo -- the player's own stat record, 145 bytes. The
        # u32 status comes FIRST and gates the rest: the parser (0x0085a750)
        # stops dead on a non-zero status, so 0 is mandatory. Served as zeros
        # until the fields are identified; --stat-probe makes each one legible.
        if resp_opcode == 0x4103:
            if self.player is None:
                return b''
            if self.is_sn:
                return playerinfo_record_sn(self.player.get('id', 0), self.who(),
                                            self.player.get('dancer', 0))
            pid = self.player.get('id', 0)
            return playerinfo_record(pid, self.who(),
                                     self.player.get('dancer', 0),
                                     probe=self.args.stat_probe,
                                     stats=info_stats(self.x2_stats(pid)))
        if resp_opcode == 0x3012:
            with STATE_LOCK:
                files = list(account(self.acct)['player_files'])
            if files:
                self.log('     serving %d player file(s): %s'
                         % (len(files), ', '.join(f['name'] for f in files)))
            if self.is_sn:
                return playerfile_list_sn(files)
            return playerfile_list(files, probe=self.args.stat_probe)
        if resp_opcode == 0x200a and self.args.serve_svrinfo:
            return svrinfo_record(
                ident=self.args.probe_info_id,
                type_=self.args.svr_type,
                users=self.args.svr_users,
                addr=self.advertised_host(),
                name=self.args.svr_name,
                extra=wrap_news(self.args.motd, self.args.motd_wrap))
        if resp_opcode == 0x0004:
            # u32 BE status -> ctx+0x4900. 0 = success.
            return struct.pack('>I', self.args.hello_status & 0xffffffff)
        if resp_opcode == 0x2002 and self.local_port in self.args.sn_ports:
            # SuperNOVA's SvrList BEGIN is NOT empty -- Extreme 2's is. This is
            # the first real protocol divergence found between the two games.
            #
            # Parser 0x0026b080 does:
            #     s2 = read_u32be(msg, &ctx[0x2350])
            #     if (s2 != 0) return s2;          <-- bails on a SHORT READ
            #     ctx[0x3120] = 0; clear 200 entries;
            #     ctx[0x3114] |= 2; ctx[0x310c] = ctx[0x2354];
            #
            # ctx+0x2350 is the standard "last result" slot -- the same one the
            # errno dispatch 0x00271370 reads (it maps -0x6e/-110 &c). So the
            # u32 is a RESULT CODE, exactly like 0x0004's status into ctx+0x4900.
            #
            # Sending this empty made the read fail, so the list was never reset
            # and ctx+0x2350 kept a stale error -> the client completed the gate,
            # said goodbye, and re-ran the whole login every ~21 s without ever
            # dialling the account server.
            return struct.pack('>I', self.args.sn_svrlist_status & 0xffffffff)
        if resp_opcode == 0x2003 and self.args.serve_svrlist:
            # ONE ENTRY PER SERVER TYPE, all pointing back at us.
            #
            # TYPE (entry+0x04) is what 0x0085b990(ctx, type, &idx) scans for,
            # and it is ALSO the connection slot index (0x00858870 dials into
            # `ctx + type*0x20`). Slot 0 is the gate, which login case 5
            # deliberately closes, so the account server has to be TYPE 1 on its
            # own fresh socket -- it is not a reuse of the gate connection.
            #
            # HOST (entry+0x1f, 15 bytes) and PORT (entry+0x0a, u16) are the
            # address actually dialled. Serving the name "DDR" here is what made
            # the account connect fail in 0.17 s with nothing in this log: the
            # client was resolving "DDR", not connecting to us.
            out = b''
            for t in range(self.args.svrlist_types):
                out += svrlist_entry(
                    n0=t, type_=t,
                    label=self.args.svr_label,
                    host=self.advertised_host(),
                    # Send SuperNOVA to its OWN port so the account/lobby
                    # connection arrives somewhere we can still tell the games
                    # apart -- otherwise both land on 9573 and the 0x3012 layout
                    # would have to be guessed from behaviour. 19570 is the
                    # second half of the u16 pair at 0x002d013c, whose purpose
                    # was otherwise unexplained.
                    port=(self.args.sn_svr_port if self.is_sn
                          else (self.args.svr_port or self.args.port)),
                    b=(self.args.probe_b if self.args.probe_b
                       else live_users()),
                    c=self.args.probe_c)
            return out
        return b''


def main():
    ap = argparse.ArgumentParser(description='DDR Extreme 2 / SuperNOVA stub gate server')
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=9573)
    ap.add_argument('--keyfile', default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                      'xorkey.bin'))
    ap.add_argument('--reply-empty', action='store_true',
                    help='answer every request with the correct response opcode '
                         'sequence and a zero-length body')
    ap.add_argument('--serve-svrinfo', action='store_true',
                    help='put a real server record in the SvrInfo 0x200a part')
    ap.add_argument('--svr-addr', default='auto',
                    help='address string in the server record (max 19 chars). '
                         '"auto" uses whatever address the client reached this '
                         'server on, or for a client arriving from the internet '
                         'the public address (see --public-addr), which needs '
                         'no configuration. An explicit value is sent to EVERY '
                         'client, LAN included.')
    ap.add_argument('--public-addr', default='auto',
                    help='our address for clients arriving from the internet, '
                         'when the one they connected to is a LAN address '
                         'behind a port forward. "auto" looks it up over STUN '
                         'the first time such a client connects and re-checks '
                         'it every few minutes, so a dynamic IP needs no '
                         'restart. "off" gives them the local address. '
                         'Anything else is a name or address to resolve.')
    ap.add_argument('--svr-name', default='DDR', help='server name (max 64)')
    ap.add_argument('--motd', default='',
                    help='SvrInfo notification/MOTD text -- the 513-byte '
                         'NUL-terminated field at struct +0x5b. CONFIRMED live: '
                         'the client shows this in a notification box (an empty '
                         'string produced an empty box).')
    ap.add_argument('--motd-wrap', type=int, default=40,
                    help='hard-wrap the MOTD at this column, since the client '
                         'does not wrap it. 0 leaves it as typed.')
    ap.add_argument('--verify-login', action='store_true',
                    help='check the login password. The 0x3003 blob carries '
                         'MD5(username + a constant challenge + password), so '
                         'the digest is stable per password. The first login '
                         'for a username records its digest; later logins must '
                         'match or are rejected. It stops anyone entering an '
                         'account without its password; it does not recover '
                         'the password. Off by default, which trusts any '
                         'login and auto-creates accounts as before.')
    ap.add_argument('--login-reject-status', type=int, default=-0x16,
                    help='the 0x3004 status returned to a rejected login. The '
                         'client recognises a fixed set of negatives and '
                         'handles them cleanly (-0x78,-0x69,-0x63,-0x50,-0x49,'
                         '-0x47,-0x3e,-0x3d,-0x24,-0x23,-0x21,-0x20,-0x1f,'
                         '-0x1e,-0x19,-0x16); which one shows the nicest '
                         'message is unconfirmed on screen.')
    ap.add_argument('--svr-id', type=int, default=1)
    ap.add_argument('--svr-type', type=int, default=1)
    ap.add_argument('--svr-users', type=int, default=0)
    ap.add_argument('--hello-status', type=int, default=0,
                    help='u32 status returned in the 0x0004 reply to the 0x0003 '
                         'session hello (0 = success)')
    ap.add_argument('--serve-svrlist', action='store_true',
                    help='put a real entry in the SvrList 0x2003 part')
    ap.add_argument('--svr-host', default='',
                    help='SvrList entry+0x1f (15 chars) -- THE ADDRESS THE '
                         'CLIENT DIALS for every server after the gate. '
                         'Defaults to --svr-addr. Must be something the PS2 '
                         'can reach: a dotted-quad avoids DNS entirely.')
    ap.add_argument('--svr-port', type=int, default=0,
                    help='SvrList entry+0x0a (u16) -- THE PORT THE CLIENT '
                         'DIALS. Defaults to --port.')
    ap.add_argument('--svr-label', default='DDR',
                    help='SvrList entry+0x0e (16 chars) -- display label only, '
                         'nothing dials it')
    ap.add_argument('--sn-ports', default='19573,19570',
                    help='ports on which the peer is assumed to be SuperNOVA '
                         'rather than Extreme 2. SuperNOVA dials 19573 (service '
                         'table 0x002d013c); Extreme 2 dials 9573. Used to send '
                         'SuperNOVA-only fields without changing Extreme 2.')
    ap.add_argument('--sn-block-max', type=int, default=1000,
                    help="second u16 of SuperNOVA's 0x4201 block record; Extreme "
                         "2 has no equivalent field. Presumed block capacity.")
    ap.add_argument('--sn-svr-port', type=int, default=19570,
                    help='port advertised in the SvrList to SuperNOVA clients '
                         '(Extreme 2 keeps --svr-port). Must be in --also-listen '
                         'AND in --sn-ports, or the account connection lands '
                         'somewhere the game cannot be identified.')
    ap.add_argument('--sn-svrlist-status', type=int, default=0,
                    help="u32 BE result code in SuperNOVA's 0x2002 SvrList "
                         "BEGIN -> ctx+0x2350. 0 = success.")
    ap.add_argument('--svrlist-types', type=int, default=4,
                    help='serve one entry per TYPE 0..N-1. TYPE indexes the '
                         '4-slot connection table (ctx+type*0x20), so 4 is the '
                         'safe maximum even though the lookup allows 0..4.')
    ap.add_argument('--probe-info-id', type=int, default=9031,
                    help='SvrInfo u32 at struct +0x00 (port probe)')
    ap.add_argument('--probe-b', type=int, default=0,
                    help='override the SvrList USER COUNT (struct +0x08). 0 '
                         'means serve the live lobby population. Identified on '
                         'screen 2026-08-27: sending 777 here put 777 in the '
                         '"DDR 0000/1000" readout.')
    ap.add_argument('--probe-c', type=int, default=0,
                    help='SvrList u16 at struct +0x0c (unidentified)')
    ap.add_argument('--also-listen', default='',
                    help='comma-separated extra TCP ports to accept on, so a '
                         'connection to a probe port is visible')
    ap.add_argument('--svr-time', type=int, default=0,
                    help='u32 the client takes as server time (0 = wall clock). '
                         'Unverified whether the epoch is UNIX.')
    ap.add_argument('--rc-flag', type=int, default=None,
                    help='the WEEK NUMBER served in 0x5012 and 0x5013. Left '
                         'unset it is derived from the clock and advances by '
                         'itself every seven days, which is what makes an '
                         'unattended server show a running event. Legal range '
                         'is 1..60: the tab-bar handler hides the Ranking '
                         'Challenge tab unless 0 < week < 61, and the widget '
                         'clamps the same way. 0 hides the tab.')
    ap.add_argument('--serve-block', action='store_true',
                    help='answer GetBlockList 0x4201 with one real block '
                         'instead of an empty list')
    ap.add_argument('--block-name', default='DDR BLOCK 1')
    ap.add_argument('--stat-probe', action='store_true',
                    help='fill every unidentified stat field in 0x4212 '
                         'GetPlayerList and 0x4103 GetPlayerInfo with a '
                         'sentinel that spells out its own field number (field '
                         '7 -> 777, field 14 -> 141414). Look at the player '
                         'list / detail screen and the digits say which field '
                         'drives which number. Prints a legend at startup.')
    ap.add_argument('--serve-rc', action='store_true',
                    help='serve 0x5001 GetRCInfo, 0x5003 GetRCTrycount and '
                         '0x5010 GetRCIdList instead of empty bodies. Without '
                         'it the RC tab lists ten copies of one song -- the '
                         'song id is a u16 we were sending as zero -- and 00/00 '
                         'tries.')
    ap.add_argument('--rc-flags', default='',
                    help='the TEN per-entry u8s in 0x5001, comma separated. '
                         'Default is 0 followed by the game\'s own default play '
                         'options %s -- the tuple both card builders compare '
                         'against to decide whether a challenge counts as '
                         '"options changed". They are indices, and a sweep of '
                         '31..40 froze the client on entering the lobby, so '
                         'change ONE at a time and keep values small.'
                         % (','.join(str(x) for x in RC_DEFAULT_OPTS)))
    ap.add_argument('--rc-difficulty', type=int, default=0,
                    help='the challenge DIFFICULTY, header field R+0x10, 0..%d. '
                         'It picks which of a song\'s three per-difficulty '
                         'values every row of the challenge is played and drawn '
                         'at (FUN_001f75b0: 2 -> song+0x20, 1 -> +0x24, '
                         '0 -> +0x28). Ignored if --rc-hdr is given.'
                         % (RC_DIFFICULTIES - 1))
    ap.add_argument('--rc-stages', type=int, default=RC_ENTRIES,
                    help='how many of the ten rows are real (1..10). The rest '
                         'are terminated with song id 0xffff, which the '
                         'client\'s own loop breaks on.')
    ap.add_argument('--rc-vary', type=int, default=None,
                    help='set this per-entry byte (0-9) to the ENTRY INDEX '
                         'instead of a constant, so one run tests ten values. '
                         'Entry i is stage i of the challenge.')
    ap.add_argument('--rc-hdr', default='',
                    help='the eight 0x5001 header values (u32,u8,u32,u8 x5), '
                         'comma separated. Same warning as --rc-flags.')
    ap.add_argument('--rc-tries', type=int, default=3,
                    help='tries ALLOWED per RC challenge (0x5003)')
    ap.add_argument('--rc-entries', type=int, default=2,
                    help='how many RC ids to advertise in 0x5010 (max 120)')
    ap.add_argument('--rc-first-song', type=int, default=None,
                    help='pin the ten 0x5001 rows to consecutive song ids '
                         'starting here, instead of generating them. Left '
                         'unset, each challenge gets ten ids derived from the '
                         'week, so the lineup changes weekly on its own and '
                         'never includes an id known to hang the client. If '
                         'you do pin it, keep it at 11 or above: wire id 8 '
                         'hangs the online scene (docs/protocol.md).')
    ap.add_argument('--sched-remaining', type=int, default=None,
                    help='0x5012 field 3: seconds left in the current Ranking '
                         'Challenge week. Left unset it counts down to the '
                         'real week rollover. This is a DURATION, not a '
                         'timestamp; the client draws it as hours:minutes and '
                         'clamps at 999:59, so sending an absolute clock value '
                         'just pins it to the clamp. 0 hides the countdown.')
    ap.add_argument('--sched-inert', type=int, default=0,
                    help='0x5012 field 2. INERT: the client copies it to '
                         'DAT_01047ca8 and nothing in the ELF or any DATA0x '
                         'overlay ever reads it back. Exposed only so the '
                         'claim can be re-tested.')
    ap.add_argument('--push-5013', type=int, default=None,
                    help='push 0x5013 WEEK ROLLOVER with this week number '
                         'after --push-delay. WARNING: this is not a refresh. '
                         'The online scene reacts by entering '
                         'NetGameShutdownMain -- modal, OutRoom, network '
                         'teardown -- so the client leaves the lobby. That is '
                         'the mechanism, not a bug.')
    ap.add_argument('--stat-probe-logs', type=int, default=3,
                    help='how many synthetic records to put in each PERSONAL '
                         'DATA log under --stat-probe (default 3). Values read '
                         'as RRRFF -- record index then field number.')
    ap.add_argument('--stat-probe-small', action='store_true',
                    help='with --stat-probe, use 100+N instead of repeated '
                         'digits. Several stat widgets are only 4-5 digits wide '
                         'and CLAMP, so 111111/161616/181818 all render as '
                         '99999 and cannot be told apart; 100+N always fits.')
    ap.add_argument('--push-4222', action='store_true',
                    help='EXPERIMENT. Push 0x4222 -- the fourth member of the '
                         'GetPlayerList group, which only the server can send -- '
                         'once the client reaches the lobby. The body is ONE '
                         '0x4212 record and that is now confirmed field by '
                         'field against FUN_0085b020; the push goes to every '
                         'OTHER player in the lobby (an arrival announcement, '
                         'which is what should visibly add a row) and then back '
                         'to the pushing client, where the id already matches '
                         'and nothing should appear. A row appearing in the '
                         'sender\'s own list means the upsert is not keying on '
                         'the id the way the parser says.')
    ap.add_argument('--push-4500', type=int, default=None,
                    help='EXPERIMENT. Push 0x4500 with this many SECONDS as a '
                         'big-endian u32. FUN_001e84c0 converts that integer to '
                         'float, counts it down one frame per tick and clears '
                         'the armed flag once it reaches 60.0, so anything <= 60 '
                         'arms and disarms in the same frame. Try 120.')
    ap.add_argument('--sn-comp', default='none', choices=('none', 'open'),
                    help='SuperNOVA: serve one open competition in the 0x5032 '
                         'list. "none" is the empty list, which the client '
                         'renders as "The competition event is not being held '
                         'at the moment". UNTESTED -- the start/end pair is '
                         'inferred from shape')
    ap.add_argument('--sn-comp-name', default='DDR ONLINE CHALLENGE',
                    help='SuperNOVA: competition name, 32 bytes on the wire')
    ap.add_argument('--sn-comp-future', type=int, default=0,
                    help='SuperNOVA: also advertise ONE not-yet-open '
                         'competition, starting this many seconds from '
                         'now, in the 0x5036 list. 0 (default) serves '
                         'that list empty, which the client reports as '
                         '"There are no future competitions currently '
                         'planned." -- correct, not broken.')
    ap.add_argument('--sn-comp-future-name', default=None,
                    help='SuperNOVA: name for the --sn-comp-future '
                         'event. Defaults to the open event name with '
                         '" 2" appended.')
    ap.add_argument('--sn-comp-back', type=int, default=86400,
                    help='SuperNOVA: seconds before now the competition opened')
    ap.add_argument('--sn-comp-ahead', type=int, default=30 * 86400,
                    help='SuperNOVA: seconds from now until it closes')
    ap.add_argument('--sn-songs', default='none',
                    choices=('none', 'online', 'all'),
                    help='SuperNOVA: which songs to mark available in the '
                         '0x8002 list. "online" unlocks the five online-only '
                         'songs (felw/nizi/punc/silv/trim, ids 0x4a-0x4e); '
                         '"all" unlocks all 79 and takes two DATA frames. '
                         'UNTESTED against a client -- default is the empty '
                         'list we have always served')
    ap.add_argument('--sn-song-extra', type=int, default=0,
                    help='SuperNOVA: the trailing s32 of each 0x8002 record. '
                         'FUN_0027e970 returns it and the parser sums it into '
                         'ctx+0x2c60 as a total; its meaning is NOT known, so '
                         'this is a knob for finding out, not a setting')
    ap.add_argument('--sn-rule-mask', default='1,1,1,1',
                    help='SuperNOVA: the four u8 of 0x441e GetRuleMask. Extreme '
                         "2's three are SCORE,COMBO,SURVIVAL; SuperNOVA reads a "
                         'fourth and ships no strings naming any of them')
    ap.add_argument('--push-delay', type=float, default=3.0,
                    help='seconds to wait before each experimental push, so it '
                         'cannot overwrite the reply an in-flight RPC is still '
                         'polling for (netwk+0x8d8 is checked once per frame)')
    ap.add_argument('--match-tail', default='0,0,0,0',
                    help='the four tail fields of the 0x44b0 match record, in '
                         'WIRE order: R+0x00 (u8) is the ONLINE GAME MODE, 0..3 '
                         '(the client permutes them to 1,3,2,4 in '
                         '_DAT_006f1698); R+0x01 (u8) is read by nothing; '
                         'R+0x04 (u16) is THE SONG THE MATCH PLAYS, a table '
                         'index bounded 0..%d and clamped here; R+0x02 (u8) is '
                         'read by nothing. All zero is what every match so far '
                         'has run under -- mode 1, song 1. Change ONE at a '
                         'time.' % (RC_SONG_IDS - 1))
    ap.add_argument('--rule-mask', default='1,1,1',
                    help='the three 0x441e GetRuleMask flags -- score, combo, '
                         'survival -- which are the head-to-head win conditions '
                         'the client draws a results column for (FUN_00298040 '
                         'prints those three names). Extreme 2 only; each is a '
                         'boolean tested == 1. Served empty until 2026-08-28, '
                         'which was a short read the client happened to '
                         'tolerate.')
    ap.add_argument('--start-delay', type=float, default=0.5,
                    help='seconds to wait after both clients have run '
                         'GetStartStaus before pushing 0x4412, the PLAY START '
                         'gate. Must be > 1/60 s: the RPC polls netwk+0x8d8 '
                         'once per frame and 0x4412 overwrites the 0x4411 it '
                         'is waiting for.')
    ap.add_argument('--pair-sweep', action='store_true',
                    help='OBSOLETE experiment, kept so the negative result '
                         'stays reproducible: instead of pushing 0x44b0, sweep '
                         'the push-only lobby opcodes and the 0x4400 '
                         'notification types at both paired clients. Every one '
                         'of them was proven inert -- 0x44b0 is the real match '
                         'message. See docs/protocol.md.')
    ap.add_argument('--pair-push', default='0x4351,0x441c,0x4450,0x44a1',
                    help='comma-separated opcodes to push at a paired client, '
                         'one at a time, --pair-gap seconds apart')
    ap.add_argument('--pair-notify', default='2,10,5,7,17,4,6',
                    help='0x4400 peer-channel notification TYPE bytes to sweep '
                         'after the plain-opcode sweep. Type 9 is excluded on '
                         'purpose: it is the NET_WORK_TYPE_DEAD fatal path.')
    ap.add_argument('--pair-gap', type=float, default=12.0,
                    help='seconds between sweep pushes -- long enough to tell '
                         'on screen which one did something')
    ap.add_argument('--sn-news', action='append', default=None,
                    metavar='TITLE|BODY',
                    help='SuperNOVA only: one item for the ONLINE PLAY -> '
                         'Information feed (0x3120, fetched at login). '
                         'Repeat for more. TITLE is capped at 64 bytes '
                         'and BODY at 512; with no "|" the text is used '
                         'for both. Omit entirely and no 0x3122 frame is '
                         'sent at all, which is what the client wants for '
                         'an empty feed.')
    ap.add_argument('--sn-news-wrap', type=int, default=40,
                    help='SuperNOVA only: hard-wrap news bodies at this '
                         'many characters. The client does NOT wrap -- a '
                         'long line runs off the right edge and is cut -- '
                         'so the breaks have to be in what the server '
                         'sends. 0 leaves the text untouched.')
    ap.add_argument('--sn-news-fields', default=None,
                    help='SuperNOVA only: override the THREE UNIDENTIFIED '
                         's32 at the head of every news record, as a,b,c. '
                         'Default is (index, YYYYMMDD, HHMM) from the '
                         'clock -- a guess, since the screen shows a date '
                         'and a time but nothing says in what encoding.')
    ap.add_argument('--friend-bytes', default=None,
                    help='SuperNOVA only: force the THREE UNIDENTIFIED trailing '
                         'bytes of every 0x3084 friends-list record, as '
                         'a,b,c. Left off, they are served as (relationship '
                         'state 0=sent/1=received/2=accepted, online, dancer) '
                         '-- a guess. Pass constants and read the screen to '
                         'settle what each one draws, the way --stat-probe '
                         'settled the player record.')
    ap.add_argument('--friend-probe', action='store_true',
                    help='SuperNOVA only: serve twelve SYNTHETIC friends '
                         'records instead of the real list, one per '
                         'combination of the three trailing bytes, each '
                         'NAMED after the bytes it carries (F-102 is '
                         'byte0=1 byte1=0 byte2=2). Open the Friends and '
                         'Ignore screens and the names say which '
                         'encoding lands where.')
    ap.add_argument('--friend-push', action='store_true',
                    help='SuperNOVA only: after a friend operation, re-send '
                         'our own 0x3084 so the screen refreshes without '
                         'reopening the list. **KNOWN HAZARD, off by default:** '
                         'the record count lives at ctx+0x2c78 and the BEGIN '
                         '0x3082 does not reset it -- only the request builder '
                         '0x0026c610 does -- so a bare 0x3084 APPENDS and the '
                         'list fills with duplicates. Reopening the list is '
                         'the safe refresh. Kept for experiments.')
    ap.add_argument('--sn-match-push', default='0x4a13',
                    help='SuperNOVA only: which match push to send when two '
                         'clients are both advertising. 0x4a13 (default) is '
                         'the one whose consumer copies the opponent record '
                         'out and sets the scene mode to 2; 0x4a04 sets mode 1 '
                         'and copies nothing. "both" sends 0x4a04 then 0x4a13, '
                         '"off" disables the push. The two are the SuperNOVA '
                         'counterpart of Extreme 2 0x44b0 -- see '
                         'build_sn_match_record. UNVERIFIED on the client.')
    ap.add_argument('--sn-search-push', default='0x4a04',
                    help='SuperNOVA only: the match push sent to an '
                         'AUTO-SEARCHER that is matched into an existing '
                         'room. 0x4a04 (default) makes it a guest, which is '
                         'what it is; 0x4a13 makes it a second room owner. '
                         'See try_sn_search.')
    ap.add_argument('--sn-no-host-push', dest='sn_host_push',
                    action='store_false', default=True,
                    help='SuperNOVA only: do NOT send the host 0x4325 '
                         'when someone matches into its room. The host '
                         'needs a different message from the searcher '
                         '-- 0x4a13 moves the searcher, 0x4325 moves '
                         'the host -- so turning this off leaves the '
                         'host stuck on the room screen, which is what '
                         'it did before the push existed.')
    ap.add_argument('--sn-comp-songs', default='0',
                    help='SuperNOVA: up to ten song ids for the tournament '
                         'built from the --sn-comp flags, comma separated, '
                         'one per stage (the u16 at the start of each 0x5001 '
                         'stage record). A short list repeats. Ignored when '
                         'sn_competitions.json exists.')
    ap.add_argument('--sn-comp-file', default='',
                    help='SuperNOVA: a JSON list of competitions (see '
                         'sn_competitions). Default: sn_competitions.json '
                         'beside the state file, used only if it exists.')
    ap.add_argument('--sn-addr-delay', type=float, default=0.5,
                    help='SuperNOVA: seconds between telling the host '
                         'that someone joined (0x4325) and telling it '
                         'where they are (0x4b01). The address is '
                         'accepted only if it names the opponent the '
                         'scene already knows (0x00a4a7d4 compares '
                         'scene->0x32c against ctx+0x141c8), so sending '
                         'both at once means the second is discarded.')
    ap.add_argument('--udp-relay', action='store_true',
                    help='SuperNOVA: relay the peer-to-peer gameplay UDP '
                         'through this server instead of telling the two '
                         'consoles to dial each other. SuperNOVA dials '
                         'the opponent directly, which two consoles under '
                         'one emulator cannot do -- PCSX2 translates '
                         'outbound UDP and forwards nothing inbound -- so '
                         'without this a match reaches the play screen and '
                         'no inputs cross. See server/udprelay.py.')
    ap.add_argument('--relay-addr', default=None,
                    help='the relay address AS THE CONSOLE SEES IT, like '
                         '--svr-addr and for the same reason. Defaults to the '
                         'address each console is given for the server.')
    ap.add_argument('--relay-base-port', type=int, default=19600,
                    help='first UDP port of the relay pool (default 19600)')
    ap.add_argument('--relay-pairs', type=int, default=8,
                    help='how many simultaneous matches the relay can '
                         'carry; each takes two ports (default 8)')
    ap.add_argument('--sn-start-open', action='store_true',
                    help='SuperNOVA only: answer each 0x4411 '
                         'GetStartStaus at once instead of holding the '
                         'first until the opponent has readied too. '
                         'Holding is what starts the two peer connects '
                         'together (see hold_sn_start); this restores '
                         'the old behaviour for comparison.')
    ap.add_argument('--sn-match-song', type=int, default=0,
                    help='SuperNOVA only: the song id in the match push, the '
                         'u16 that lands at match record +0x1a. NOT put '
                         'through the 0x002e7850 table -- that one is Extreme '
                         "2's -- and nothing in the parser bounds-checks it.")
    ap.add_argument('--sn-pair-delay', type=float, default=0.0,
                    help='SuperNOVA only: seconds to wait before the match '
                         'push. Should not be needed -- SuperNOVA signals a '
                         'push by setting a FLAG BYTE, which the next message '
                         'does not overwrite, so the Extreme 2 timing trap '
                         '(one "last opcode" word, hence --start-delay) has no '
                         'equivalent here. Present to test that claim.')
    ap.add_argument('--pair', action='store_true',
                    help='EXPERIMENT: when two lobby connections are both '
                         'advertising a room (0x4330 with no 0x4340 yet), push '
                         '0x4351 to both to see whether that is the join '
                         'notification')
    ap.add_argument('--state-file', default='',
                    help='JSON file holding the two player-file slots; defaults '
                         'to state.json beside --keyfile')
    args = ap.parse_args()
    args.match_tail = [int(x, 0) for x in args.match_tail.split(',') if x.strip()]
    args.rc_flags = [int(x, 0) for x in args.rc_flags.split(',') if x.strip()]
    args.rc_hdr = [int(x, 0) for x in args.rc_hdr.split(',') if x.strip()]
    args.rule_mask = [int(x, 0) for x in args.rule_mask.split(',') if x.strip()]
    if not 0 <= args.rc_difficulty < RC_DIFFICULTIES:
        sys.exit('--rc-difficulty is an index 0..%d: R+0x10 selects one of '
                 'three per-song difficulty values and nothing bounds it in '
                 'the client' % (RC_DIFFICULTIES - 1))
    args.pair_push = [int(x, 0) for x in args.pair_push.split(',') if x.strip()]
    args.sn_comp_songs = [int(x, 0) & 0xffff
                          for x in args.sn_comp_songs.split(',')
                          if x.strip()][:SN_STAGES] or [0]
    if args.sn_news_fields:
        args.sn_news_fields = tuple(
            int(x, 0) for x in args.sn_news_fields.split(','))[:3]
        if len(args.sn_news_fields) != 3:
            ap.error('--sn-news-fields wants exactly three values, a,b,c')
    if args.friend_bytes:
        args.friend_bytes = tuple(
            (int(x, 0) & 0xff) for x in args.friend_bytes.split(','))[:3]
        if len(args.friend_bytes) != 3:
            ap.error('--friend-bytes wants exactly three values, a,b,c')
    args.pair_notify = [int(x, 0) for x in args.pair_notify.split(',') if x.strip()]
    if 9 in args.pair_notify:
        sys.exit('refusing type 9: NET_WORK_TYPE_DEAD is a fatal path')

    state_load(args.state_file
               or os.path.join(os.path.dirname(os.path.abspath(args.keyfile)),
                               'state.json'))

    args.sn_ports = set(int(p) for p in str(args.sn_ports).split(',') if p.strip())
    args.sn_rule_mask = [int(x) for x in str(args.sn_rule_mask).split(',') if x.strip()]

    keybox = {'key': None}
    if os.path.exists(args.keyfile):
        keybox['key'] = open(args.keyfile, 'rb').read(4)
        print('loaded XOR key %s from %s'
              % (binascii.hexlify(keybox['key']).decode(), args.keyfile))

    ports = [args.port]
    for p in args.also_listen.split(','):
        p = p.strip()
        if p and int(p) not in ports:
            ports.append(int(p))
    listeners = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((args.host, p))
        except OSError as e:
            print('!! cannot bind %s:%d (%s) -- skipping' % (args.host, p, e), flush=True)
            continue
        s.listen(8)
        listeners.append(s)
    if not listeners:
        sys.exit('no ports could be bound')
    print('gate listening on %s ports %s  (reply-empty=%s svrinfo=%s svrlist=%s)'
          % (args.host, ','.join(str(x.getsockname()[1]) for x in listeners),
             args.reply_empty, args.serve_svrinfo, args.serve_svrlist), flush=True)
    if args.serve_svrlist:
        where = args.svr_host or args.svr_addr
        if not where or where == 'auto':
            where = 'the address each client connects to'
        else:
            where = '%s:%d' % (where, args.svr_port or args.port)
        print('SvrList: %d entries, TYPE 0..%d, each pointing the client at %s'
              % (args.svrlist_types, args.svrlist_types - 1, where), flush=True)
        print('  TYPE 1 is the account server; expect a SECOND connection there '
              'right after the gate hangs up', flush=True)
    globals()['PUBLIC'] = publicaddr.PublicAddress(
        args.public_addr, log=lambda m: print(m, flush=True))
    print('internet clients: public address %s' % PUBLIC.describe(), flush=True)
    if args.udp_relay:
        globals()['RELAY'] = udprelay.Relay(
            args.host, args.relay_base_port, args.relay_pairs,
            log=lambda m: print(m, flush=True)).start()
    if args.stat_probe:
        globals()['PROBE_SMALL'] = args.stat_probe_small
        print(probe_legend(), flush=True)
    print('point dx2gate01.konamionline.com at this machine\n', flush=True)
    while True:
        ready, _, _ = select.select(listeners, [], [])
        for s in ready:
            conn, addr = s.accept()
            local_port = s.getsockname()[1]
            Session(conn, addr, args, keybox, local_port).start()


if __name__ == '__main__':
    main()
