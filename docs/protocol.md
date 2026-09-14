# Protocol

Wire protocol for the online modes of DDR Extreme 2 (SLUS-21174) and
DDR SuperNOVA (SLUS-21377).

The two games share a backend, a frame format and an obfuscation key. Their
payloads are not interchangeable, and the differences are not always visible
as a length mismatch. Section [Differences between the two games](#differences-between-the-two-games)
lists every one found so far.

Addresses in this document are virtual addresses in the named executable.
Extreme 2 addresses refer to `SLUS_211.74` or `DATA07.BIN`; SuperNOVA addresses
refer to `SLUS_213.77` unless stated otherwise.

---

## Architecture

```
DNS -> gate -> [gate returns a server list, then hangs up]
            -> account server   (a second, fresh connection)
            -> lobby server     (a third, fresh connection)
            -> STUN, to discover the public UDP mapping
            -> peer-to-peer UDP for gameplay; the server only brokers
```

The gate closing the connection at the end of its phase is deliberate, not an
error. The client is expected to reconnect to whatever the server list gave it.

At most four connections exist at once (gate, account, lobby, and one spare).

### Ports

| port | service | game |
|---|---|---|
| 9573 | gate, account, lobby | Extreme 2 |
| 19573 | gate | SuperNOVA |
| 19570 | account, lobby | SuperNOVA |
| 3478/udp | STUN | both |
| 80, 443 | HTTP | SuperNOVA (see below) |

Extreme 2 builds its endpoints inline in code: `9573` (`0x2565`) at `0x001d4f34`
and `3478` at `0x001d4fc0`. `9573` appears exactly once as an immediate in the
whole executable.

SuperNOVA keeps its endpoints in a **service table at `0x002d0120`**, an array
of pointers, one entry of which is not a pointer:

| offset | value |
|---|---|
| `0x2d0124` | `dx2gate01.konamionline.com` |
| `0x2d0128`–`0x2d0138` | five HTTP URLs (see [HTTP services](#http-services-supernova-only)) |
| `0x2d013c` | `0x4c724c75`: **a packed u16 pair: 19573 (gate), 19570** |
| `0x2d0144` | `ddrsnstun.konamionline.com` |
| `0x2d0148` | `3478` |

Because the ports live in a data table rather than as immediates, the
"scan for the port immediate" approach that works on Extreme 2 finds nothing in
SuperNOVA.

---

## Framing

Recovered from `0x00856de0` (recv) and `0x00856cd8` (send) in Extreme 2. Both
directions are symmetric.

Every message is **XOR-obfuscated with a repeating 4-byte key** applied over the
entire frame, header included, indexed `i & 3`. The header is 24 bytes and the
index is continuous across it; since `0x18 % 4 == 0` the payload restarts
cleanly at `key[0]`.

After de-XOR the header is **big-endian**:

| offset | size | field |
|---|---|---|
| `0x00` | u16 BE | opcode |
| `0x02` | u16 BE | payload length |
| `0x04` | u32 BE | serial, monotonic per connection |
| `0x08` | 16 B | MD5 digest |

Then `length` bytes of payload, XORed with the same key.

- `length == 0` is legal, a header-only message.
- `length > 0x400` is a hard error (`-0xce`). **Payloads are capped at 1024 bytes.**

### The key

`72 5c 41 cb`. A build-time constant at `$gp-0xf0` in `DATA07.BIN`'s data,
shared by both games, confirmed by SuperNOVA's frames digesting correctly
against it.

If you need to recover it from scratch, it is cheap: brute-force the 65536
opcode candidates for the client's first frame and check each against the
frame's MD5. `server/gate.py` does this automatically.

### The MD5 is not checked by the client

The digest is computed and sent, but the client does not verify inbound
digests. The server should still compute it correctly; there is no salt.

---

## Message grouping

Many requests are answered by **more than one message**. The last message of a
group completes the RPC; earlier ones only reset the client's timeout. Answering
a multi-part request with a single message leaves the client waiting on a
terminator that never arrives, it does not error, it hangs.

The request opcode is not derivable from the response opcode. Known
counterexamples: `0x3020 -> 0x3022`, `0x3030 -> 0x3032`, `0x5009 -> 0x5010`,
`0x2005 -> 0x2002..0x2004`. Assuming `response = request + 1` is the single most
expensive mistake available in this protocol.

### Recovering the grouping from the binary

Every SuperNOVA response parser validates two things before doing anything: its
own opcode, and **the opcode of the request still in flight**, at
`ctx+0x2364+0xc`. The role of each message is likewise readable, each parser
ORs a flag into `ctx+0x2364+8`:

| flag | role |
|---|---|
| `\|= 2` | BEGIN |
| `\|= 0xe` | END |
| neither | DATA |

`tools/sndispmap.py` walks the dispatch chains and prints the whole map:
request, its responses in order, and each one's body shape. It reproduces the
known `+1` exceptions independently, which is a reasonable check that it is
reading the binary correctly.

A parser can answer more than one request. The compare is a chain, not a
single test, `0x0026c1b0` accepts the in-flight request being either `0x4520`
or `0x4521` and runs the same body for both, and `0x4525`, `0x4528` and
`0x452b` do the same for their own pairs. Reading only the first compare hides
four requests that are in fact answered.

Extreme 2 has an equivalent recoverable from its `NetPrg*` debug-string table,
which SuperNOVA does not ship.

#### The second method: group by state block

The in-flight compare finds most of the protocol and **cannot see the rest**.
The friends list is the warning: `0x3082`/`0x3084`/`0x3086` keep their state in
a second block at `ctx+0x2c64`, never touch `ctx+0x2364`, and so look like
unsolicited pushes, which is how `0x3080` came to be answered with the `+1`
guess and [froze the client](#friends-list-0x3080-supernova-and-the-second-state-block).

Every multi-part group shares one state block: `+0x00` cursor, `+0x08` flag
word, a record count nearby. So the block **is** the group, whether or not
anyone compares the in-flight request. `tools/snblocks.py` recovers the
grouping that way, tracking registers symbolically so the
`lui r,1 ; addu r,ctx,r ; sw rX,0x42xx(r)` form used for large displacements
resolves, neither a displacement scan nor `tools/scanconst.py` can see those,
because the constant being materialised is `0x10000`.

It reproduces `0x5030 → (0x5031, 0x5032, 0x5033)` on `ctx+0x13cd0` and
`0x5034 → (0x5035, 0x5036, 0x5037)` on `ctx+0x13f40`, both already known from
the in-flight compare, which is the check that it reads the binary correctly.
It then finds one more group of the same shape that the first method missed:

| block | group | request |
|---|---|---|
| `ctx+0x13038` | `0x5041` BEGIN, `0x5042` DATA, `0x5043` END | **`0x5040`** |

`0x5040` was falling through to the `+1` fallback, which sends `0x5041` alone:
a BEGIN with no terminator, the friends-list freeze exactly. Note that its END
carries a `u32` status where `0x5033` and `0x5037`, the same shape of group,
have no body at all; check each one.

The blocks also separate the room family from the lobby proper:

| block | parsers | is |
|---|---|---|
| `ctx+0x0b7ec` | `0x4211`, `0x4212`, `0x4213`, `0x4222` | the player list |
| `ctx+0x0d294` | `0x4301`, `0x4310`, `0x4311` | the room list (`0x4300`) |
| `ctx+0x0d298` | `0x4321`, `0x4322` | **upserts into that same room array** |
| `ctx+0x141b0` | `0x4351` clears it; `0x4a04`/`0x4a13` fill it | the opponent record |
| `ctx+0x1422c` | `0x4331`, `0x43b1`–`0x43b5`, `0x4a04`, `0x4a13` | the match record |
| `ctx+0x2378` | `0x4391`, `0x4393`, `0x4395` | the per-setting toggles |

`0x4322` is to the room list what `0x4222` is to the player list: a push whose
body is one record of the `0x4310` loop's shape, written into the array the
`0x4300` group fills.

---

## Phases

### Gate

| request | responses |
|---|---|
| `0x2008` SvrInfo | `0x2009`, `0x200a`, `0x200b` |
| `0x2005` SvrList | `0x2002`, `0x2003`, `0x2004` |
| `0x2006` SvrTime | `0x2007` |
| `0x0003` | goodbye; the client sends it and disconnects |

#### SvrList entry (`0x2003`), 45 bytes, max 200

This is the server directory and it carries the real addresses. Wire order
is the parser's call order, which is not the struct order:

| wire | size | struct | meaning |
|---|---|---|---|
| u32 BE | 4 | `+0x00` | unidentified |
| u32 BE | 4 | `+0x04` | **TYPE**, selects the entry and indexes the connection slot |
| fixed | 16 | `+0x0e` | label, display only |
| fixed | 15 | `+0x1f` | **host, the string the client dials** |
| u16 BE | 2 | `+0x0a` | **port** |
| u16 BE | 2 | `+0x08` | unidentified |
| u16 BE | 2 | `+0x0c` | unidentified |

Entries live at `ctx+0x124 + i*0x30` (SuperNOVA: `ctx+0x3128 + i*0x30`, count at
`ctx+0x3120`). The account server is **TYPE 1**. Types are range-checked `0..4`
but only four connection slots exist, so serve types `0`–`3`.

Serve an IP, not a hostname. The host field is 15 bytes, enough for a
dotted quad and nothing else, and resolution depends on the console's own
network configuration.

The SuperNOVA layout is identical. Only the `0x2002` BEGIN differs; see below.

### Account

| request | responses | notes |
|---|---|---|
| `0x3001` | `0x3002` | challenge, 16 bytes |
| `0x3003` | `0x3004` | credential blob, 48 bytes in; u32 status out, 0 = OK |
| `0x3010` | `0x3012` | GetPlayerFileList |
| `0x3020` | `0x3022` | NewCreatePlayerFile: **not** `0x3021` |
| `0x3030` | `0x3032` | DeletePlayerFile: **not** `0x3031` |

`0x3001` must be answered with `0x3002` **only**. The client waits for `0x3002`
and `0x3004` in separate sub-states, and the receive handler overwrites the
"last opcode" field; sending both back to back loses the first.

The stable account identity is the **first 8 bytes** of the `0x3003` blob. Later
blocks change every login and cannot be used as a key.

#### Player file list (`0x3012`)

Leading `u32 BE` status (0 = OK), then up to **two** entries. Two is a hard
client-side limit, not a convention.

Extreme 2, 42 bytes per entry, struct stride 48:

```
u8 slot, u32, char[16] name, u32, u8 dancer, u32, u32, u32, u32
```

SuperNOVA, **30 bytes** per entry, struct stride **36**:

```
u8 slot, s32, char[16] name, u8 dancer, s32, s32
```

The slot byte is also the index, entries are addressed, not ordered.

### Lobby

| request | responses |
|---|---|
| `0x4200` GetBlockList | `0x4201` (Extreme 2) / `0x4204`, `0x4201`, `0x4205` (SuperNOVA) |
| `0x4100` SelectPlayerFile | `0x4101` |
| `0x4202` EntryBlock | `0x4203` |
| `0x4210` GetPlayerList | `0x4211`, `0x4212`, `0x4213` |
| `0x4300` GetRoomList | `0x4301`, `0x4310`, `0x4311` |
| `0x411a` SetMyAddr | `0x411b` |
| `0x441d` GetRuleMask | `0x441e` |

#### Block list (`0x4201`), 21 bytes, one block, no loop

Both games use 21 bytes with different field order. A length check does not
catch this.

| game | wire |
|---|---|
| Extreme 2 | `u16 count, u8 id, char[16] name, u16 occupancy` |
| SuperNOVA | `u8 id, char[16] name, u16 occupancy, u16 capacity` |

SuperNOVA takes the count from `ctx+0xb6f8` rather than the wire.

#### Rule mask (`0x441e`, Extreme 2), 7 bytes

`u32 status` and, only when the status is zero, **three u8 booleans**, each
tested `== 1`. `FUN_001e7950` folds them into one bitmask and the results
screen (`FUN_00298040`) draws one column per enabled rule, with the header
strings that name them:

| byte | rule |
|---|---|
| 0 | SCORE |
| 1 | COMBO |
| 2 | SURVIVAL |

These are the head-to-head win conditions. SuperNOVA's parser for the same
opcode reads a different number of bytes and its meanings are unconfirmed.

#### Player-list update (`0x4222`), push-only

The fourth member of the `0x4210` group, and the only one no request produces.
`FUN_0085b020` parses **one record with exactly the `0x4212` per-entry field
sequence** (all 19 fields, checked one by one) and then upserts it into the same
1000-entry array: every entry whose id matches is overwritten, and if none
matches the first free entry is filled.

The id must not be zero. A free entry is one whose id is zero, so a record
with id 0 matches every free slot and fills the whole list with copies of it.

It never updates the count, so on its own it cannot populate a list. The
array the group fills lives at `ctx+0x9f00`: a `u16` running count at `+0x00`,
then up to 1000 records of 80 bytes from `+0x08`. `0x4211` opens the group by
`memset`ting `0x13884` bytes of it, the count and every slot, and `0x4212`
appends records and advances the count. `FUN_0085b020` writes only into a
record; it never touches `+0x00`. Every consumer of the array is bounded by that
`u16`, so a pushed `0x4222` lands in memory that nothing will iterate over. To
make a client actually *see* a player list it has not requested, the group
(`0x4211`, `0x4212`, `0x4213`) has to be pushed, not `0x4222` alone.

#### Wait countdown (`0x4500`), push-only

Four bytes: a **big-endian u32 count of seconds**. The parser stores the word
and `FUN_001e84c0` *converts* it to float, it is not an IEEE float on the wire.
The client then subtracts 0.016683351 (one frame at 59.94 Hz) per tick and
clears the armed flag once the value reaches 60.0, so anything at or under 60
arms and disarms in the same frame.

#### Friends list (`0x3080`, SuperNOVA), and the SECOND state block

Answered `0x3082` BEGIN, `0x3084` DATA, `0x3086` END. Confirmed live 2026-08-28
by the failure: `0x3080` was unmapped, the `+1` fallback replied `0x3081`, and
opening the friends list froze the game. There is no `0x3081` parser in the
client at all, the dispatcher drops the message, the completion flag is never
set, and the RPC waits forever. The multi-part trap at its worst: not a short
read, not an error, a hang.

| opcode | parser | role | body |
|---|---|---|---|
| `0x3082` | `0x0026c5a0` | BEGIN | `u32` status |
| `0x3084` | `0x0026c470` | DATA | up to **40** records of 23 bytes: `s32 id`, `char[16] name`, `u8`, `u8`, `u8` |
| `0x3086` | `0x0026c420` | END | empty |

This family does not use `ctx+0x2364`. It keeps its own state block at
`ctx+0x2c64`, request field, flag word at `ctx+0x2c6c`, record count at
`ctx+0x2c78`. So its parsers never compare the in-flight request at
`ctx+0x2370` and never touch `ctx+0x236c`, which is exactly why
`tools/sndispmap.py` does not list them: the tool keys on both of those.

That generalises, and it is the reason to distrust a short dispatch map. Any
opcode `sndispmap.py` reports under "no in-flight request check" may belong to
a group it cannot see. Check for a second state block before concluding an
opcode is a push, `tools/snblocks.py` does exactly that sweep, and it found
one more group of this shape still armed: see
[group by state block](#the-second-method-group-by-state-block).

Two neighbours resolved at the same time, both single-message ENDs whose
request the `+1` rule happens to guess correctly, but which were being served
with **no body**, so the client read stale message-buffer bytes:

| request | response | parser | body |
|---|---|---|---|
| `0x3900` | `0x3901` | `0x0026b9a0` | `u32` status + a fixed 32-byte string, written to the pointer the request builder left at `ctx+0x2374`. 36 bytes. |
| `0x3006` | `0x3007` | `0x0026e240` | bare `u32` status. 4 bytes. |

`0x3901`'s string read copies 32 bytes regardless of the payload length
(`FUN_00279b10` bounds-checks the cursor, not the message), so a short body is
not rejected, it is silently filled with whatever the buffer last held.

### Online songs (SuperNOVA)

The five online-only songs are unlocked by the `0x8000` availability list and
nothing else. Full derivation, wire format and boot order in
[supernova-online-songs.md](supernova-online-songs.md). Confirmed live
2026-08-28: with the five ids marked available, the client requested exactly
those five blobs over `0x7000` and no others.

The game never announces an unlock. `FUN_0027ec80` is a filter consulted at
selection time, 56 call sites in `netlby_mas4`, not an event, and nothing
compares a new list against a previous one. There is no "new song" string
anywhere in the client's 274-entry UI message table. Silence is the designed
behaviour, not a missing server feature.

### Matchmaking (Extreme 2)

The server's entire contribution to a match is three pushes and one relay:

- `0x44b0`, the match message. Push-only, 61 bytes: opponent id, name, and both endpoint pairs (local then public, mirroring `0x411a`), then four tail fields.
- `0x4400`, a server-**relayed** peer channel. The client builds it itself and sends it on the lobby connection; the whole in-game peer protocol rides inside it as `[u32 type][body]`, where the type word is **little-endian**, unlike every header field. Relay it verbatim in both directions.
- `0x4412`, opens the PLAY START gate. One u8, pushed to both clients once both have run `0x4410`, after a short delay.

Pushes must be sent after the in-flight reply, and not too soon after it.
The client's "last received opcode" field is overwritten by each message and the
waiting RPC only polls it once per frame, so a push sent immediately before or
immediately after a reply is lost.

#### The `0x44b0` tail: what the server decides about the match

Four fields follow the endpoints. Two of them are the match settings and two
are read by nothing. The bridge `FUN_00235d40` is the only consumer of this
record; it copies the fields into globals, `FUN_00237270` assembles a play
block from them and `FUN_00233f60` consumes it.

| wire | size | struct | is |
|---|---|---|---|
| `+0x38` | u8 | `R+0x00` | **game mode**, `0..3`, permuted to `1,3,2,4` in `[0x006f1698]` |
| `+0x39` | u8 | `R+0x01` | read by nothing |
| `+0x3a` | u16 | `R+0x04` | **the song the match plays** |
| `+0x3c` | u8 | `R+0x02` | read by nothing |

The song is a table index: `FUN_001e7060` reads `*(s16 *)(0x002e7850 + id*2)`,
a table with 80 valid entries that returns −1 for a negative index, and the
result **plus one** becomes `dance_num`. When the lookup fails the client prints
`reset dance_num : %d < %d` and forces `dance_num = 1`, which is the client
naming the field, and also means a bad index here is recoverable rather than
fatal. Everything this server has run used `0,0,0,0`: mode 1, song 1.

`[0x006f1698]` is the global that was once mislabelled a peer count. Every store
to it is in the match code, and this is where its value comes from.

### Matchmaking (SuperNOVA)

SuperNOVA does not work the way Extreme 2 does, and the difference is
structural rather than a matter of different opcodes. Extreme 2 has **one**
test of "last received opcode" (`netwk+0x8d8 == 0x44b0` in `FUN_001e8330`),
which is why finding that one opcode unlocked the whole match. SuperNOVA
instead keeps an **array of event-flag bytes**: each push parser sets its own
byte to 1, and the lobby overlay `netlby_mas4` polls the byte, acts, and clears
it. There is no single opcode to find, there is a table.

> Everything in this section is static: read out of `SLUS_213.77` and
> `DATA04.BIN`, **not yet exercised against the client**. The wire shapes and
> the addresses are solid; which push the server should send when is not.

`tools/snblocks.py` prints the table. Setters are in the ELF's parser block,
readers in the overlay at base `0x00a46000`:

| flag | set by push | read at | body |
|---|---|---|---|
| `ctx+0x142f4` | `0x4411` | `00a4c658`, `00a4d824`, `00a5a4dc`, `00a5b964` | GetStartStaus reply, 7 B |
| `ctx+0x142fc` | `0x4414` | `00a4a8f0`, `00a4ca6c`, `00a4d180`, `00a582b8`, `00a5a8d8`, `00a5b29c` | `u32` status |
| `ctx+0x142fd` | **`0x4a04`** | `00a47908` | **67 B match record** |
| `ctx+0x142fe` | **`0x4a13`** | `00a4791c` | **67 B match record** |
| `ctx+0x142ff` | `0x4325` | `00a53b88`, `00a57bf8` | 49 B player record |
| `ctx+0x14300` | `0x4351` | `00a4a858`, `00a581d0` | `u32` status |
| `ctx+0x14301` | `0x4331` | none | CreateRoom reply, 8 B |
| `ctx+0x14302` | `0x43b1` | none | empty |
| `ctx+0x14303` | `0x43b2` | `00a4a528`, `00a57e84` | `u16` BE |
| `ctx+0x14304` | `0x43b5` | `00a4a83c`, `00a581b4` | empty |
| `ctx+0x14305` | `0x43b4` | none | `s32` |
| `ctx+0x14306` | `0x4b01` | `00a4a7d4`, `00a57e1c` | 44 B |

Four flags are set by a parser and **read by nothing**, `0x14301`, `0x14302`,
`0x14305`, and so `0x4331`, `0x43b1` and `0x43b4` announce something the game
never looks at. They are inert in the same sense as the two `0x44b0` tail
fields, not unknown.

#### `0x4a04` and `0x4a13` are the match pushes

These are the counterpart of Extreme 2's `0x44b0`. Both carry the same **67-byte**
record and both write it into **two** places, the opponent record at
`ctx+0x141b0` and the match record at `ctx+0x1422c`, before raising their
flag. Wire order is the parser's call order (`0x0026cd60` for `0x4a13`,
`0x0026cf30` for `0x4a04`):

| wire | size | lands at | is |
|---|---|---|---|
| u32 BE | 4 | `ctx+0x2350` | status |
| s32 | 4 | match `+0x14` | |
| u16 BE | 2 | match `+0x1a` | **the song**, the same field the scene reads before calling the availability filter |
| u8 | 1 | match `+0x18` | |
| s32 | 4 | match `+0x1c` | |
| u8 | 1 | *discarded* | read to a stack local and dropped |
| u16 BE | 2 | oppo `+0x50` | |
| s32 | 4 | oppo `+0x18` | opponent **id** |
| fixed | 16 | oppo `+0x1c` | opponent **name** |
| u8 | 1 | oppo `+0x2d` | opponent **dancer** |
| s32 × 5 | 20 | oppo `+0x30`…`+0x40` | |
| u8 | 1 | oppo `+0x44` | |
| s32 | 4 | oppo `+0x48` | |
| u16 BE | 2 | oppo `+0x4c` | |
| u8 | 1 | oppo `+0x4e` | |

The id / name / dancer naming is not a guess about those three: the opponent
record has the same field order as one `0x4222` player-list entry shifted by
`0x18`, `s32` id, `char[16]` name, `u8` dancer, then the stats, and the
consumer copies exactly those out. The unnamed numeric fields are the player's
stats.

`server/gate.py` builds this as `build_sn_match_record`, behind
`--sn-match-push` / `--sn-match-song`.

The consumer is four instructions at `0x00a478fc`, and it is as blunt as
Extreme 2's:

```
if (ctx+0x142fd == 1) { scene->0x18 = 1; }          // 0x4a04
else if (ctx+0x142fe == 1) { scene->0x18 = 2;       // 0x4a13
    scene->+0x04 = (s16) ctx+0x14246;               //   the song
    scene->+0x08 =       ctx+0x14244;
    scene->+0x10 =       ctx+0x14240;
    strncpy(scene->+0xa9, ctx+0x141cc, 16);         //   the opponent name
    ... the rest of the opponent record ... }
```

So **the two pushes select the mode** (`scene+0x18` = 1 or 2) the same way
Extreme 2's `0x44b0` tail field `R+0x00` does, and the `0x4a13` path is the one
that copies the opponent out. `0x4351` is the other half: it *clears* the whole
opponent record at `ctx+0x141b0` and raises `0x14300`, which reads as "the
opponent went away".

Two requests sit next to these, `0x4a00` and `0x4a02`, answered by `0x4a01`
and `0x4a03`, both bare `u32` status ENDs on the main state block. Neither is
mapped in `gate.py`; the `+1` fallback picks the right opcode for both but
sends no body, which is a short read.

The rest of the family (`0x4322`, `0x4324`, `0x4325`, `0x4330`, `0x4343`,
`0x4360`, `0x43b1`–`0x43b5`) is consistent with SuperNOVA's UI, which lets
players create and search rooms with granular settings rather than only
searching for players.

### Starting a match (SuperNOVA): the readiness is peer-to-peer

Worth stating plainly because three separate server-side attempts to gate this
were all wrong: **the two clients do not tell each other they are ready through
the server.** The server's only jobs are to acknowledge the ready and to hand
each side the other's address.

The chain, read out of `netlby_mas4`:

| step | where | what |
|---|---|---|
| `0x4410` → `0x4411` | | the client asks; the reply's `u32` status is the whole decision |
| status **0** | `0x00a4c658` | `s0->0x4c = 1`, go to `0x00a4c490` |
| status **non-zero** | `0x00a4c658` | `s0->0x4c = 0`, this is the client **un-readying itself**, not waiting |
| ready == 1 | `0x00a4c490` | → `0x00a4c1f0` |
| | `0x00a4c1f0` | draws the wait screen, message `0xb3` |
| | → `0x00a4c100` | calls `0x0027bb30(conn, addr, addr, port, port, …)`: **the peer connect** |

So the "waiting for the opponent" state exists to wait for the **peer link**, not
for a server message. Once the link is up the two clients drive each other; if
it never comes up there is nothing to wait on and the client falls through into
the song alone. That is what "it just starts without the other player" is: not a
skipped handshake, a missing connection.

The consequence for a server: there is no readiness message to invent, but
the timing of `0x4411` matters. Answer it with status 0, hold the first one
until the other side has readied too, and make sure both sides have the
other's address. That means pushing `0x4b01` to the host, because only the
joiner ever sends `0x4b00`. See "Why the host never dialled" below.

Extreme 2 is genuinely different here: its `0x4412` push really is the gate, and
its peer protocol is relayed rather than dialled. The two games do not share
this design, and assuming they did cost three rounds of testing.

### The SuperNOVA peer link is real UDP, and PCSX2 cannot carry it

Extreme 2 relays its whole in-game peer protocol through the server over
`0x4400`, which is why it works under an emulator. **SuperNOVA does not.** It
dials the opponent directly, and the decompiled chain is unambiguous:

```
FUN_00a4c100  state 0: connect(conn, my_public, their_public, their_local)
              state 1: poll FUN_0027b900 until != 0
              state 2: -> the song

FUN_0027bb30  if (my_public == their_public) dial their_local  : local_port
              else                           dial their_public : public_port

FUN_0027c6f0  e->0x14 = addr ; e->0x12 = htons(port)     // a sockaddr
              e->0x24 = addr ; e->0x22 = htons(port)     // and a second one
              e->0x34 |= 4                               // "peer address set"
```

`FUN_0027b900` gates everything on `(ctx+0x34 & 7) == 7` and gives up after
300 ticks, roughly five seconds, returning −1. That timeout is what a
client falling straight through to `0x4430 GetEndgame` looks like.

So the server's part is only to supply the addresses; the consoles must then
reach each other over UDP. Under PCSX2's `Sockets` backend they cannot: outbound
UDP is translated, but there is no inbound port forwarding, so the port the
STUN mapping advertises is not deliverable to the emulated console. Both
consoles also share the local address `192.0.2.100`, so the hairpin branch is
no help either, it would point each of them at itself.

This is the same limitation the project already recorded for Extreme 2's
untested peer path. Extreme 2 simply never depends on it.

A server-side fix exists and is not implemented: relay the UDP. Give each
client the *server's* address and a per-client port in `0x4b01`, then forward
datagrams between the two ports, TURN-style. The client cannot tell the
difference, it dials what it is told, and it would make SuperNOVA
head-to-head work on emulators and behind symmetric NATs alike.

#### Why the host never dialled

The relay works. With `--udp-relay` a joining console dials it on the first
attempt (`relay 19600: A is 192.0.2.15:5730`). The host never did. The cause
is timing, not addresses. An earlier reading blamed `0x4b01`; that came from
the guest's consumer, not the host's.

The connect record at `scene->0x834` holds two player slots of `0x74` bytes:

| | slot A | slot B |
|---|---|---|
| id | `+0x32c` | `+0x3a0` |
| NAT word | `+0x338` | `+0x3ac` |
| name | `+0x33d` | `+0x3b1` |
| local / public port | `+0x370` / `+0x372` | `+0x3e4` / `+0x3e6` |
| local / public address | `+0x374` / `+0x385` | `+0x3e8` / `+0x3f9` |

The room owner is slot A and the guest is slot B:

| who | fills | where |
|---|---|---|
| owner, itself | slot A | `FUN_00a4f800` state 1, after `0x4330` CreateRoom (`FUN_0026ff50`) |
| owner, the guest | slot B | the `0x4325` consumer in `FUN_00a57bc0` |
| `0x4a04` receiver | A = opponent, B = itself | `FUN_00a47880`, scene mode 1 |
| `0x4a13` receiver | A = itself, B = opponent | `FUN_00a47880`, scene mode 2 |

A client's own entry always comes from `scene->0x82c`, which is its own
address block. Read live over PINE from a guest on 2026-09-14:

```
+0x08 "192.0.2.60"   +0x30 19573    the gate
+0x18 "192.0.2.60"   +0x32 3478     the STUN server
+0x38 0xb1                           its NAT type
+0x3c "192.0.2.15"   +0x64 5730     its public (STUN) address
+0x4c "192.0.2.100"   +0x66 5730     its local address
+0x68, +0x89                         two 0x21-byte strings
```

`blk->4` is the client's own id. The earlier note that `FUN_00a4f800` sets
"`blk->0x32c` = opponent id" was wrong: that line puts the owner into its own
slot A.

There is one `0x4b01` consumer per room scene:

| scene | built by | consumer | guard | writes |
|---|---|---|---|---|
| guest | `FUN_00a4f210` | `FUN_00a4a4f0` (`0x00a4a7d4`) | slot A id == `ctx+0x141c8` | slot A |
| owner | `FUN_00a5d1c0` | `FUN_00a57bc0` (`0x00a57e1c`) | slot B id == `ctx+0x141c8` | slot B |

`ctx+0x141c8` is the trailing s32 of `0x4b01` (parser `0x0026d900`). So
`0x4b01` must name the opponent, which is what gate.py sends. The owner
accepts it once `0x4325` has put the guest in slot B.

Accepting `0x4b01` only records the peer address (`FUN_0027c6f0` sets
`conn+0x34 |= 4`). No packet goes out until the connect state runs, and each
side reaches that only after its own `0x4411`:

```
guest  0x4410 (FUN_00a4b570) -> FUN_00a4c5a0 waits for ctx+0x142f4
       -> FUN_00a4c490 -> FUN_00a4c1f0 (message 0xb3) -> FUN_00a4c100 connect
owner  0x4410 (FUN_00a59160 state 5) -> FUN_00a5a430 waits for ctx+0x142f4
       -> FUN_00a5a340 -> FUN_00a5a0a0 (message 0xb3) -> FUN_00a59fb0 connect
```

Both connects call `FUN_0027bb30(conn, my_public, their_public, their_local)`
with the ports in `t0`/`t1` and the two NAT words in `t2`/`t3`, taken from
whichever slot is theirs. `FUN_0027b900` gives up after about 300 ticks.

The server was answering each `0x4410` straight away. The guest's connect
started when the guest readied and had expired before the host pressed
start, so each side dialled into nothing. Neither wait for `0x4411` has a
timeout: both poll the flag each frame and leave only on the player's cancel,
which sends `0x4416` from `FUN_00a4b180`. So gate.py now holds the first
`0x4411` until the other side readies and then releases both together
(`hold_sn_start`; `--sn-start-open` restores the old behaviour). A non-zero
status is not an alternative, it un-readies the client. Not yet tested on the
client.

The NAT words matter too, though not here. `FUN_00277d70` maps each side's
code (`0, 1, 2, 0x10, 0x50, 0x30, 0x90, 0xb1, 0xb3, 0xd0`) to an index and
reads a 10x10 table at `0x002cff10`. The non-hairpin connect (`FUN_0027bc60`)
fails immediately if either direction's entry has no bit above `0x3`, which
covers code 2 on either side and pairs such as `0x50`/`0x50`. gate.py sends the
peer's word as 0 in `0x4325` and `0x4a13`. Against `0xb1` that gives `c0` and
`c3`, which pass, so it is not the blocker. Serving the real value would mean
finding where the client reports it.

### Inside a SuperNOVA room: settings, chat, leaving, friends

All of this was read out of `SLUS_213.77` and `DATA04.BIN` and then confirmed on
two consoles on 2026-09-14.

#### Owner and guest

A room has an owner and a guest, and each runs its own scene:

| mode | set by | scene | own slot |
|---|---|---|---|
| 2, owner | `0x4330` CreateRoom, or `0x4a13` | `FUN_00a5d1c0` | A |
| 1, guest | `0x4323` join, or `0x4a04` | `FUN_00a4f210` | B |

`FUN_00a47880` writes the mode to `scene+4 → +0x18` when a match push lands, and
`FUN_00a49b70` opens the owner scene for 2 and the guest scene for 1. An
auto-searcher matched into an existing room must therefore get `0x4a04`.
`0x4a13` made it a second owner of a room the server never listed, so when the
real owner left it kept an "open" room nobody could find.
`--sn-search-push` (default `0x4a04`) controls this.

#### Room settings

Changing a setting is a request answered with a bare status. The other
console only learns about it from a push, and each push is one bare value with
no status in front:

| request | push | parser | lands at |
|---|---|---|---|
| `0x4392` u16 song | `0x43b2` | `FUN_0026d640` | `ctx+0x14246`, flag `0x14303` |
| `0x4394` u8 difficulty | `0x43b5` | `FUN_0026d490` | `ctx+0x141fe`, flag `0x14304` |

Both room scenes copy `ctx+0x141fe` into the opponent's slot, so the value is
the sender's own difficulty. Song `0x5a` is random and passes through.

#### Ready and cancel

`0x4412` is one u8 into `ctx+0x14268`, the opponent-ready light. The server
lights it when a player readies and holds that player's `0x4411` until the
other side readies too (see "Why the host never dialled"). A cancel sends
`0x4416` from `FUN_00a4b180`; the server drops the held reply and sends the
opponent `0x4412 = 0` to put the light out.

#### Leaving

`0x4351` is a bare u32 status (`FUN_0026f760`). Status 0 zeroes the opponent
record at `ctx+0x141b0` and raises `ctx+0x14300`, and both room scenes then
clear the other player's slot. The server sends it to the remaining player on
`0x4340` OutRoom and when a connection drops.

#### Chat

Every line goes through `FUN_00273a70` case 9, which reads the chat mode at
`scene->0x834` byte 1 (0 lobby, 1 room, 2 whisper; room also needs byte 0,
"in a room") and calls the builder with:

| mode | request | first byte | second byte |
|---|---|---|---|
| lobby | `0x4511` | 0 | 1 |
| room | `0x4511` | 1 | 1 |
| whisper | `0x4512` | 0 | 2 |

The push `0x4513` is `u32 status, u8, s32, s32 id, char[16] name, text`. The
receiver `FUN_00287ac0` passes the u8 and the s32 to the chat widget, treats
s32 = 1 as a whisper it can answer, and raises the new-message alert for u8 = 1
or a whisper. So the u8 is the room flag, the request's first byte. Echoing
the second byte put every lobby line in the room channel. Room lines go only to
the other player in the room.

#### Friends

The client asks for the list once, with `0x3080`, and never again. The `0x4522`
add reply is status plus a name read into a stack buffer; it does not touch the
list. `0x3084` appends at the client's own count (`ctx+0x2c78`, reset only by the
request builder `0x0026c610`) and has no in-flight check, so after an add the
server pushes one `0x3084` record for the new friend. Pushing the whole list
would duplicate every entry.

#### Competitions

`0x5000` names one competition by s32 id. The `0x5001` detail (parser
`FUN_0026a0f0`) is 191 bytes:

```
u32 status / s32 id / char[32] name / s32 / u8 / s32 start / s32 end
/ u8 x4 / s32                                        61-byte header
then ten stage records: u16 song / u8 x11            13 bytes each
```

The song is the u16 at the start of each stage. The eleven u8 after it are
per-stage settings, not identified yet. An older layout put "song ids" there
and 0..9 made the card invalid, so at least one is a bounded index; they are
served as zero. The server reads competitions from `sn_competitions.json`
beside the state file on every request (see `sn_competitions` in gate.py) and
files each on the open (`0x5032`) or future (`0x5036`) list by its dates.

#### The login blob

`0x3003` is built by `FUN_00273440`: the username as a fixed 32-byte string,
then `MD5(username + challenge + password)`, where the challenge is the 16 bytes
of our `0x3002` reply (zeros today). The server keys accounts on the first 8
bytes, which are the first 8 characters of the username, and checks nothing.
The digest is stable across logins under a fixed challenge, in both games, so
a registration that stores the same digest could be checked at login without
ever storing the password.

### Ranking Challenge (Extreme 2)

The whole mode, request by request. `0x5013` has no request at all, it is a
server push, and the only one in the `0x50xx` family.

| request | responses |
|---|---|
| `0x5000` GetRCInfo | `0x5001` |
| `0x5002` GetRCTrycount | `0x5003` |
| `0x5004` GetRCEntry | `0x5005`, status only |
| `0x5006` GetRCRegist | `0x5007`, status only |
| `0x5009` GetRCIdList | `0x5010`: **not** `0x500a` |
| `0x5011` GetSchedule | `0x5012` |
| none | `0x5013` **push**: week rollover |
| `0x6000` Get{HtoH,Point,RC}Ranking | `0x6001`, `0x6002`, `0x6003` |

It is "timed" in two places and they are separate: the **week number** decides
whether the tab exists at all, and the **countdown** decides what the header
says. Both ride in `0x5012`, and `0x5013` rotates the first one live.

#### The request addresses a card (`0x5000`), 2 bytes

`u8 a, u8 b`, from the builder at `0x00858180`. The RC scene asks for every
card it is going to draw, and the pair is not a number split in two:

| selector | card |
|---|---|
| `(0, 0)` | first featured card |
| `(1, 0)` | second featured card |
| `(i & 1, i/2 + 1)` | entry *i* of the `0x5010` id list |

so `b == 0` addresses a featured card and `b >= 1` addresses a list entry.
Answering every selector with one record is what makes both cards show the same
songs and the same "NORMAL NO:0".

#### The challenge (`0x5001`), 138 bytes

A `u32` status, an eight-field header, then ten 12-byte rows of
`u16 song` + ten `u8`. The wire order is the parser's call order and not the
struct order; `NetPrgGetRCInfo` (`0x001dd5a0`) then copies the struct into a
0x84-byte per-challenge record, which is what identifies the fields:

| wire | struct | is |
|---|---|---|
| u32 | `R+0x04` | challenge id, echoed onto the card |
| u8 | `R+0x00` | challenge class, `0..7` → message ids 89–96 |
| u32 | `R+0x08` | |
| u8 | `R+0x0c` | rule mask, four bits → message ids `0x4c`–`0x50` |
| u8 | `R+0x0d` | `0..2` → message ids 82–84 |
| u8 | `R+0x0e` | |
| u8 | `R+0x0f` | parsed, then never copied out, reaches nothing |
| u8 | `R+0x10` | **difficulty**, `0..2` → message ids 86–88 |

There are two difficulty fields and they do different jobs.

`R+0x10` is per-challenge and it is what the card **displays**: in
`FUN_001f75b0` and `FUN_001f44e0` it selects which of a song's three
per-difficulty values every row is drawn at, `2` → song`+0x20`, `1` → `+0x24`,
`0` → `+0x28`, passed to the row widget as class 3 / 2 / 1. Only the two card
builders read it.

`R+0x12` is per-row and is the chart actually **played**. That comes from a live
sweep rather than the disassembly: set to 2 the play screen read HEAVY, and 4
hard-froze the game on the Practice tab with no keepalives afterwards, so its
range is at most `0..3`. It is also the one byte of the ten that the client's
own "options changed" comparison skips, a difficulty is not an option, which
is why it stands apart from the nine below.

The message ids are indices into a table filled at runtime (`0x01045b7c`) from
data that is not ASCII anywhere on the disc, so the ids are known and the words
they render are not.

#### The ten per-row bytes, and their defaults

`R+0x12` is not one of the play options. The other nine are, and **the client
states their default values itself**: both card builders (`FUN_00262c40` for the
featured cards, `FUN_001f5770` for the list) decide whether to light the
"options changed" marker by comparing nine bytes against a fixed tuple:

```
R+0x13 == 2   R+0x14 == 0   R+0x15 == 0   R+0x16 == 1   R+0x17 == 0
R+0x18 == 1   R+0x19 == 0   R+0x1a == 0   R+0x1b == 0
```

so `(2,0,0,1,0,1,0,0,0)` is "options unchanged". An all-zero record, which is
what a server serves if it treats these as unknown, is three bytes away from
that, in the direction of a challenge nobody configured.

These bytes are indices into fixed tables. A sweep of `31..40` froze the client
on entering the lobby, so they are the one place in this protocol where an
out-of-range value is worse than a wrong one.

#### Serving fewer than ten rows

Both card builders break out of the row loop on `song == -1`, and
`FUN_001e7060` returns −1 for a negative index. The wire field is read as a
signed short, so **any song id with the top bit set ends the list**. The body
stays 138 bytes; the rows after the terminator are simply never read.

The mapped id is clamped to `0x4a` again by the banner loader `FUN_001f4af0`.

The table itself is **a permutation of `0..73`**, 74 wire ids onto the same 74
internal song ids, one to one. Entries `74..79` are zero, which is a valid
internal id rather than a terminator, so a wire id in that range silently draws
song 0 again. Valid wire ids are `0..73`.

#### A song id that hangs the client: wire id 8

Do not serve wire song id 8. It maps through the permutation at `0x002e7850`
to internal song **44**, and a challenge row carrying it wedges the online scene.
Not instantly, within a few minutes of working the Ranking Challenge tab, after
which the client stops responding entirely: no keepalives, no reset, the TCP
connection simply goes quiet.

Bisected against a real client on 2026-09-13. Six windows, perfectly consistent:

| card 0 block | contains wire 8 | outcome |
|---|---|---|
| `1..10` (the old default) | yes | hang |
| `5..14` | yes | hang |
| `7..16` | yes | hang |
| `8..17` | yes | hang |
| `9..18` | no | stable |
| `11..20` | no | stable |

`--rc-first-song 1` put id 8 in the first featured card every single session,
which is why the online lobby had been hanging since the day RC serving was
switched on. `--rc-first-song 11` clears all four challenge blocks
(`11-20`, `21-30`, `31-40`, `41-50`) of it. **Do not lower it below 11 without
re-testing.**

What the hang looks like. The EE is not crashed and nothing has written
through a bad pointer. The game is spinning inside its own `sceGsSyncPath`,
waiting on a GIF DMA that never completes:

```
sceGsSyncPath: DMA Ch.2 does not terminate
  D2_CHCR  = 30000105   STR set, QWC=0, chain parked on a `ref` tag
  GIF_STAT = 10000000   FQC=16 -- the GIF FIFO is full and not draining
```

A savestate classifies instantly: `D2_CHCR & 0x100` is set when hung and clear
when healthy. Hung captures also draw at absurd sizes. GS state fields read
`0x50` / `0x5000` where a healthy capture reads `0x10` / `0x400`, which is what
produces the stretched-sliver glitch on screen, and what takes PCSX2 down
outright under the software renderer instead of merely hanging it.

Why id 8. It is "Miracle Moon (L.E.D.LIGHT STYLE MIX)" by Togo Project
feat. Sana, and its Ranking Challenge banner is the only one of the 74 in a
different format. Each banner in the runtime table at `0x00ae4700` is a
compressed `TCB` image. The loader `FUN_001f4af0` unpacks a card's ten banners
back to back into `DAT_0104bf38`, and the unpacked headers read:

```
                size    pixels   colours  format  size
every other     0x0e90  +0x050   16       4       224x32
song 44         0x2050  +0x410   256      5       224x32
```

The rest are 4-bit images with a 16-colour palette. Song 44's is 8-bit with a
256-colour palette: same size on screen, twice the pixel data and a palette
sixteen times larger. 73 of the 74 compressed streams open with identical bytes
and song 44's diverges at the seventh, so this shows up without unpacking
anything. An earlier dump called the table uniform because it compared only
the offset word at the start of each entry, which is the same for all of them.

The card code is built for the 4-bit banners, and the loader advances its
destination by each banner's rounded size with no bounds check. How an 8-bit
banner gets from there to the GS stall is not pinned down. That it is the only
banner that differs is not in doubt, and it is the only song id that hangs.

Three mechanisms were proposed and disproved before the bisect found it, each
killed by the same method: compare the broken capture against a *working* one.

| proposed | killed by |
|---|---|
| `RC_SONGLIST` is null | the pointer is valid in the hung capture |
| the `RC_SONGLIST` block is unpopulated | a **working** Practice screen has the same 122,432-byte block, 100% zero, and the same zero player count |
| the arena overflowed | a working capture has byte-identical arena state, `ARENA_PTR=0x010b9cc0`, `N=3`, sizes `0x1de40 0x9240 0x5480` |

The lesson is one this project keeps relearning: the only evidence that counts is
what *differs* between a broken capture and a working one. A plausible mechanism
that is identical in both is not a cause, however well it explains the symptom.

#### A client hazard the server can trigger: the online scene's arena

Not a protocol rule, but the server decides how often it is exercised, so it
belongs here. The online scene allocates from one block with a bump pointer set
up at `0x001e8810`, and every allocation is the same shape (`FUN_001e7950`
case 10, `FUN_00262c40`, `FUN_001f5770`):

```
out = 0
if (ARENA_PTR != 0 && ARENA_N < 12) { out = ARENA_PTR; ARENA_PTR += size;
                                      sizes[ARENA_N++] = size; }
RC_SONGLIST = out
memset(out, 0, size)          <-- not guarded
```

The failure path writes to address 0. Nothing checks `out` before the
`memset`, and nothing checks the bump pointer against the end of the block:
only the count against 12. So the thirteenth allocation clears `0x1de40` bytes
from address 0, which is a hard freeze with no keepalives afterwards, and
earlier ones can run off the end of the block instead.

`ARENA_N` is reset only on whole-scene transitions (`0x001e86ac`, `0x001e875c`,
`0x00222a3c`, `0x002372f0`, `0x002635ec`), **not per tab**, so tab switches
inside one online session accumulate against the cap of 12.

> This was proposed as the cause of the Practice-tab freeze and it is NOT.
> The real cause was found on 2026-09-13 and is a song id, see
> [A song id that hangs the client](#a-song-id-that-hangs-the-client-wire-id-8).
> A save state taken on the frozen screen (2026-08-28) reads `ARENA_N = 3` of
> 12, `ARENA_PTR = 0x010b9cc0`, and all three blocks (`0x1de40`, `0x9240`,
> `0x5480`) accounted for from a base of `0x0108d7c0`. Nothing was exhausted and
> nothing wrote to address 0. The unguarded `memset` above is real and worth
> knowing about, but it did not fire here.

`python tools/pinewatch.py --rc` watches `ARENA_PTR` (`0x0104c1b4`), `ARENA_N`
(`0x0104c1b8`) and `RC_SONGLIST` (`0x0104c0d0`) live.

> `RC_SONGLIST` is a misnomer and the name has cost time. `0x0104c0d0` is not
> the Ranking Challenge's song list. It is a shared scratch buffer: two stores
> (both in the scene's allocator) against 102 loads spread across the DATA, RC
> and Practice tab handlers, about sixty of the loads are in Practice alone.
> What Practice copies into it are *player* records: its filler reads the `u16`
> count at `ctx+0x9f00` and copies that many 80-byte entries in at an 84-byte
> stride. Treat it as "the online scene's list buffer", not as anything to do
> with songs.

#### The tab bar, and what gates each tab

Six tabs, driven by `PTR_FUN_002e7bb0` (enter) and `PTR_FUN_002e7c10` (handler),
with `DAT_0104beec` the current tab and `DAT_0104beed` the one being moved to:

| tab | screen | handler |
|---|---|---|
| 0 | HEAD-TO-HEAD | `0x001f10d0` |
| 1 | RANKING CHALLENGE | `0x00261e70` |
| 2 | PRACTICE | `0x001fb380` |
| 3 | DATA | `0x001f74f0` |
| 4 | OPTIONS | `0x001ee4e0` |
| 5 | LOGOUT | `0x001eeea0` |

The tab-bar input handler `FUN_001ef640` **skips tab 1 entirely** unless
`0 < DAT_01047cb4 < 61` (the compare is at `0x001ef754`). That byte is the week
number the online scene copies out of `ctx+0x2a383`, from the `0x5012`
GetSchedule reply, so the schedule field the server sends decides whether the
Ranking Challenge tab can be reached at all. Left/right jump straight past it
when the value is out of range.

The scene object is at `0x01045980` (its per-frame tick is at `+0x24` and is how
you find it in a memory dump). `+0x10` is the tab-switch state and `+0x14` is
the pad result the state machine waits on, `1` = confirm, `2` = back, `0` =
still waiting. The RC card records live at `+0x2338` and `+0x23bc`, the id-list
records at `+0x2444` with stride `0x84`, and the id count at `+0x2440`.


#### The schedule, and the clock the challenge runs on (`0x5011` → `0x5012`)

Nine bytes: `u8` → `ctx+0x2a383`, `u32` BE → `ctx+0x2a388`, `u32` BE →
`ctx+0x2a38c` (parser `0x00857970`, dispatched at `0x0085c098`). The online
scene copies all three into globals as soon as the RPC completes, at
`0x001e70fc`, `0x001e79ac` and `0x001e8418`, three copies of the same block:
and **the globals are where the meaning is**, not the parser:

| wire | ctx | global | is |
|---|---|---|---|
| u8 | `+0x2a383` | `DAT_01047cb4` | the **week number**, 1..60 |
| u32 | `+0x2a388` | `DAT_01047ca8` | **inert** |
| u32 | `+0x2a38c` | `DAT_01047cac` | **seconds remaining**, a duration |

The second field is read by nothing. Four stores, zero loads, across the ELF
and every `DATA0x` overlay. It is documented as inert rather than unknown, the
same way the `0x44b0` tail fields `R+0x01` and `R+0x02` are.

The third field is a countdown, not an end timestamp. `FUN_0022f790` is the
setter, and it settles the units on its own:

```
if (secs == 0) { flags |= 4; return; }      // no countdown at all
widget+0x78 = (float)(secs % 60)            // the seconds digits
widget+0x7c = min(secs / 60, 59999)         // minutes, CLAMPED
```

and the draw path at `0x0022f9ac` divides `widget+0x7c` by 60 *again* before
printing `"%03d:%02d"`. So the readout is **HOURS:MINUTES**, and the clamp of
59999 minutes renders as exactly `999:59`. A server that sends an absolute UNIX
timestamp here sends ~1.79e9 seconds and always draws `999:59`; that is what the
2026-08-27 log was showing, and it was the server's value, not a client bug.

The week is clamped twice, to the same range. The widget setter
`FUN_0022f840` maps `>= 61` to `60` and negatives to `0`, and the tab-bar
handler only opens the tab for `0 < week < 61`. So `0` means "no challenge
running" and `1..60` is the whole legal range, the same scale as the `period`
field of the `0x6000` ranking request (`-2..60`).

#### `0x5013`, the week rollover push, and it logs the client out

Push-only, **one byte**, parser `0x008578f0`, writing the same `ctx+0x2a383` the
schedule reply fills. There is no request that produces it: like `0x44b0`, it is
invisible to any candidate list built from observed traffic. The online scene's
tick tests it the same way it tests `0x44b0`, at `0x001e8540`:

```
if (netwk+0x8d8 == 0x5013) {
    printf("UPDATE WEEK:%d===...", ctx[0x2a383]);   // 0x003030e0
    scene->state = 0x002c0f60;                      // -> 0x002c0c00
    DAT_0104c0b8 &= ~1;
}
```

`0x002c0c00` is a ten-case state machine, and **its own error string names it**:
`"NetGameShutdownMain"` at `0x0030bba0`. It puts up a modal (`0x0025db50`),
waits for the confirm (`0x0025daf0`), calls `NetPrgOutRoom` (`0x001df4b0`) and
tears the network down (`0x001d3e00`). The trampoline it arrives through also
`memset`s the shared RPC state block at `0x01045e9c`, so whatever RPC was in
flight is abandoned.

So this is not a refresh, **it is how a server rotates the challenge period out
from under a live lobby**. Announce the new week and every online client walks
itself back out. `--push-5013 <week>` sends it, and the usual push timing rule
applies: after the in-flight reply, and not too soon after it.

#### Entering a challenge and posting a result

| request | bytes | responses |
|---|---|---|
| `0x5004` GetRCEntry | 5 | `0x5005` |
| `0x5006` GetRCRegist | 16 | `0x5007` |

`0x5004` (builder `0x00857e00`) is `s32 id`, `u8 card`. The `s32` is
`**(u32 **)0x01045edc`, the selected player file's id, every RC, log and
ranking RPC sends the same word. The `u8` is `DAT_0104bf34`, and the RC tab's
cursor handler only ever does `v = (v + 1) & 1` (`0x00261828`, `0x00261888`), so
it is **which of the two featured cards is selected, 0 or 1**, the same two the
`0x5000` selector calls `(0,0)` and `(1,0)`, not an index into the id list.

`0x5006` (builder `0x00857d40`) is the result upload: `s32 id`, then four
values read straight out of the per-player play record at `0x00644910`
(stride `0x5427c`, two players):

| wire | source | is |
|---|---|---|
| s32 | `PLAY+0x15c` | **SCORE** |
| s32 | `PLAY+0x34` | play time in milliseconds |
| s16 | `PLAY+0x234` | **MAX COMBO** |
| s16 | `PLAY+0x42` if `PLAY+0x1c == 2`, else `PLAY+0x44 + 1` clamped `>= 0` | `PLAY+0x1c` is the play style; the `+1` is a 0-based counter made 1-based |

Two of the four were settled by playing a stage and reading the results screen
against the log. A play scoring `015945888` with `59 MAX COMBO` sent exactly
`15945888` and `59`. Nothing in the binary names them: they are only ever
written through a base pointer out of an overlay. The client sends them, so
matching one real play was quicker and more certain than any amount of scanning.

`PLAY+0x34` is not shown on the results screen, so it is inferred rather than
matched. Two samples fit elapsed play time in milliseconds and nothing else:
118101 for a full song, 15965 for one failed within seconds. The last field has
been 0 in every sample so far.

Both replies are status-only, and both were being served empty. The two RPCs
jump straight to the generic parse thunk `0x0085b710`, which reads one `s32`
through `0x008565f0` and returns it as the parse result. `0x008565f0`
bounds-checks the **read cursor** against `0x3fd`, never the message length, so
an empty body is a silent short read: the client takes four bytes of whatever
the 1 KB message buffer last held and uses them as the RPC's status. That is the
friends-list bug's shape for the third time, and the first time it has turned up
in Extreme 2. Both now carry `struct.pack('>i', 0)`.
---

### Results, boards and logs (Extreme 2)

The client reports every result, and the server keeps them in `results.json`
beside `state.json` (see `server/results.py`). The ranking boards, the personal
logs, the tries counter and the player stats are all served from that file.
Before it existed every result was logged and thrown away, and every board
ranked whoever was online, all on zero.

#### What the client sends

| request | when | body |
|---|---|---|
| `0x5004` GetRCEntry | entering a challenge | `s32` player id, `u8` featured card |
| `0x5006` GetRCRegist | after a Ranking Challenge play | see the `0x5006` table in the Ranking Challenge section |
| `0x4430` GetEndgame | after a head-to-head song, from both players | 36 bytes, below |

`0x4430` is a copy of a 36-byte stack struct. The save-record builder at
`0x00236f40` zeroes it, fills four fields and passes it to `NetPrgGetEndgame`:

| wire | struct | source |
|---|---|---|
| `u32` | `+4` | the score, computed from two play counters just before the call |
| `u16` | `+0` | the same stage counter `0x5006` carries |
| `u32` | `+8` | `PLAY+0x30`; 14400 for both players in the one capture |
| `u16` | `+2` | `PLAY+0x124`; 8 and 109 in a match one player failed early |
| 12 x `u16` | `+0xc` to `+0x22` | always zero in Extreme 2 |

Both players report, so the server pairs the two reports: the higher score
wins and equal scores draw. The opponent is remembered when the first report
arrives, because OutRoom can tear the pairing down before the second one does.

#### Ranking requests

The three ranking RPCs all call the `0x6000` builder at `0x00857bf0`, and the
first byte says which board:

| type | RPC | the extra byte |
|---|---|---|
| 0 | NetPrgGetHtoHRanking | 0 |
| 1 | NetPrgGetRCRanking | the featured card |
| 2 | NetPrgGetPointRanking | 0 |

`period` is the schedule's week number. The Ranking Challenge tab asked for
type 1, period 19, card 1 during week 19. A period of 0 or less has not been
seen from the client; the server treats it as all time. Ranking Challenge
boards are per week and per card, and rank each player's best score.

All three boards share the 49-byte `0x6002` record and read different fields
from it: 5, 6 and 7 (win, draw, loss) for head-to-head, 8 for points, 9 for
the Ranking Challenge score.

#### Tries

`0x5002` carries only the player id, and the client sends it once per visit to
the tab. The two cards still drew different numbers from one `0x5003` reply:
`00/00` and `03/00` from a reply of `0, 3`. So the two bytes are one count per
card, not a used and allowed pair. The server sends the entries so far this
week on each card. Where the number after the slash comes from is not known.

#### Points

The original points formula is not known. This server gives 3 for a win, 1 for
a draw and 0 for a loss.

#### Not yet checked on screen

- The Ranking Challenge log's TITLE column is served as the wire song id and
  its TIME column in milliseconds. Either may be wrong.
- The PERSONAL DATA "SCORE" row (player info fields 13 to 16) is served the
  same head-to-head totals as fields 9 to 12. Nothing yet says what
  distinguishes them.
- Player list field 12 is served the weekly match count.
- The per-card reading of `0x5003`.

## HTTP services (SuperNOVA only)

Extreme 2 never makes an HTTP request. SuperNOVA fetches three documents after
the gate and STUN phases succeed, and **will not proceed without them**, the
failure surfaces as "Failed to connect to the server. Server may currently be
under maintenance", which is a UI message about HTTP, not about the gate.

Stock URLs, from the service table:

```
http://dx2web.konamionline.com/ddrsn/oua/ddrsn_oua.txt          online user agreement
http://dx2web.konamionline.com/ddrsn/oua/ddrsn_pia.txt          privacy statement
http://info.service.konamionline.com/VW335-U1/info/             service information
https://dx2web.konamionline.com/ddrsn/reguser/reguser.html      registration
https://dx2web.konamionline.com/ddrsn/reguser/chgpswd.html      password change
```

The client parses the URL: it picks a default port by scheme and then honours an
explicit `:port`, so these can be moved without patching code.

### Account registration

Registration is an **HTTP POST**, not part of the gate protocol. The client uses
its own User-Agent, `DDRSN/1.00 (KONAMI)`, rather than the `sceHTTPSLib` one it
uses for the documents.

`POST`, `application/x-www-form-urlencoded`:

| field | format |
|---|---|
| `name` | `name=%s` |
| `passwd` | `&passwd=%s` |
| `email` | `&email=%s` |
| `region` | `&region=%d` |
| `gender` | `&gender=%d` |
| `age` | `&age=%d` |
| `pswdnew` | `&pswdnew=%s` (password change only) |

Each field is formatted through a 48-byte buffer and rejected if it does not fit.

The response must be a bare decimal integer, strictly under 10 bytes. At
`0x00b204e8` the client checks the body length against 10 *before* looking at
the content, and returns `-10015` if it is longer. It then `strtol`s the body;
the result becomes the call's return value, and the caller tests it with `beqz`.

So: **`0` means success**, and serving an HTML page fails every registration
regardless of what was in the form.

---

## Differences between the two games

| | Extreme 2 | SuperNOVA |
|---|---|---|
| gate port | 9573 | 19573 |
| account / lobby port | 9573 | 19570 |
| endpoint storage | inline in code | table at `0x002d0120` |
| `0x2002` SvrList BEGIN | empty | u32 BE result code |
| `0x3012` player file | 42 B/entry, stride 48 | 30 B/entry, stride 36, different order |
| `0x4201` block record | `u16, u8, str16, u16` | `u8, str16, u16, u16` |
| `0x4200` reply | one message | three (`0x4204`, `0x4201`, `0x4205`) |
| account creation | gate protocol | HTTP POST |
| `0x70xx` / `0x80xx` | absent | six opcodes, three-part groups |
| `0x3120` | absent | three-part list, 592-byte records |
| debug strings | full `NetPrg*` RPC name table | transport strings only, no RPC names |

### SuperNOVA multi-part groups

```
0x3120: (0x3121 BEGIN 4B status, 0x3122 DATA, 0x3123 END empty)
0x4200: (0x4204 BEGIN 4B status, 0x4201 DATA 21B, 0x4205 END empty)
0x5030: (0x5031 BEGIN 4B status, 0x5032 DATA, 0x5033 END empty)
0x5034: (0x5035, 0x5036, 0x5037)
0x7000: (0x7001 BEGIN 8B, 0x7002 DATA, 0x7003 END 4B status)
0x7010: (0x7011 BEGIN 8B, 0x7012 DATA, 0x7013 END 4B status)
0x8000: (0x8001 BEGIN 4B status, 0x8002 DATA, 0x8003 END 4B status)
0x8004: (0x8005 BEGIN 4B status, 0x8006 DATA, 0x8007 END 4B status)
```

`0x7001` and `0x7011` are **8-byte** BEGINs, u32 status plus an s32 count,
clamped to `0x2800`, where every other BEGIN is a bare 4-byte status. The
pattern does not generalise; check each one.

---

## DNAS

Both games authenticate against Sony's DNAS before reaching Konami's servers.
Those servers are also dead, so the check can never pass.

Extreme 2 polls and continues on failure. The login-side wrapper at
`0x001d5280` returns 1 = ok / 0 = busy / -1 = error; stubbing it to return 1 is
sufficient, and `0x001d5284` already holds the required instruction.

SuperNOVA uses DNAS2 and behaves differently, but does not need DNAS2
defeated either, only its *verdict* overridden, and the verdict is read in
exactly one place.

The DNAS layer that matters is **game code in `DATA03.BIN` (`net_mas4`)**, not
Sony's library. A scene object drives it through a 17-state machine; state 10
(`0x00a46fb8`) reads the result, and the draw function's test is the whole
thing:

```
result type 5  ->  "Authenticated."
anything else  ->  error table lookup
```

`obj+0x58 == 5` is the entire definition of "DNAS passed".

The `-621` seen on failure is not a cryptographic rejection: it is socket errno
`-12` from Konami's own DNAS2 transport (`proc_send`, `0x00a650d8`), the
connection to the dead Sony host.

This must be a file patch, not a pnach. `0x00a46000` is an overlay slot
shared by `DATA03` (`net_mas4`) and `DATA04` (`netlby_mas4`); a runtime patch
there corrupts whichever module is resident. `tools/isopatch.py` patches the
disc image.

---

## Known gaps

- Which step of the card's texture upload an 8-bit banner breaks is not pinned down. The cause of the id 8 hang is: it is the only 8-bit banner of the 74. See [A song id that hangs the client](#a-song-id-that-hangs-the-client-wire-id-8).
- The GS state fields that read `0x50`/`0x5000` in a hung capture and `0x10`/`0x400` in a healthy one are a reliable classifier but are **not identified**: they are offsets into PCSX2's savestate struct, and naming them needs the emulator's source.
- SuperNOVA's `0x441e` GetRuleMask is now served: `u32` status plus four `u8` into `ctx+0x12e3c`..`0x12e3f`, 8 bytes (`--sn-rule-mask`). Extreme 2's is a different shape, 7 bytes, and is served too; see [Rule mask](#rule-mask-0x441e-extreme-2-7-bytes). What the four SuperNOVA bytes *mean* is still unconfirmed: it ships no equivalent of the header strings that named Extreme 2's three.
- The trailing `s32` of each `0x8002` song record is served as 0. `FUN_0027e970` returns it and the parser sums it into `ctx+0x2c60` as a total; its meaning is unestablished (`--sn-song-extra`).
- SuperNOVA's `0x8004` list (20 records of `s32` + 32-byte name) is served empty. Its only reader is in `DATA08 net_https_mas4` (`0x00b2a0f0`), which also reads the friends count, so it feeds the web-backed "Online Contents Menu", not the song list.
- The 1024 bytes of each `0x7002` are served as zeros. The shape is certain, the parser copies exactly `0x400` into a per-song buffer and nothing advances the pointer, so one message per group, but the contents are not the chart (those ship on the disc, 8–24 KB) and are otherwise unidentified.
- SuperNOVA matchmaking is unimplemented. The *mechanism* is now read out of the binary, see [Matchmaking (SuperNOVA)](#matchmaking-supernova): an event-flag array at `ctx+0x142f4`…`0x14306`, with `0x4a04`/`0x4a13` as the match pushes and their 67-byte record decoded. What is not known is the sequence: which push the server sends when, and what a room's lifecycle looks like from the server's side. None of it has been exercised against the client.
- Eight SuperNOVA requests reach the client through the `+1` fallback with no body: `0x4413`, `0x4416`, `0x4432`, `0x4512`, `0x4a00`, `0x4a02`, `0x4b00`, and `0x4323`'s 55-byte `0x4324`. The opcode is right in each case, the response has a parser and no in-flight check to fail, but a short read there is silent, so the fields come from whatever the message buffer last held. `0x4b01` is 44 bytes and `0x5021` and `0x0007` are now served properly.
- `0x4390` is inferred, not observed: `0x4391` is an END on the state block `ctx+0x2378` shared with `0x4393` and `0x4395`, whose requests are the known `0x4392` and `0x4394`. `tools/snreqmap.py` does not find a `0x4390` issuer, so either the request is built in a way the scan misses or the reply is a push.
- The Extreme 2 RC header fields `R+0x08`, `R+0x0c` and `R+0x0d` are decoded structurally, their ranges and the tables they index are known, but the words they select are in a message table built at runtime from non-ASCII data, so nothing here says what they *say*. `R+0x0f` is parsed and read by nothing.
- The two `0x44b0` tail fields `R+0x01` and `R+0x02` are read by nothing in either binary. They are documented as inert rather than unknown. The `0x5012` schedule's second `u32` is the same: stored to `DAT_01047ca8`, never loaded.
- The four result values in `0x5006` GetRCRegist are decoded structurally, widths, order and the play-record offsets they come from, but not named. They are written through a base pointer from an overlay, so no string reaches them; one real Ranking Challenge play names all four off the server log. See [Entering a challenge and posting a result](#entering-a-challenge-and-posting-a-result).
- The `0x3122` record (592 bytes: three s32, a 64-byte string, a NUL-terminated string up to 512) is decoded structurally but its meaning is unconfirmed. Serving an empty list is accepted.
- The Extreme 2 `0x3003` credential blob is keyed on its first 8 bytes; the remaining fields are opaque.
