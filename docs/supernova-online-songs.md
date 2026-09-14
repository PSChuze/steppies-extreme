# SuperNOVA, the online song unlock

The manual's "extra songs over the network" feature, found and traced in
`SLUS_213.77` and `DATA04.BIN` (`netlby_mas4`).

Short version: five songs ship on the disc, charts and all, and are locked
behind a server-supplied availability list. The server decides which songs a
player may pick, per difficulty. We have been serving that list empty, so
nothing has ever been unlocked.

Nothing here is confirmed against a running client yet, it is all read out of
the binary. The wire shapes are exact; the two places where meaning is inferred
rather than proved are called out as such.

---

## The five songs

The disc holds 79 songs as an array of `0xa8`-byte records at `0x002c1b90`,
each beginning with a 4-character code. The last five are the online ones:

| id | code | title | chart on disc |
|---|---|---|---|
| 74 `0x4a` | `felw` | Feelings Won't Fade (Extend Trance Mix) | `online/ssq/00_felw_b.bin` |
| 76 `0x4c` | `nizi` | NIJIIRO | `online/ssq/01_nizi_b.bin` |
| 75 `0x4b` | `punc` | HONEY PUNCH | `online/ssq/02_punc_b.bin` |
| 77 `0x4d` | `silv` | Silver Platform - I wanna get your heart - | `online/ssq/03_silv_b.bin` |
| 78 `0x4e` | `trim` | Trim | `online/ssq/04_trim_b.bin` |

Titles come from the `code\0title\0` table at file `0x001f6300`–`0x001f6a80`.

The charts are on the disc, not on the server. Each `online/ssq/*.bin` has a
real entry in the file index at `0x001ab9a0` (stride `0x2c`) with a size of
8–24 KB, and the music (`MUSIC/felw.vig`) and select-screen art
(`SEL/felw_s.vig`) ship too. So this is a lock, not a download, which is the
whole reason the feature is still recoverable with the servers dead.

The id order above is the download order, from the five-entry table at
`0x002d1290` (`0x4a, 0x4c, 0x4b, 0x4d, 0x4e`), and it matches the `00_`..`04_`
numbering of the filenames exactly. That agreement is what identifies the table.

## The lock

`FUN_0027ec80(song, difficulty, mode)` is the gate. It searches `ctx+0x26b0`
for a record whose id matches the song, and returns `-1`, "not available":
unless the flag for that difficulty is set:

```
count  = *(s32 *)(ctx + 0x26b0)
entry  = ctx + 0x26b4 + i * 0x10        // first match on entry[0] == song
                                        // difficulty 1..5 -> entry+4 .. entry+8
```

`FUN_0027e970` is the same lookup returning the record's trailing `s32` instead
of the id.

The only thing that ever writes `ctx+0x26b0` is the `0x8002` parser. That is
the load-bearing fact: the list has no other source, so it is entirely
server-driven.

Who calls the gate, across all thirteen overlays:

| module | calls |
|---|---|
| `DATA04` `netlby_mas4` | 56 |
| `DATA08` `net_https_mas4` | 2 |
| every other module | 0 |

So the gate governs song choice **inside the online lobby** and nowhere else.
`DATA11` `shop_mas4` reads the same song table but never consults the gate, so
the shop is a separate, offline unlock path and is not affected by any of this.

## Wire format

### `0x8000`, the availability list

No request body. Group is `0x8001` BEGIN, `0x8002` DATA, `0x8003` END; BEGIN and
END are each a bare `u32` status.

`0x8002` body, from the parser at `0x0026b5a0`: **13 bytes per record, no
delimiter and no count**; the loop just reads until the payload runs out:

| field | size | meaning |
|---|---|---|
| id | s32 BE | song id, 0–78 |
| available | 5 × u8 | one per difficulty, tested `== 1` |
| ? | s32 BE | returned by `FUN_0027e970`, and summed across all records into `ctx+0x2c60` as a total. **Meaning not established**, serve 0. |

Records accumulate across messages and the client caps the array at `0x5a` = 90.
A single frame holds 78 (the payload cap is 1024 bytes), so serving all 79 takes
two `0x8002` messages.

The five flags are per-difficulty: the gate maps its `difficulty` argument 1–5
onto `entry+4`..`entry+8`, and each of those paths also calls
`FUN_0022a3e0(record, style, n)` with chart difficulty `n` = 0–4. That is what
identifies them as difficulties rather than five unrelated booleans.

### `0x8004`, a 20-entry name list

`0x8005`/`0x8006`/`0x8007`, BEGIN and END again a bare `u32` status. `0x8006`
records (parser `0x0026b2b0`) are `s32 id` + a fixed 32-byte name, same
read-until-empty loop, capped at 20. Fetched immediately before the
availability list. **What it names is not established.**

### `0x7000`, a 1 KB blob per song

Issued once per online song, but only for songs the gate has already approved.
Request is `u32` + `u16` (player id and song id); the reply is `0x7001` BEGIN
(`u32` status + `s32`), `0x7002` DATA, `0x7003` END (`u32` status).

`0x7002` copies **exactly 1024 bytes** into a per-song buffer
(`FUN_00279b10(msg, dst, 0x400)`). Nothing advances the destination pointer
between messages, so **one `0x7002` per group**, a second would overwrite the
first. The `s32` from `0x7001` lands in `ctx+0x303c`, which nothing reads.

This is **not** the chart: the charts are on the disc and are 8–24 KB. What the
1 KB is has not been established. It is small, per-song, and keyed by player.

## Boot order

`FUN_00288200` is the online session state machine. One RPC per state:

| state | RPC |
|---|---|
| 3 | `0x411a` SetMyAddr |
| 4 | `0x8004` name list |
| 6 | `0x4104` |
| 7 | `0x441d` GetRuleMask |
| 8 | `0x8000` **availability list** |
| 9 | `0x7000` ×5, one per online song, each gated on `FUN_0027ec80(song, 0, 2)` |

State 9 sets a per-song "got it" byte at `+0x4023+i` and writes into the buffer
at `+0x4028+i*4`.

Because state 9 is gated, enabling songs in `0x8000` is what *causes* the five
`0x7000` requests. A server that starts answering `0x8000` must answer `0x7002`
too, or the client copies 1024 bytes of whatever is left in the message buffer.

## `0x441e` GetRuleMask, the shape, for the record

Closes the gap listed in `protocol.md`. Parser `0x0026e570`:
`u32` status, then **four** `u8` into `ctx+0x12e3c`..`0x12e3f`, where Extreme
2's parser reads three. Eight bytes total. Now served (`--sn-rule-mask`);
the four bytes' meanings are still unconfirmed.

---

## Server support, implemented, UNTESTED

`server/gate.py`, SuperNOVA paths only. Off by default: `--sn-songs` defaults to
`none`, which serves the same empty list as before, so nothing changes until it
is asked for.

| flag | effect |
|---|---|
| `--sn-songs online` | unlock the five online songs, all five difficulties |
| `--sn-songs all` | unlock all 79 (two `0x8002` frames) |
| `--sn-song-extra N` | the unidentified trailing `s32`; a knob for finding out what it is |
| `--sn-rule-mask a,b,c,d` | the four `0x441e` bytes |

`0x8006` is served empty (we do not know what it names) and `0x7002` serves 1024
zero bytes, which is required rather than optional: unlocking songs is what
causes the client to ask for them at all.

Sending it needed one structural change, `payload_for` may now return a *list*
of bodies and `on_frame` sends one frame per entry, because 79 records is 1027
bytes against a 1024-byte cap. Everything else returns a single body and takes
the same path as before.

`server/selftest.py` covers the record strides, the 78-record split, the caps
and the two rule-mask shapes: 32 new checks, all passing. **None of this has
been in front of a client.** The wire shapes are read out of the binary and the
encoding is verified against the client's own decoding rule, but whether the
game actually offers the songs afterwards is unverified.

Two things to watch on the first live run:

- The trailing `s32` is served as 0 because its meaning is unknown. If the
  unlock half-works, songs listed but not selectable, that field is the first
  suspect; try `--sn-song-extra 1`.
- `0x7002`'s 1024 zero bytes are a guess at content, not at shape. Whatever the
  blob is, the client will accept it and set its "got it" flag.
