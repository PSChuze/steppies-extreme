# DDR Online

A replacement for the online servers of two PlayStation 2 games. Konami shut
both services down years ago. This brings them back on a machine you control.

| game | serial | state |
|---|---|---|
| Dance Dance Revolution Extreme 2 (USA) | SLUS-21174 | Playable. Login, lobby, head-to-head matches, Ranking Challenge, rankings and personal records. |
| Dance Dance Revolution SuperNOVA (USA) | SLUS-21377 | Playable. Account creation, matchmaking, chat, friends and tournaments work. |

Everything was recovered from the retail discs and checked against a real
client. Claims in the documentation carry the address or the wire trace they
came from.

The server is Python standard library only. Nothing to build, nothing to
install.

## What is not here

No game data. No disc images, nothing extracted from a disc, no decompiler
projects, no strings or disassembly dumps. You need your own copy of each game.
The files under `patches/` describe addresses and instructions, and you apply
them to your own disc.

## Running it

```sh
docker compose up -d
```

That is the whole setup. No environment variables and no files to copy. State
lives in a named volume and survives restarts.

Host networking is required, so this wants Linux. A NAS or a small VM is fine.
Docker Desktop on Windows and macOS does not pass the real source address of
incoming packets to containers, and STUN cannot work without it. On those, run
the scripts in `server/` directly.

Without Docker:

```sh
python3 server/selftest.py     # offline checks, no client needed
python3 server/gate.py --host 0.0.0.0 --also-listen 19573,19570 \
                       --serve-svrinfo --serve-svrlist --serve-block --serve-rc \
                       --udp-relay
python3 server/stun.py --host 0.0.0.0
python3 server/web.py  --host 0.0.0.0    # SuperNOVA only
```

### Pointing the console at it

Both games find their servers by DNS, so you need to control what the console
resolves. Point these names at the machine running the server:

| name | game | service |
|---|---|---|
| `dx2gate01.konamionline.com` | both | gate |
| `dx2stun.konamionline.com` | Extreme 2 | STUN |
| `ddrsnstun.konamionline.com` | SuperNOVA | STUN |
| `dx2web.konamionline.com` | SuperNOVA | HTTP |
| `info.service.konamionline.com` | SuperNOVA | HTTP |

Any DNS server that can override a name will do. On PCSX2 the built-in DNS
overrides are enough.

The address the client is told to dial after the gate phase is worked out per
connection, so there is nothing to configure for that. A client on your network
is given whichever address it reached the server on. A client arriving from the
internet through a port forward would get a LAN address it cannot dial that
way, so it is given the server's public address instead. The server looks that
up over STUN the first time such a client connects, and re-checks it every
five minutes, so a home connection whose IP changes keeps working without a
restart. `--public-addr` on `gate.py` and `stun.py` changes where it comes from:
`off`, or a name such as a dynamic DNS hostname. `--svr-addr` still overrides
all of it, for every client.

### Ports

| port | service | game |
|---|---|---|
| 9573 | gate, account, lobby | Extreme 2 |
| 19573 | gate | SuperNOVA |
| 19570 | account, lobby | SuperNOVA |
| 19580 | HTTP | SuperNOVA |
| 3478–3479/udp | STUN | both |
| 19600–19615/udp | match relay | SuperNOVA |

SuperNOVA reads its ports from a table in its executable, and they are not the
same as Extreme 2's. It also plays matches peer to peer over UDP, which two
consoles behind an emulator or a home router cannot do directly, so the gate
relays that traffic on 19600–19615. Extreme 2 needs none of this: its match
traffic already travels over the lobby connection.

Port 19580 is this project's choice. The stock URLs use 80 and 443, and the
disc patch rewrites them to something that will not collide.

## The discs

Both games check with Sony's DNAS before reaching Konami's servers. DNAS is
also gone, so the check can never pass and has to be bypassed on the client
side. [docs/patching.md](docs/patching.md) is the guide. It covers emulator and
real hardware, and which dump you need.

Short version: take the `.xdelta` for your game from Releases and apply it to
your own dump with [DeltaPatcher](https://github.com/marco-calautti/DeltaPatcher)
or `xdelta3 -d`. No Python needed. Or do it here:

```sh
python3 tools/isopatch.py "SuperNOVA (USA).iso" "SuperNOVA (USA) [ONLINE].iso"
```

Either route checks every original byte before writing anything, and rewrites
sectors in place so the disc layout is untouched. Extreme 2 changes by 4 bytes,
SuperNOVA by 160.

For Extreme 2 under PCSX2 you can skip the disc patch and drop
`patches/SLUS-21174_E8FB7A7F.pnach` into your `cheats/` folder instead. There is
no working cheat file for SuperNOVA: its DNAS2 code sits in an overlay slot
shared with another module, so a per-frame write corrupts whichever one happens
to be loaded.

Extreme 2 also needs a network configuration on the memory card and ships no way
to create one. SuperNOVA includes Sony's configuration tool, so if you have
both, set the configuration up in SuperNOVA first.

## Ranking Challenge

The server runs a challenge without being told to. The week number and its
countdown come from the calendar, and each challenge gets ten songs derived from
the week, so the lineup changes every seven days on its own. A server nobody
looks after still has something running in the Ranking Challenge tab.

Results are kept. Every Ranking Challenge play and every head-to-head match is
stored in the database, and the ranking boards, the personal logs and the
player stats are built from it. The original points formula is not known, so
points are the server's own rule: 3 for a win, 1 for a draw.

If you want to say something specific, the web service has an operator page at
`/admin` on port 19580. It edits news items and lets you pin the songs,
difficulty or length of any challenge. Anything you leave alone stays generated,
so you can fix the difficulty and let the songs keep rotating.

The page wants a token in the URL. One is generated on first run and printed in
the log:

```sh
docker compose logs web | grep operator
```

There is no login beyond that token. It is sized for a game server on a home
network. Do not put port 19580 on the internet.

## Accounts

Accounts, player files and results live in a SQLite database, `ddr.db`, in the
state volume. It uses Python's built-in `sqlite3`, so there is still nothing to
install. Back it up or reset it by copying or deleting that one file. A server
upgraded from the older JSON files imports them into the database once on first
start and leaves the originals untouched.

Both games have a username and password. At login the client sends a 48-byte
blob: a 32-byte username followed by MD5 of the username, a 16-byte challenge
the server issued, and the password. The server never receives the password
itself, only that digest.

The server does not verify it. It reads the username as the account identity
and creates the account the first time it sees one, accepting whatever digest
came with it. So in practice anyone who can reach the gate gets in, and the
account is only as strong as knowing its username. That is fine for a private
server on a LAN or a tailnet, and it is not an authentication system. Do not
expose the gate to the open internet.

Verifying the password is possible and not yet done: with a fixed challenge the
digest is stable, so a registration flow could store it and the gate could
compare. SuperNOVA's registration is a web form, so its password arrives in the
clear there; the server records that a registration happened and redacts the
password and email, because nothing reads them back yet. `--reg-keep-secrets`
keeps them, which is for protocol work against your own client, not for a
server other people use.

## Layout

```
server/     the server: gate, STUN responder, SuperNOVA web service
tools/      analysis tools and the disc patcher
patches/    disc-patch manifest and PCSX2 cheat files
docs/       protocol specification and research notes
```

| file | does |
|---|---|
| `server/gate.py` | gate, account and lobby, all three phases, both games |
| `server/stun.py` | RFC 3489 STUN responder, for the client's NAT check |
| `server/web.py` | SuperNOVA's HTTP service, and the operator page |
| `server/schedule.py` | the challenge calendar and generator |
| `server/content.py` | operator-edited news and challenges |
| `server/results.py` | result decoders, and the ranking/log/stat queries |
| `server/db.py` | SQLite storage for accounts, player files, friends and results |
| `server/selftest.py` | offline protocol checks, no client required |

## Documentation

- [docs/patching.md](docs/patching.md). Getting past DNAS: which dump you need,
  applying the patch, real hardware, and why SuperNOVA cannot use a cheat file.
- [docs/protocol.md](docs/protocol.md). The wire protocol: framing, opcodes,
  payload layouts, and every place the two games differ.
- [docs/research-log.md](docs/research-log.md). How it was worked out and, more
  usefully, what turned out to be false. Knowing what is not true is most of the
  value in work like this.

## Working on it

The thing to know before changing anything: the two games share a frame format
and a backend, but their payloads are not interchangeable. The worst case found
so far is the block-list record, which is 21 bytes in both games with every
field shifted by one. A length check does not catch that. `Session.is_sn` in
`gate.py` gates every divergence.

If a client hangs on an opcode the server does not know, `tools/sndispmap.py`
prints the whole receive map: each request, the responses that answer it, and
the shape of each body. That turns an unknown opcode into a lookup.

It cannot see every group. Some families keep their state in a block of their
own and never compare the request in flight, so they do not show up that way.
`tools/snblocks.py` groups parsers by that block instead. Both times a group was
missed, the symptom was a freeze rather than an error.

Findings that turned out to be wrong are marked as wrong in the research log
rather than deleted, so the corrections can be checked too.

## Legal

Not affiliated with or endorsed by Konami or Sony. No copyrighted material is
distributed here and no means of obtaining any is provided. This reimplements a
discontinued network service so that games people already own keep working.
