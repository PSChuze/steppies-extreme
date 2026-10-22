# DDR Online

A replacement for the online servers of three PlayStation 2 games. Konami shut
both services down years ago. This brings them back on a machine you control.

| game | serial | state |
|---|---|---|
| Dance Dance Revolution Extreme 2 (USA) | SLUS-21174 | Playable. Login, lobby, head-to-head matches, Ranking Challenge, rankings and personal records. |
| Dance Dance Revolution SuperNOVA (USA) | SLUS-21377 | Playable. Account creation, matchmaking, chat, friends and tournaments work. |
| Dance Dance Revolution SuperNOVA 2 (USA) | SLUS-21608 | In progress. Login, lobby, rooms and tournaments are in place; matchmaking between two players is written from the disc and not yet tried against a client. |

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

## The easy way: DDR Online Setup

Not comfortable with a terminal? Download DDR Online Setup for your computer
from Releases (Windows, Mac with Apple silicon, or Linux) and run it. It asks
three questions: who will play, where your disc images are, and what to call
the server. Then it starts the server, checks it, and tells you how to point
PCSX2 or a console at it. Run it again for a menu: start and stop, settings,
updates, backups, patching a disc, and connecting to an OpenLobby admin panel.

On Windows and macOS it runs the server straight on your computer, no Docker
needed, so players' real addresses reach the server. On Linux it uses
docker compose with the file below. [docs/setup.md](docs/setup.md) is the
guide. From a copy of this repository, `python3 setup.py` does the same.

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
python3 server/gate.py --host 0.0.0.0 --also-listen 19573,19570,29573,29570 \
                       --serve-svrinfo --serve-svrlist --serve-block --serve-rc \
                       --udp-relay
python3 server/stun.py --host 0.0.0.0
python3 server/web.py  --host 0.0.0.0    # SuperNOVA and SuperNOVA 2
```

### Pointing the console at it

Both games find their servers by DNS, so you need to control what the console
resolves. Point these names at the machine running the server:

| name | game | service |
|---|---|---|
| `dx2gate01.konamionline.com` | Extreme 2, SuperNOVA | gate |
| `game.ddr.konamionline.com` | SuperNOVA 2 | gate |
| `dx2stun.konamionline.com` | Extreme 2 | STUN |
| `ddrsnstun.konamionline.com` | SuperNOVA, SuperNOVA 2 | STUN |
| `dx2web.konamionline.com` | SuperNOVA | HTTP |
| `www.ddr.konamionline.com` | SuperNOVA 2 | HTTP |
| `info.service.konamionline.com` | SuperNOVA, SuperNOVA 2 | HTTP |

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

**If players reach you through another machine, set `--public-addr` yourself.**
The automatic lookup finds the address of the line the server sits on. That is
what you want behind an ordinary port forward. It is the wrong answer when
players connect to a VPS, a tunnel or a reverse proxy that forwards to you and
keeps each player's own source address: every one of them counts as "arriving
from the internet", and every one of them is handed your home address, in the
server list and in the STUN replies. If the point of the front machine was to
keep that address private, the default defeats it. Give both programs the
address players actually dial:

```
python3 server/gate.py --public-addr 203.0.113.10 ...
python3 server/stun.py --public-addr 203.0.113.10 ...
```

To check it, send a STUN request to the public address from outside and look
at SOURCE-ADDRESS and CHANGED-ADDRESS in the reply. Both must be the front
machine's address.

### Ports

| port | service | game |
|---|---|---|
| 9573 | gate, account, lobby | Extreme 2 |
| 19573 | gate | SuperNOVA |
| 19570 | account, lobby | SuperNOVA |
| 29573 | gate | SuperNOVA 2 |
| 29570 | account, lobby | SuperNOVA 2 |
| 19580 | HTTP | SuperNOVA, SuperNOVA 2 |
| 3478–3479/udp | STUN | both |
| 19600–19615/udp | match relay | SuperNOVA, SuperNOVA 2 |
| 19581, 19582, 19583 | the boards, one page per game | Extreme 2, SuperNOVA, SuperNOVA 2 |

SuperNOVA reads its ports from a table in its executable, and they are not the
same as Extreme 2's. It also plays matches peer to peer over UDP, which two
consoles behind an emulator or a home router cannot do directly, so the gate
relays that traffic on 19600–19615. Extreme 2 needs none of this: its match
traffic already travels over the lobby connection.

SuperNOVA 2 has its own pair, 29573 and 29570, and its own gate name. The
server tells the games apart by the port each connection arrives on, so a
SuperNOVA 2 player only ever sees, joins and plays other SuperNOVA 2 players.
Accounts are shared: the same username logs in to either SuperNOVA.

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
SuperNOVA by 160, SuperNOVA 2 by 156.

There is no `.xdelta` for SuperNOVA 2 in Releases yet, so use `isopatch.py`
for it.

For Extreme 2 under PCSX2 you can skip the disc patch and drop
`patches/SLUS-21174_E8FB7A7F.pnach` into your `cheats/` folder instead. There is
no working pnach for either SuperNOVA: the DNAS2 code sits in an overlay slot
nine modules take turns in, so a per-frame write corrupts whichever one happens
to be loaded, and a pnach cannot check first.

On a console with a real disc in the drive there is nothing to patch, so
all three games get cheat codes instead: `patches/cheats/DDR-Online.txt`,
generated from the same manifest, for Cheat Device PS2 under FreeMcBoot.
[docs/cheats.md](docs/cheats.md) is that guide. SuperNOVA's codes test the
resident module before writing, which is the part a pnach has no way to say.

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

## SuperNOVA 2 tournaments

SuperNOVA 2 runs its tournaments the same way, from the calendar: a five-song
WEEKLY CUP that changes every Thursday at 00:00 UTC and steps through basic,
difficult and expert, and a ten-song MARATHON every 28 days. The next one of
each shows as upcoming. Every period has its own id, so each board starts
empty. To run your own instead, put a `sn2_competitions.json` beside the
database, in the same format as SuperNOVA's `sn_competitions.json`.

The page wants a token in the URL. One is generated on first run and printed in
the log:

```sh
docker compose logs web | grep operator
```

There is no login beyond that token, and it travels in the clear. Port 19580
has to be reachable for SuperNOVA, so by default the page answers only LAN,
tailnet and loopback addresses. A request from the internet gets the same
answer as if the page did not exist. `--admin-from any` on `web.py` lifts that.

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

## Boards

Each game has a live board: a web page showing who is online and the current
standings, and optionally a Discord message that keeps itself up to date.
SuperNOVA and SuperNOVA 2 show each tournament's ranking. Extreme 2 shows this
week's Ranking Challenge and the head-to-head points. The numbers come from the
same queries as the in-game ranking screens, so the board and the console
always agree.

The boards look like the games because they are drawn with the games' own art:
backgrounds, rank plates and fonts. That art is on your discs, not in this
project, so bake it once from the folder holding your disc images:

```sh
docker compose run --rm -v "$PWD:/discs:ro" boards python3 boardart.py /discs/*.iso
```

That writes PNGs and an index into the state volume, under `boardart/`. Clean
and patched images both work. Discs it does not recognise are skipped.

The pages are on ports 19581 (Extreme 2), 19582 (SuperNOVA) and 19583
(SuperNOVA 2). To post a board to Discord, create a webhook for the channel and
put its URL in a `.env` file beside `docker-compose.yml`:

```sh
DDR_BOARDS_SN_DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```

The board posts one message and edits it in place, at most once a minute, with
a picture of the game's ranking screen. A new week, a new leader, or a
tournament opening or closing goes out as a short post that deletes itself
after ten minutes. `DDR_BOARDS_SN_URL` adds a link to the page. The variables
for the other two boards start `DDR_BOARDS_E2_` and `DDR_BOARDS_SN2_`.

A board can also run as a Discord bot instead of a webhook. Create an
application in the Discord developer portal, invite its bot, and give the board
its token, application id and public key:

```sh
DDR_BOARDS_SN_DISCORD_BOT_TOKEN=...
DDR_BOARDS_SN_DISCORD_APP_ID=...
DDR_BOARDS_SN_DISCORD_PUBLIC_KEY=...
DDR_BOARDS_SN_URL=https://your.host/
```

Set the application's interactions endpoint to the page's URL followed by
`/discord/interactions`, which must be reachable from the internet. In a
server, a member who can manage it runs `/ddrsnboard here` in the channel the
board should post in. `/ddre2board` and `/ddrsn2board` do the same for the
other two. Each server gets its own board, and the bot's status shows how many
players are online.

The bot's board message has buttons that switch what it shows: each
tournament's ranking, the ONLINE PLAY screen with the stages and who is in the
lobby, or Extreme 2's two cards and head-to-head tables. The picture comes from
the board's public page, so the page must be reachable from the internet.
`/ddrsnboard news` in another channel turns on lasting announcements there: a
tournament opening or ending, or a new Ranking Challenge week.

If the server runs beside a PlayOnline (OpenLobby) stack, the bots can take
their credentials from its admin page instead. Give the boards container
`POL_DATABASE_URL`, `POL_BOT_KEY` and `POL_VALKEY_URL`, and add the bots
(`ddre2`, `ddrsn`, `ddrsn2`) to that stack's `POL_BOT_EXTRA`. A bot restarts
within a minute of its credentials changing there.

The boards read the database and never write to it. They run in their own
container, so a problem there cannot affect a game in progress. The gate writes
who is online to `live.json` in the state volume every five seconds, and
`--live-file off` turns that off.

## OpenLobby admin panel

The server can be run from an OpenLobby admin panel, beside any other games
that panel looks after. The gate describes itself to the panel over a small HTTP port (`server/adminport.py`), so the
panel needs no DDR code of its own. From the panel you get:

- who is online, in which game and what they are doing, and the open
  tournaments and Ranking Challenge week;
- the Ranking Challenge weeks and every tournament on the panel's calendar;
- **Message in the lobby**: a line in the SuperNOVA and SuperNOVA 2 lobby
  chat, which the panel's maintenance warning uses too. Extreme 2 has no chat,
  so its players do not see it;
- **Disconnect a player**, also used by the panel's Kick. It ends the
  connection and bans nobody;
- a player search, and each linked account's dancers with their records;
- three pages: **Rankings**, **News and events** (news, SuperNOVA server
  information and the Ranking Challenge override, the same things the operator
  page edits) and **Tournaments**, to add or remove SuperNOVA and SuperNOVA 2
  tournaments without editing the JSON files by hand.

The setup program connects the two for you. By hand: put a long random
`DDR_ADMIN_TOKEN` in `.env`, add `COMPOSE_PROFILES=openlobby`, create the
panel's network if it does not exist yet, and start again:

```sh
docker network create openlobby
docker compose up -d
```

The gate's admin port, 19591, listens only on Docker's bridge address
(`DDR_ADMIN_BIND`, 172.17.0.1 unless set), and the `admin` service puts it on
the panel's network as `http://ddr:19591`. Give the panel that address and the
token (`POL_ADMIN_GAME_DDR_URL`, `POL_ADMIN_GAME_DDR_TOKEN`), or pair it from
the panel's Settings, Modules page with the setup program. Without a token the
admin port stays off.

### Linking website accounts

An OpenLobby website can also let players link their DDR login to their
website account, and set a new DDR password there. That needs the key the
games encipher logins with, which is on your disc and not in this project:

```sh
python3 tools/loginkey.py "DDR SuperNOVA (USA).iso" /path/to/state/loginkey.bin
```

Any of the three discs will do. Then set `GAMELINK_SECRET` (32 characters or
more, the same value the website has) and the gate answers the website on
127.0.0.1:19590. Without the secret, or the key, it stays off.

## Layout

```
server/     the server: gate, STUN responder, SuperNOVA web service
tools/      analysis tools and the disc patcher
patches/    disc-patch manifest, PCSX2 pnach files, console cheat codes
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
| `server/boards.py` | the boards' web pages and Discord messages |
| `server/boarde2.py`, `boardsn.py`, `boardsn2.py` | each game's board |
| `server/boardart.py` | bakes the boards' art from your discs |
| `server/boardimg.py`, `boardpage.py` | draw a board's screens; the page that shows them |
| `server/boarddata.py` | what the boards read: database, live.json, calendar |
| `server/boardbot.py` | a board as a Discord bot: its command, posts and status |
| `server/discordgw.py` | the Discord Gateway session behind a bot's status |
| `server/polregistry.py` | bot credentials from a PlayOnline admin page, optional |
| `server/boardtest.py` | offline checks for the boards, no disc required |
| `server/adminport.py` | the gate's port for an OpenLobby admin panel |
| `server/adminrelay.py` | carries that port onto the panel's Docker network |
| `server/ddrlink.py`, `gamelink.py` | the website account link, optional |
| `tools/loginkey.py` | copies the login key from your disc, for the account link |

## Documentation

- [docs/setup.md](docs/setup.md). The setup program, step by step, for people
  hosting a server.
- [docs/patching.md](docs/patching.md). Getting past DNAS: which dump you need,
  applying the patch, real hardware, and why SuperNOVA cannot use a pnach.
- [docs/cheats.md](docs/cheats.md). The same edits as runtime codes, for
  booting the original disc on a console.
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

SuperNOVA 2 is SuperNOVA's client rebuilt, so a SuperNOVA 2 session is also
`is_sn`, and `Session.is_sn2` gates the places it differs: rooms with four
slots, pushes that name a player id, and a join that fetches the room with
`0x4332` instead of asking for the opponent's address. The SuperNOVA 2 section
of [docs/protocol.md](docs/protocol.md) lists them.

If a client hangs on an opcode the server does not know, `tools/sndispmap.py`
prints the whole receive map: each request, the responses that answer it, and
the shape of each body. That turns an unknown opcode into a lookup. Give it
either game's executable, `SLUS_213.77` or `SLUS_216.08`.

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
