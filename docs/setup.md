# Setting up a server with DDR Online Setup

DDR Online Setup puts a server for Dance Dance Revolution Extreme 2,
SuperNOVA and SuperNOVA 2 on your computer. It asks three questions, starts
the server and tells you what to do next. Later it is where you start and stop
the server, change settings, make backups and patch your discs.

You need your own copy of each game as a disc image (.iso). The setup program
and the server contain no game data.

## Get it

Download the program for your computer from the
[Releases page](https://github.com/PSChuze/steppies-extreme/releases):

| computer | file | notes |
|---|---|---|
| Windows 10 or 11 | `DDR-Online-Setup.exe` | nothing else to install |
| Mac with Apple silicon | `DDR-Online-Setup-mac.zip` | nothing else to install |
| Linux (x86-64) | `DDR-Online-Setup-linux-x86_64` | needs Docker |

**Windows.** Double-click the program. The first time, Windows may say
"Windows protected your PC", because the program is not signed. Click
"More info", then "Run anyway".

**Mac.** Open the zip, then right-click `DDR-Online-Setup` and choose Open
(a double-click is refused the first time, because the program is not
signed). It opens in Terminal.

**Linux.** Install Docker Engine first (<https://docs.docker.com/engine/install/>).
Then, in a terminal:

```sh
chmod +x DDR-Online-Setup-linux-x86_64
./DDR-Online-Setup-linux-x86_64
```

An Intel Mac, or anyone who prefers it, can run the same thing from a copy of
this repository with Python 3.8 or newer: `python3 setup.py`.

## The first run

The program puts the server's files in a folder named `DDR Online` in your
home folder, then asks:

1. **Who will play?** Just you on this computer, people on your home
   network, or friends over the internet. For friends over the internet it
   asks your router to open the ports (see [Router ports](#router-ports)).
2. **Where are your disc images?** Optional. Setup looks in Downloads,
   Documents, Desktop and PCSX2's game folders by itself. With the discs it
   draws the boards (the live standings pages) with the games' own art, and it
   can make the patched copy each game needs. It reads `.iso` files and zips of
   them. A `.7z` has to be unpacked first. Your files are never changed.
3. **What is the server called?** Up to 16 letters, numbers and spaces.
   Players see it in the game.

Then it starts the server and checks that every part answers. That takes a
minute or two.

On Windows and Mac the server runs straight on your computer. It keeps
running after you close the setup window, until you shut down or restart.
On Windows you can have it start each time you log in: run the setup again
and choose "Start with Windows". On Linux it runs in Docker and starts again
with Docker by itself.

Windows may ask whether DDR Online Setup may use the network. Tick "Private
networks" and click Allow, or other devices cannot reach the server.

## Patch your discs

All three games check with Sony's DNAS service before going online. DNAS is
gone, so each disc needs a small patch that skips the check. Setup offers to
do it at the end of the first run, and the menu has "Patch a disc for online
play". It writes a new file beside the original, named
`<the same name> [ONLINE].iso`, and leaves the original alone. Play the
`[ONLINE]` copy.

The patch wants a clean copy of the USA disc. [patching.md](patching.md) has
the details, and other ways to do it.

On a real PlayStation 2 with the original disc, use the cheat codes in
[cheats.md](cheats.md) instead.

## Point the game at the server

The games find their servers by name. Point these names at the address setup
shows you (it is in "Show what to tell players" in the menu too):

| name | game |
|---|---|
| `dx2gate01.konamionline.com` | Extreme 2, SuperNOVA |
| `game.ddr.konamionline.com` | SuperNOVA 2 |
| `dx2stun.konamionline.com` | Extreme 2 |
| `ddrsnstun.konamionline.com` | SuperNOVA, SuperNOVA 2 |
| `dx2web.konamionline.com` | SuperNOVA |
| `www.ddr.konamionline.com` | SuperNOVA 2 |
| `info.service.konamionline.com` | SuperNOVA, SuperNOVA 2 |

**PCSX2** (version 1.7 or 2.x): open Settings, then Network & HDD.

1. Turn on the network adapter and set the device type to Sockets.
2. Tick Intercept DHCP.
3. Set DNS 1 to Internal.
4. Under Hosts, add each name above with the server's address.

Use the address setup gives you even when PCSX2 runs on the same computer as
the server.

**A real PlayStation 2** asks a DNS server for these names. Set the DNS
server in the console's network settings to one you control that answers
them with the server's address: your router's own local DNS, Pi-hole or
dnsmasq all can.

Extreme 2 also needs a network configuration on the memory card and has no
way to make one. SuperNOVA includes Sony's tool, so set it up there first.

## Router ports

Only for friends over the internet. Setup asks your router to open these by
itself (UPnP). If the router says no, open them by hand in its settings
("Port forwarding", "Virtual server" or "NAT") to the computer running the
server:

| ports | type |
|---|---|
| 9573, 19570, 19573, 19580, 29570, 29573 | TCP |
| 3478-3479 | UDP |
| 19600-19615 | UDP |

Setup cannot test the internet side from inside your home. Ask a friend to
try.

If players reach you through another machine (a VPS, a tunnel, a proxy), tell
the server the address they use: Change settings, then "Players connect
through another machine". README.md explains why.

## The menu

Run the setup program again for the menu:

- **Start the server**, **Stop the server**.
- **Change settings**: who plays, the server name and the welcome message
  players see when they log in, an address for players behind another
  machine, Discord posts from the boards, and a new admin token for the
  OpenLobby panel.
- **Update**: fetches the newest release and restarts the server. Your
  settings, accounts and backups stay. If a newer setup program is needed, it
  says so, and changes nothing. When a newer release is out, the menu says so
  as it opens.
- **Make a backup**, **Restore a backup**: accounts, player files, results and
  the operator page's settings, as a zip in the `backups` folder. A backup
  can be made while the server runs. Keep a copy of the `.env` file as well:
  it holds the admin token and Discord settings.
- **Patch a disc for online play**.
- **Bake the board art again**, after adding a disc.
- **Show what the server is doing**: the server's log. Ctrl+C goes back.
- **Check that the server works**.
- **Open the router ports again**.
- **Connect to an OpenLobby admin panel** (below).
- **Show what to tell players**.
- **Start with Windows** (Windows only).

## The boards

Each game has a live standings page: <http://localhost:19581> (Extreme 2),
<http://localhost:19582> (SuperNOVA) and <http://localhost:19583>
(SuperNOVA 2). Others on your network use the server's address instead of
`localhost`. They show the games' art once setup has read your discs.

## OpenLobby admin panel

If you run an OpenLobby admin panel on the same computer, the server can show
up in it. The panel runs in Docker, so this part needs Docker (Docker Desktop
on Windows and Mac). Without Docker everything else works as before.

1. In the panel, open Settings, then Modules, and click "Pair with a setup
   program". It shows a code of 8 characters.
2. In DDR Online Setup choose "Connect to an OpenLobby admin panel" and type
   the code.

Setup starts a small helper container, `ddr-admin`, that lets the panel reach
the server. The server's admin port is never opened to your network.

### Updating from the panel

The panel lists DDR Online among its updates: which version runs, whether a
newer one is out, and what changed.

- **Windows and Mac**: the panel shows an **Update** button. The server
  fetches the newest release, puts it in place and starts again by itself,
  and the panel shows each step. Everyone playing is disconnected for a few
  seconds. If it fails, the old version keeps running and the panel says why.
- **Linux**: the server runs in Docker, so the panel's deployer does the
  update with `python3 setup.py --update --yes` in the server folder. Setup
  asks for that when it pairs; the panel's owner allows it once, under
  Settings, Modules. Without a deployer the panel says to run the setup
  program and choose Update.

You can run the same thing yourself: `--update --yes` updates and restarts
without asking anything, and `--check-update` only says whether a newer
version is out.

## When something goes wrong

- **"cannot bind" in the log**: another program uses one of the ports.
  Usually it is a second copy of the server. Stop it, or restart the computer.
- **The check fails**: choose "Show what the server is doing" and look at the
  last lines.
- **Everything setup did** is logged in `logs/setup.log` in the server folder,
  and the server's own output in `logs/server.log` (Windows and Mac).

The server folder holds:

| file or folder | what |
|---|---|
| `.env` | the settings setup wrote |
| `setup.json` | your three answers |
| `state/` | accounts, results, the baked board art (Windows and Mac; on Linux it is a Docker volume) |
| `backups/` | backups you made |
| `logs/` | what setup and the server wrote |
| `discs/` | disc images setup unpacked from zips |
