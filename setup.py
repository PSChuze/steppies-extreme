"""DDR Online Setup: python setup.py (or the "DDR Online Setup" program)

The first run asks three questions (who plays, where the disc images are, the
server's name), writes .env, bakes the boards' art from the discs, starts the
server and checks it. Later runs show a menu: start and stop, settings,
update, backups, patching a disc, logs, an OpenLobby admin panel.

How the server runs depends on the system. On Linux it is docker compose with
docker-compose.yml, as the README describes. On Windows and macOS it runs
without Docker, as server/serve.py with this program's own Python: Docker
Desktop hides the players' real addresses, and the server cannot work without
them (STUN, the match relay, the LAN-or-internet address choice). There,
Docker is only used for the optional OpenLobby admin panel.

Python 3.8+ when run as a script, standard library only.
"""
import argparse
import ast
import datetime
import importlib.util
import json
import os
import re
import runpy
import secrets
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile

from hostsetup import discs as disclib
from hostsetup import progress as proglib
from hostsetup import statefiles
from hostsetup import upnp

APP = "DDR Online Setup"
REPO = os.environ.get("DDR_SETUP_REPO", "PSChuze/steppies-extreme")
RELEASES = "https://github.com/%s/releases" % REPO
DOCKER_DOWNLOAD = "https://www.docker.com/products/docker-desktop/"
DOCKER_LINUX = "https://docs.docker.com/engine/install/"
PORT_HELP = "https://portforward.com/router.htm"
DEFAULT_FOLDER = "DDR Online"
DEFAULT_NAME = "DDR Online"
# --svr-label is 16 characters on the wire and the name goes there too.
NAME_MAX = 16
MOTD_MAX = 400          # --motd's field is 513 bytes; stay well inside it
FROZEN = getattr(sys, "frozen", False)

# The ports players reach, from README.md's table.
TCP_PORTS = (9573, 19573, 19570, 29573, 29570, 19580)
UDP_PORTS = (3478, 3479) + tuple(range(19600, 19616))
BOARD_PORTS = (19581, 19582, 19583)
# The names the games look up, from README.md: (name, games, what).
DNS_NAMES = (("dx2gate01.konamionline.com", "Extreme 2, SuperNOVA", "gate"),
             ("game.ddr.konamionline.com", "SuperNOVA 2", "gate"),
             ("dx2stun.konamionline.com", "Extreme 2", "STUN"),
             ("ddrsnstun.konamionline.com", "SuperNOVA, SuperNOVA 2", "STUN"),
             ("dx2web.konamionline.com", "SuperNOVA", "web"),
             ("www.ddr.konamionline.com", "SuperNOVA 2", "web"),
             ("info.service.konamionline.com", "SuperNOVA, SuperNOVA 2", "web"))
# What the smoke test tries: (what, kind, port).
CHECKS = (("Extreme 2 gate", "tcp", 9573), ("SuperNOVA gate", "tcp", 19573),
          ("SuperNOVA 2 gate", "tcp", 29573), ("web service", "http", 19580))
SMOKE_URL = "http://127.0.0.1:19580/ddrsn/oua/oua.txt"

# The OpenLobby admin panel: a shared Docker network, and the game's admin
# service on it under the alias "ddr". For DDR that service is a small relay
# container, server/adminrelay.py, in front of the gate's admin port.
OPENLOBBY_NETWORK = "openlobby"
GAME_KEY = "ddr"
GAME_TITLE = "Dance Dance Revolution"
ADMIN_PORT = 19591
ADMIN_URL = "http://%s:%d" % (GAME_KEY, ADMIN_PORT)
RELAY_NAME = "ddr-admin"
RELAY_IMAGE = "python:3.12-slim"
LABELS = (("org.openlobby.role", "game"), ("org.openlobby.game.key", GAME_KEY),
          ("org.openlobby.game.title", GAME_TITLE), ("org.openlobby.admin.url", ADMIN_URL))

# Files of ours in the server folder that an update must never replace.
KEEP = (".env", "setup.json", "state", "backups", "logs", "discs")
STARTUP_FILE = "DDR Online server.cmd"


def use_root(path):
    """Point every path at the server folder `path`."""
    global ROOT, ENV, STATE, BACKUPS, CHOICES, LOG, SERVER_LOG, MANIFEST, VERSION_FILE, COMPOSE, SERVER_DIR
    ROOT = os.path.abspath(path)
    ENV = os.path.join(ROOT, ".env")
    STATE = os.path.join(ROOT, "state")
    BACKUPS = os.path.join(ROOT, "backups")
    CHOICES = os.path.join(ROOT, "setup.json")
    LOG = os.path.join(ROOT, "logs", "setup.log")
    SERVER_LOG = os.path.join(ROOT, "logs", "server.log")
    MANIFEST = os.path.join(ROOT, ".setup-files")
    VERSION_FILE = os.path.join(ROOT, ".setup-version")
    COMPOSE = os.path.join(ROOT, "docker-compose.yml")
    SERVER_DIR = os.path.join(ROOT, "server")


use_root(os.path.dirname(os.path.abspath(__file__)))


def mode():
    """"docker" (Linux: docker compose) or "native" (Windows, macOS:
    server/serve.py). DDR_SETUP_MODE picks one by hand."""
    chosen = os.environ.get("DDR_SETUP_MODE", "").strip().lower()
    if chosen in ("docker", "native"):
        return chosen
    return "docker" if sys.platform.startswith("linux") else "native"


# --- terminal ----------------------------------------------------------------------------

def say(text=""):
    print(text, flush=True)


def ask(question, default=""):
    shown = " [%s]" % default if default else ""
    try:
        answer = input("%s%s: " % (question, shown)).strip()
    except EOFError:
        answer = ""
    return answer or default


def ask_yes(question, default=True):
    answer = ask(question + (" (Y/n)" if default else " (y/N)")).lower()
    return default if not answer else answer.startswith("y")


def ask_choice(question, options, default=1):
    """Number options from 1 and return the 1-based pick."""
    if question:
        say(question)
    for i, text in enumerate(options, 1):
        say("  %d. %s" % (i, text))
    while True:
        answer = ask("Type a number", str(default))
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return int(answer)
        say("  Type one of the numbers above.")


def ask_path(question):
    """A file or folder the host types or drags into the window; "" for none."""
    place = ask(question).strip().strip('"').strip("'")
    return os.path.abspath(os.path.expanduser(place)) if place else ""


def pause():
    ask("Press Enter to go on")


def heading(text):
    say()
    say(text)
    say("-" * len(text))


def log_file():
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    f = open(LOG, "a", encoding="utf-8")
    f.write("\n=== %s ===\n" % datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    return f


# --- the server's files ------------------------------------------------------------------

def find_root(args_folder=None):
    """The server folder: the one given, else the folder this runs from when it
    holds the server, else "DDR Online" in the home folder (made when missing)."""
    if args_folder:
        return os.path.abspath(args_folder)
    if not FROZEN:
        return os.path.dirname(os.path.abspath(__file__))
    for d in (os.path.dirname(sys.executable), os.getcwd()):
        if os.path.exists(os.path.join(d, "docker-compose.yml")):
            return d
    return os.path.join(os.path.expanduser("~"), DEFAULT_FOLDER)


def bundled(name):
    """A file packed into the setup program, or None."""
    base = getattr(sys, "_MEIPASS", None)
    path = os.path.join(base, name) if base else None
    return path if path and os.path.exists(path) else None


def unpack_server(archive, root, version=""):
    """Unpack a source zip of this repository into root, replacing the files
    the last one put there and leaving the host's own (.env, state, ...) alone.
    Returns the paths it wrote, relative to root."""
    with zipfile.ZipFile(archive) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
        # GitHub's and git archive's zips put everything in one top folder.
        tops = {n.split("/", 1)[0] for n in z.namelist()}
        strip = len(tops) == 1 and all("/" in n for n in names)
        old = set(read_manifest(root))
        written = []
        for name in names:
            rel = name.split("/", 1)[1] if strip else name
            if not rel or rel.split("/", 1)[0] in KEEP:
                continue
            target = os.path.normpath(os.path.join(root, rel))
            if not target.startswith(os.path.normpath(root) + os.sep):
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(name) as src, open(target + ".tmp", "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.replace(target + ".tmp", target)
            written.append(rel)
    for rel in old - set(written):
        try:
            os.remove(os.path.join(root, rel))
        except OSError:
            pass
    with open(os.path.join(root, ".setup-files"), "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(sorted(written)) + "\n")
    if version:
        with open(os.path.join(root, ".setup-version"), "w", encoding="utf-8") as f:
            f.write(version + "\n")
    return written


def read_manifest(root):
    try:
        with open(os.path.join(root, ".setup-files"), encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except OSError:
        return []


def installed_version():
    try:
        with open(VERSION_FILE, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def ensure_server_files():
    """Put the server's files in ROOT when they are not there yet."""
    if os.path.exists(COMPOSE):
        return True
    archive = bundled("server.zip")
    if not archive:
        say("The server's files are not in %s, and this setup program does not carry them." % ROOT)
        say("Download %s again from %s" % (APP, RELEASES))
        return False
    os.makedirs(ROOT, exist_ok=True)
    version = ""
    if bundled("server-version.txt"):
        with open(bundled("server-version.txt"), encoding="utf-8") as f:
            version = f.read().strip()
    unpack_server(archive, ROOT, version)
    say("The server's files are in %s" % ROOT)
    return True


def latest_release():
    """(tag, source zip URL) of the newest release, or None."""
    url = "https://api.github.com/repos/%s/releases/latest" % REPO
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/vnd.github+json"}),
                                    timeout=10) as r:
            info = json.load(r)
    except (OSError, ValueError):
        return None
    tag = info.get("tag_name")
    return (tag, "https://github.com/%s/archive/refs/tags/%s.zip" % (REPO, tag)) if tag else None


def server_imports(folder=None):
    """The top-level modules server/*.py and the tools setup runs import, less
    the server's own. packaging/build_setup.py packs these into the program."""
    folder = folder or ROOT
    files = [os.path.join(folder, "server", n) for n in sorted(os.listdir(os.path.join(folder, "server")))
             if n.endswith(".py")]
    files += [os.path.join(folder, "tools", n) for n in ("isopatch.py", "loginkey.py")]
    own = {os.path.splitext(os.path.basename(p))[0] for p in files}
    found = set()
    for path in files:
        try:
            with open(path, encoding="utf-8") as f:
                tree = ast.parse(f.read(), path)
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                found.add(node.module)
    return sorted(m for m in found if m.split(".")[0] not in own)


def missing_modules():
    """Modules the server's files need that this program does not carry. A
    newer server can import something the program it came with lacks."""
    out = []
    for name in server_imports():
        try:
            if importlib.util.find_spec(name) is None:
                out.append(name)
        except (ImportError, ValueError):
            out.append(name)
    return out


# --- running Python scripts ----------------------------------------------------------------

def script_cmd(path, *args):
    """The command that runs a Python script: this Python, or this program's
    --run-script mode when it is the frozen setup program."""
    if FROZEN:
        return [sys.executable, "--run-script", path] + list(args)
    return [sys.executable, "-u", path] + list(args)


def run_script(argv):
    """--run-script <script> args...: run a script with this program's Python,
    as `python script args` would. serve.py starts the server's services this
    way inside the frozen program, where there is no python to call."""
    if not argv:
        sys.exit("--run-script needs a script")
    path = os.path.abspath(argv[0])
    sys.argv = [path] + list(argv[1:])
    sys.path.insert(0, os.path.dirname(path))
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(line_buffering=True)
        except (AttributeError, ValueError):
            pass
    runpy.run_path(path, run_name="__main__")


def load_serve():
    """server/serve.py of the server folder, as a module."""
    spec = importlib.util.spec_from_file_location("ddr_serve", os.path.join(SERVER_DIR, "serve.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- docker ------------------------------------------------------------------------------

def run(cmd, check=True, capture=False, **kw):
    """Run a command in the server folder; its output goes to the terminal unless captured."""
    if capture:
        kw.update(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
    result = subprocess.run(cmd, cwd=ROOT if os.path.isdir(ROOT) else None, **kw)
    if check and result.returncode != 0:
        raise SystemExit("Failed (exit %d): %s" % (result.returncode, " ".join(cmd)))
    return result


def compose(*args, **kw):
    return run(["docker", "compose"] + list(args), **kw)


def add_docker_to_path():
    """Docker installed while this window was open is not on its PATH yet."""
    places = [os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Docker", "Docker", "resources",
                           "bin"),
              "/usr/local/bin", "/Applications/Docker.app/Contents/Resources/bin",
              os.path.join(os.path.expanduser("~"), ".docker", "bin")]
    path = os.environ.get("PATH", "").split(os.pathsep)
    for p in places:
        if os.path.isdir(p) and p not in path:
            path.append(p)
    os.environ["PATH"] = os.pathsep.join(path)


def docker_state():
    """"ok", "missing", "stopped", "denied" (Linux user not allowed) or "old"."""
    add_docker_to_path()
    if not shutil.which("docker"):
        return "missing"
    try:
        info = run(["docker", "info"], check=False, capture=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError):
        return "stopped"
    if info.returncode != 0:
        return "denied" if "permission denied" in (info.stdout or "").lower() else "stopped"
    if run(["docker", "compose", "version"], check=False, capture=True).returncode != 0:
        return "old"
    return "ok"


def start_docker_desktop():
    """Ask Docker Desktop to start; True when there was one to start."""
    if os.name == "nt":
        exe = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Docker", "Docker",
                           "Docker Desktop.exe")
        if os.path.exists(exe):
            subprocess.Popen([exe], close_fds=True)
            return True
    elif sys.platform == "darwin" and os.path.isdir("/Applications/Docker.app"):
        return subprocess.run(["open", "-a", "Docker"]).returncode == 0
    return False


def wait_for_docker(wait=True):
    """Return once Docker works (Linux, where the server runs in it). Explains
    what is missing and waits for the host to fix it (or returns False at once
    with wait=False)."""
    started = False
    while True:
        state = docker_state()
        if state == "ok":
            return True
        say()
        if state == "missing":
            if sys.platform.startswith("linux"):
                say("Docker is not installed. Install Docker Engine: %s" % DOCKER_LINUX)
            else:
                say("Docker Desktop is not installed. Download it here, install it and start it:")
                say("  %s" % DOCKER_DOWNLOAD)
        elif state == "stopped" and not started and wait and start_docker_desktop():
            started = True
            say("Starting Docker Desktop. This can take a minute or two.")
            for _ in range(60):
                time.sleep(3)
                if docker_state() == "ok":
                    say("Docker Desktop is running.")
                    return True
            say("Docker Desktop has not started yet. If it shows a message (terms to accept,")
            say("an update to install), answer it.")
        elif state == "stopped":
            if sys.platform.startswith("linux"):
                say("Docker is installed but not running. Start it with: sudo systemctl start docker")
            else:
                say("Docker Desktop is installed but not running. Open it and wait until it says")
                say("it is running.")
        elif state == "denied":
            say("Your user may not use Docker yet. Run this, then log out and back in:")
            say("  sudo usermod -aG docker $USER")
        else:
            say("This Docker is too old (it has no 'docker compose'). Update it: %s" % DOCKER_LINUX)
        if not wait:
            return False
        ask("Press Enter to check again (or close this window to stop)")


# --- settings ----------------------------------------------------------------------------

ENV_HEADER = ("# Settings for the DDR Online server, read by docker compose and by\n"
              "# server/serve.py. Written by setup.py; run it again to change them.\n")


def read_env(path=None):
    path = path or ENV
    values = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = re.match(r"\s*([A-Z_][A-Z0-9_]*)=(.*)$", line.rstrip("\n"))
                if m:
                    values[m.group(1)] = m.group(2).strip()
    return values


def write_env(values, path=None):
    """Write values into the file's lines (a commented-out `#KEY=` line is switched
    on, a value of None comments a line out); new keys go at the end. Comments
    stay as they are."""
    path = path or ENV
    lines = ENV_HEADER.splitlines()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    left = dict(values)
    out = []
    for line in lines:
        m = re.match(r"(#?)([A-Z_][A-Z0-9_]*)=", line)
        if m and m.group(2) in left:
            value = left.pop(m.group(2))
            out.append(("#" + line.lstrip("#")) if value is None else "%s=%s" % (m.group(2), value))
            continue
        out.append(line)
    for key, value in left.items():
        if value is not None:
            out.append("%s=%s" % (key, value))
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    os.replace(tmp, path)


def read_choices():
    try:
        with open(CHOICES, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def write_choices(choices):
    os.makedirs(os.path.dirname(CHOICES), exist_ok=True)
    with open(CHOICES, "w", encoding="utf-8", newline="\n") as f:
        json.dump(choices, f, indent=1)
        f.write("\n")


def lan_address():
    """This machine's address on the local network (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return ""


def public_address():
    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=4) as r:
            ip = r.read().decode().strip()
        socket.inet_aton(ip)
        return ip
    except (OSError, ValueError):
        return ""


def plain_text(text):
    """Printable ASCII, which is what the games can show, less the characters
    a .env value cannot carry as is: compose expands $ and starts a comment at
    #, and quotes would be taken off."""
    return "".join(c for c in text if 32 <= ord(c) < 127 and c not in "$#\"'`\\").strip()


def clean_name(text):
    """The server name as the games can show it, at most NAME_MAX characters.
    "" when nothing is left."""
    return plain_text(text)[:NAME_MAX].strip()


def first_settings(name, env):
    """The .env values for a first run. Values already there stay."""
    changes = {"DDR_SERVER_NAME": name}
    if not env.get("DDR_MOTD"):
        changes["DDR_MOTD"] = "Welcome to %s!" % name
    if not env.get("DDR_ADMIN_TOKEN"):
        changes["DDR_ADMIN_TOKEN"] = secrets.token_urlsafe(24)
    return changes


def ports_to_open():
    """[(port, protocol)] players must reach, in order."""
    return [(p, "TCP") for p in TCP_PORTS] + [(p, "UDP") for p in UDP_PORTS]


def port_ranges(ports):
    """[(first, last)] runs of consecutive ports, for a short table."""
    out = []
    for p in sorted(set(ports)):
        if out and p == out[-1][1] + 1:
            out[-1] = (out[-1][0], p)
        else:
            out.append((p, p))
    return out


def player_address(choices):
    """The address players point the game's names at."""
    return choices.get("address") or lan_address() or "this computer's address"


# --- the three questions -----------------------------------------------------------------

WHO = ("me", "home", "internet")


def ask_who(current="home"):
    heading("Question 1 of 3: Who will play on this server?")
    pick = ask_choice("", ["Just me, on this computer (PCSX2)",
                           "People on my home network",
                           "Friends over the internet"], WHO.index(current) + 1 if current in WHO else 2)
    return WHO[pick - 1]


def ask_address(who, current=""):
    """The address players point the game's names at: this machine's for home,
    the internet one otherwise. The server itself needs neither: it works out
    per connection what to tell each console."""
    if who != "internet":
        lan = lan_address()
        if lan:
            say("Players point the game's names at this computer's address: %s" % lan)
            return lan
        say("Setup could not find this computer's address on your network.")
        default = current
    else:
        public = public_address()
        default = current if current and not upnp.is_private(current) else public
        if public:
            say("Your internet address is %s." % public)
        if default:
            say("Friends point the game's names at this address. If you have a name for it (like")
            say("myserver.example.net), type the name. Otherwise press Enter.")
        else:
            say("Setup could not find your internet address. Type it, or a name that leads to it.")
    while True:
        address = ask("Address", default)
        if address:
            return address


def find_discs(extra=()):
    """Look in the usual places and offer what is there. Optional: Enter
    skips. Returns {serial: Disc}."""
    heading("Question 2 of 3: Where are your DDR disc images?")
    say("This is optional. With them, setup draws the boards (the standings pages) with")
    say("the game's own art, and can make the patched copy each game needs to go online.")
    say("Setup reads .iso files and zips of them. It never changes them.")
    places = [ROOT] + ([os.path.dirname(sys.executable)] if FROZEN else []) + list(extra)
    say("Looking in Downloads, Documents, Desktop and PCSX2's game folders...")
    sevenzips = []
    found = disclib.search(disclib.likely_folders(places), sevenzips=sevenzips)
    chosen = disclib.pick(found)
    if chosen:
        show_discs(chosen)
        if ask_yes("Use these?"):
            return chosen
        chosen = {}
    tell_7z(sevenzips)
    while True:
        say("Type the folder (or file) where the disc images are, or drag one into this")
        say("window and press Enter. Press Enter alone to skip this.")
        place = ask_path("Folder or file")
        if not place:
            return chosen
        if os.path.isfile(place):
            if place.lower().endswith(disclib.SEVENZIP_EXT):
                tell_7z([place])
                continue
            new = disclib.identify(place)
        elif os.path.isdir(place):
            sevenzips = []
            new = disclib.search([place], depth=4, sevenzips=sevenzips)
            tell_7z(sevenzips)
        else:
            say("  There is no folder or file at %s" % place)
            continue
        if not new:
            say("  No DDR disc image there (Extreme 2, SuperNOVA or SuperNOVA 2, USA).")
            continue
        chosen.update(disclib.pick(new + list(chosen.values())))
        show_discs(chosen)
        if len(chosen) == len(disclib.GAMES) or not ask_yes("Add more?", False):
            return chosen


def tell_7z(paths):
    if paths:
        say("These look like DDR discs packed as .7z, which setup cannot open. Unpack them")
        say("(7-Zip, or your system's archive tool) and point setup at the .iso inside:")
        for p in paths[:5]:
            say("  %s" % p)


def show_discs(chosen):
    say("Found:")
    for serial in disclib.GAMES:
        d = chosen.get(serial)
        if d:
            say("  %s: %s" % (d.game, d.shown()))


def ask_name(current=DEFAULT_NAME):
    heading("Question 3 of 3: Give your server a name")
    say("Players see it in the game's server list. Up to %d letters, numbers and spaces." % NAME_MAX)
    while True:
        typed = ask("Server name", current)
        name = clean_name(typed)
        if name and name == typed.strip():
            return name
        if name:
            say("  That would show as \"%s\"." % name)
            if ask_yes("  Use that?"):
                return name
        else:
            say("  Use plain letters and numbers.")


def disc_records(chosen):
    """The chosen discs as setup.json keeps them."""
    return [{"path": d.path, "serial": d.serial, "member": d.member} for d in chosen.values()]


def chosen_discs(choices):
    return {item["serial"]: disclib.Disc(item["path"], item["serial"], item.get("member"))
            for item in choices.get("discs", []) if os.path.exists(item.get("path", ""))}


# --- discs: unpacking, board art, login key, patching -------------------------------------

def unzip_disc(disc, progress):
    """Unpack a disc from its zip into the discs folder; returns the new file's path."""
    dest_dir = os.path.join(ROOT, "discs")
    os.makedirs(dest_dir, exist_ok=True)
    target = os.path.join(dest_dir, os.path.basename(disc.member))
    with zipfile.ZipFile(disc.path) as z:
        info = z.getinfo(disc.member)
        if os.path.exists(target) and os.path.getsize(target) == info.file_size:
            return target
        if shutil.disk_usage(dest_dir).free < info.file_size + (1 << 30):
            raise SystemExit("Not enough free disk space to unpack %s (it needs %d GB)."
                             % (os.path.basename(disc.path), info.file_size // (1 << 30) + 1))
        progress.begin("Unpacking %s" % os.path.basename(disc.path), "a few minutes")
        done = 0
        with z.open(info) as src, open(target + ".tmp", "wb") as dst:
            while True:
                chunk = src.read(8 << 20)
                if not chunk:
                    break
                dst.write(chunk)
                done += len(chunk)
                progress.set("%d%%" % (done * 100 // max(1, info.file_size)))
    os.replace(target + ".tmp", target)
    progress.end()
    return target


def disc_file(disc, progress):
    return unzip_disc(disc, progress) if disc.member else disc.path


def disc_mounts(files):
    """(docker -v options, the files' paths inside the container): each disc's
    folder is shared read-only."""
    folders, volumes, inside = [], [], []
    for path in files:
        folder = os.path.dirname(os.path.abspath(path))
        if folder not in folders:
            folders.append(folder)
            volumes += ["-v", "%s:/discs/%d:ro" % (folder, len(folders))]
        inside.append("/discs/%d/%s" % (folders.index(folder) + 1, os.path.basename(path)))
    return volumes, inside


def in_container(service, volumes, command):
    """docker compose run of a one-off command in a service's container: it
    has the state volume at /state and the server at /app."""
    return ["docker", "compose", "run", "--rm", "--no-deps", "-T"] + volumes + [service] + command


def bake_command(files):
    if mode() == "native":
        return script_cmd(os.path.join(SERVER_DIR, "boardart.py"), *files) + \
            ["--out", os.path.join(STATE, "boardart")]
    volumes, inside = disc_mounts(files)
    return in_container("boards", volumes, ["python3", "boardart.py"] + inside)


def loginkey_command(path):
    script = os.path.join(ROOT, "tools", "loginkey.py")
    if mode() == "native":
        return script_cmd(script, path, os.path.join(STATE, "loginkey.bin"))
    volumes, inside = disc_mounts([path])
    return in_container("gate", volumes + ["-v", "%s:/repo:ro" % ROOT],
                        ["python3", "/repo/tools/loginkey.py", inside[0], "/state/loginkey.bin"])


def failed(what, tail):
    say()
    say(what)
    say("The last lines it wrote:")
    for line in tail[-12:]:
        say("  " + line)
    say("Everything it wrote is in %s" % LOG)


def use_discs(chosen, progress, log):
    """Bake the board art and read the login key from the chosen discs.
    Neither is needed to play, so a failure is reported and setup goes on."""
    if not chosen:
        return
    os.makedirs(STATE, exist_ok=True)
    try:
        files = [disc_file(d, progress) for d in chosen.values()]
    except (SystemExit, OSError, zipfile.BadZipFile) as e:
        progress.end(False)
        say(str(e))
        return
    env = dict(os.environ, DDR_STATE_DIR=STATE, PYINSTALLER_RESET_ENVIRONMENT="1")
    progress.begin("Baking the board art", "a few minutes")
    code, tail = proglib.run_logged(bake_command(files), log, cwd=ROOT, env=env, progress=progress)
    progress.end(code == 0)
    if code != 0:
        failed("Baking the board art did not work. The boards show without it.", tail)
    if not os.path.exists(os.path.join(ROOT, "tools", "loginkey.py")):
        return
    progress.begin("Reading the login key", "under a minute")
    for path in files:
        code, tail = proglib.run_logged(loginkey_command(path), log, cwd=ROOT, env=env, progress=progress)
        if code == 0:
            break
    progress.end(code == 0)
    if code != 0:
        failed("Reading the login key from your discs did not work.", tail)


def patched_name(disc):
    """Where the patched copy goes: beside the original (or beside its zip),
    "<name> [ONLINE].iso"."""
    stem = os.path.splitext(os.path.basename(disc.member or disc.path))[0]
    return os.path.join(os.path.dirname(disc.path), "%s [ONLINE].iso" % stem)


def patch_one(disc, progress, log):
    """Write the patched copy of one disc. True when it worked."""
    out = patched_name(disc)
    if os.path.normcase(os.path.abspath(out)) == os.path.normcase(os.path.abspath(disc.path)):
        say("  %s is already a patched copy." % disc.path)
        return False
    if os.path.exists(out):
        say("  %s is already there." % out)
        if not ask_yes("  Make it again?", False):
            return True
    try:
        src = disc_file(disc, progress)
        free = shutil.disk_usage(os.path.dirname(out)).free
        if free < os.path.getsize(src) + (256 << 20):
            say("  Not enough free disk space beside %s for the copy." % disc.path)
            return False
    except (SystemExit, OSError, zipfile.BadZipFile) as e:
        progress.end(False)
        say("  %s" % e)
        return False
    progress.begin("Patching %s" % disc.game, "a minute or two")
    code, tail = proglib.run_logged(script_cmd(os.path.join(ROOT, "tools", "isopatch.py"), src, out),
                                    log, cwd=ROOT, progress=progress,
                                    env=dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1"))
    progress.end(code == 0)
    if code != 0:
        failed("Patching %s did not work. Is it a clean copy of the USA disc?" % disc.game, tail)
        return False
    say("  Play this one online: %s" % out)
    return True


def patch_discs(chosen):
    """Patch the clean discs among `chosen`."""
    clean = [d for d in chosen.values() if not d.online]
    if not clean:
        say("Setup knows no clean disc image to patch.")
        return
    progress = proglib.Progress()
    with log_file() as log:
        for disc in clean:
            patch_one(disc, progress, log)
    say("The original images are untouched.")


# --- running the server --------------------------------------------------------------------

def server_running():
    if mode() == "native":
        try:
            return bool(load_serve().running_pid(STATE))
        except (OSError, ImportError, AttributeError):
            return False
    out = compose("ps", "--status", "running", "--services", check=False, capture=True).stdout or ""
    return "gate" in out.split()


def rotate_log(path, limit=5 << 20):
    try:
        if os.path.getsize(path) > limit:
            os.replace(path, path + ".1")
    except OSError:
        pass


def start_native():
    """Start server/serve.py in the background, its output going to
    logs/server.log. It keeps running when this window closes."""
    os.makedirs(STATE, exist_ok=True)
    os.makedirs(os.path.dirname(SERVER_LOG), exist_ok=True)
    rotate_log(SERVER_LOG)
    cmd = script_cmd(os.path.join(SERVER_DIR, "serve.py"), "--state", STATE, "--env-file", ENV)
    env = dict(os.environ, PYINSTALLER_RESET_ENVIRONMENT="1", PYTHONIOENCODING="utf-8")
    log = open(SERVER_LOG, "ab")
    try:
        if os.name == "nt":
            # No console window, its own process group, and out of any job this
            # window belongs to, so closing the window does not stop it.
            flags = 0x08000000 | 0x00000200      # CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
            try:
                subprocess.Popen(cmd, cwd=SERVER_DIR, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, close_fds=True,
                                 creationflags=flags | 0x01000000)     # CREATE_BREAKAWAY_FROM_JOB
            except OSError:
                subprocess.Popen(cmd, cwd=SERVER_DIR, env=env, stdin=subprocess.DEVNULL, stdout=log,
                                 stderr=subprocess.STDOUT, close_fds=True, creationflags=flags)
        else:
            subprocess.Popen(cmd, cwd=SERVER_DIR, env=env, stdin=subprocess.DEVNULL, stdout=log,
                             stderr=subprocess.STDOUT, close_fds=True, start_new_session=True)
    finally:
        log.close()


def stop_native():
    serve = load_serve()
    pid = serve.running_pid(STATE)
    if not pid:
        return
    with open(os.path.join(STATE, serve.STOP_FILE), "w", encoding="ascii") as f:
        f.write("stop\n")
    for _ in range(40):
        if not serve.pid_alive(pid):
            return
        time.sleep(0.5)
    serve.kill_tree(pid)


def tail_lines(path, n=20):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()[-n:]
    except OSError:
        return []


def smoke_results(host="127.0.0.1"):
    """[(what, ok)] for each check."""
    out = []
    for what, kind, port in CHECKS:
        if kind == "tcp":
            out.append((what, can_connect(host, port)))
        else:
            try:
                with urllib.request.urlopen(SMOKE_URL.replace("127.0.0.1", host), timeout=3) as r:
                    out.append((what, r.status == 200))
            except (OSError, ValueError):
                out.append((what, False))
    return out


def can_connect(host, port, timeout=3.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_ready(timeout=60):
    """Wait until every check passes. False (and the server's last lines) when
    they do not in time."""
    deadline = time.monotonic() + timeout
    results = []
    while time.monotonic() < deadline:
        results = smoke_results()
        if all(ok for _, ok in results):
            return True
        if mode() == "native" and time.monotonic() > deadline - timeout + 10 and not server_running():
            break
        time.sleep(2)
    say("The server did not answer as it should:")
    for what, ok in results:
        say("  %s: %s" % (what, "answers" if ok else "no answer"))
    say("Its last lines:")
    if mode() == "native":
        for line in tail_lines(SERVER_LOG):
            say("  " + line)
    else:
        say(compose("logs", "--tail", "20", check=False, capture=True).stdout)
    return False


def smoke():
    """The menu's check: one line per service."""
    results = smoke_results()
    for what, ok in results:
        say("  %s: %s" % (what, "answers" if ok else "no answer"))
    ok = all(ok for _, ok in results)
    say("The server answers as it should." if ok else "Something is not answering. Look at the logs.")
    return ok


def start_server(quiet=False):
    """Start everything and check it. True when it answers."""
    env, choices = read_env(), read_choices()
    if choices.get("who") == "internet":
        open_router_ports(quiet=True)
    if not quiet:
        say("Starting the server...")
    if mode() == "native":
        if FROZEN:
            missing = missing_modules()
            if missing:
                say("This %s is older than the server's files (they need %s)." % (APP, ", ".join(missing)))
                say("Download the new one from %s" % RELEASES)
                return False
        if not server_running():
            start_native()
        if openlobby_wanted(env):
            ensure_relay(quiet=True)
    else:
        if uses_openlobby_profile(env):
            ensure_network(quiet=True)
        compose("up", "-d", "--remove-orphans")
    ok = wait_ready()
    if ok and not quiet:
        say("The server is running and answers on every port it should.")
    return ok


def stop_server():
    if mode() == "native":
        stop_native()
    else:
        compose("stop")


def uses_openlobby_profile(env):
    return OPENLOBBY_NETWORK in [p.strip() for p in env.get("COMPOSE_PROFILES", "").split(",")]


def restart_server():
    if mode() == "native":
        stop_native()
        return start_server()
    if uses_openlobby_profile(read_env()):
        ensure_network(quiet=True)
    compose("up", "-d", "--force-recreate", "--remove-orphans")
    return wait_ready()


# --- router ------------------------------------------------------------------------------

def open_router_ports(quiet=False):
    """Ask the router to forward the ports. Returns (all open?, the router's
    internet address or "")."""
    lan = lan_address()
    ports = ports_to_open()
    if not quiet:
        say("Asking your router to open the ports...")
    gateway = upnp.find_gateway(lan) if lan else None
    if not gateway:
        if not quiet:
            say("Your router did not answer (its UPnP setting may be off). The ports need opening by hand.")
        return False, ""
    results = upnp.open_ports(gateway, ports, lan)
    try:
        external = gateway.external_ip()
    except upnp.UpnpError:
        external = ""
    good = [p for p, r in results.items() if r in ("opened", "already")]
    bad = {p: r for p, r in results.items() if p not in good}
    if not quiet or bad:
        if not bad:
            say("Your router opened the ports for this computer (%s)." % lan)
        else:
            say("Your router opened %d of %d ports. Not opened:" % (len(good), len(ports)))
            for (port, proto), r in bad.items():
                say("  %d %s: %s" % (port, proto, "another device uses it" if r == "taken" else r))
    if external and upnp.is_private(external):
        say()
        say("Note: your router has no internet address of its own (%s). Your internet provider" % external)
        say("probably shares one address between customers, or there is a second router in front")
        say("of this one. Friends outside your home will likely not reach the server. Ask your")
        say("provider for a public IP address.")
    return not bad, external


def show_port_help(router=""):
    lan = lan_address() or "this computer"
    heading("Open these ports on your router")
    say("Your router needs to send these ports to this computer (%s)." % lan)
    say("Open the router's settings page (usually http://%s, or the address printed on" % (router or "192.168.1.1"))
    say('the router) and look for "Port forwarding" (or "Virtual server", or "NAT").')
    say()
    say("  Ports            Type   To")
    for proto, ports in (("TCP", TCP_PORTS), ("UDP", UDP_PORTS)):
        for first, last in port_ranges(ports):
            shown = str(first) if first == last else "%d-%d" % (first, last)
            say("  %-16s %-6s %s" % (shown, proto, lan))
    say()
    say("Steps for many router models: %s" % PORT_HELP)


# --- OpenLobby admin panel -----------------------------------------------------------------

def docker_ok():
    """True when Docker can be used right now. Never waits and never asks."""
    try:
        return docker_state() == "ok"
    except OSError:
        return False


def find_panel():
    """The URL of the OpenLobby panel container on this machine, or ""."""
    out = run(["docker", "ps", "--filter", "label=org.openlobby.role=panel",
               "--format", '{{.Label "org.openlobby.panel.url"}}'], check=False, capture=True).stdout or ""
    for line in out.splitlines():
        if line.strip().startswith("http"):
            return line.strip().rstrip("/")
    return ""


def openlobby_wanted(env):
    """Run the admin relay when paired, or when a panel is there to pair with.
    Without Docker there is neither, and nothing is said about it."""
    if not docker_ok():
        return False
    return bool(env.get("OPENLOBBY_PAIRING")) or bool(find_panel())


def ensure_network(quiet=False):
    if run(["docker", "network", "inspect", OPENLOBBY_NETWORK], check=False, capture=True).returncode != 0:
        result = run(["docker", "network", "create", OPENLOBBY_NETWORK], check=False, capture=True)
        if result.returncode != 0 and not quiet:
            say("Could not make the Docker network %s: %s" % (OPENLOBBY_NETWORK, (result.stdout or "").strip()))
        return result.returncode == 0
    return True


def relay_command():
    """docker run for the admin relay (native mode): on the openlobby network
    as "ddr", passing the panel's requests to the gate's admin port on this
    machine's loopback, which Docker Desktop reaches as host.docker.internal."""
    cmd = ["docker", "run", "-d", "--name", RELAY_NAME, "--restart", "unless-stopped",
           "--network", OPENLOBBY_NETWORK, "--network-alias", GAME_KEY]
    for key, value in LABELS:
        cmd += ["--label", "%s=%s" % (key, value)]
    cmd += ["-v", "%s:/app:ro" % SERVER_DIR, RELAY_IMAGE,
            "python3", "/app/adminrelay.py", "--listen", "0.0.0.0:%d" % ADMIN_PORT,
            "--to", "host.docker.internal:%d" % ADMIN_PORT]
    return cmd


def ensure_relay(quiet=False):
    """Make sure the admin relay runs: on Linux it is compose's admin service,
    elsewhere a container of its own. True when it runs."""
    if not ensure_network(quiet):
        return False
    if mode() == "docker":
        # docker-compose.yml's admin service sits in the "openlobby" profile;
        # COMPOSE_PROFILES in .env keeps it on for every later compose command.
        profiles = [p for p in read_env().get("COMPOSE_PROFILES", "").split(",") if p.strip()]
        if OPENLOBBY_NETWORK not in profiles:
            write_env({"COMPOSE_PROFILES": ",".join(profiles + [OPENLOBBY_NETWORK])})
        return compose("up", "-d", "admin", check=False, capture=quiet).returncode == 0
    have = run(["docker", "inspect", "-f", "{{.State.Running}} {{range .Mounts}}{{.Source}}{{end}}", RELAY_NAME],
               check=False, capture=True)
    state = (have.stdout or "").strip()
    if have.returncode == 0 and state.startswith("true") and os.path.normcase(SERVER_DIR) in os.path.normcase(state):
        return True
    run(["docker", "rm", "-f", RELAY_NAME], check=False, capture=True)
    result = run(relay_command(), check=False, capture=True)
    if result.returncode != 0 and not quiet:
        say("Could not start the admin relay: %s" % (result.stdout or "").strip())
    return result.returncode == 0


def post_json(url, body, timeout=10):
    """(HTTP status, the answer as a dict). Status 0 when nothing answered."""
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (OSError, ValueError) as e:
        return 0, {"error": str(e)}
    try:
        answer = json.loads(raw.decode("utf-8") or "{}")
    except ValueError:
        answer = {}
    return status, answer if isinstance(answer, dict) else {}


def pair(panel, code, token):
    """Pair with the panel. (pairing id, "") when it worked, else ("", why)."""
    status, answer = post_json(panel + "/api/pair", {"code": code, "key": GAME_KEY, "title": GAME_TITLE,
                                                     "url": ADMIN_URL, "token": token})
    if status == 200 and answer.get("ok") and answer.get("pairing"):
        return str(answer["pairing"]), ""
    if status == 0:
        return "", "the panel at %s did not answer (%s)" % (panel, answer.get("error", ""))
    return "", answer.get("error") or "the panel answered HTTP %d" % status


def pair_update(panel, pairing, token):
    """Tell the panel the new token. "" when it worked, else why not."""
    status, answer = post_json(panel + "/api/pair/update", {"key": GAME_KEY, "pairing": pairing,
                                                            "token": token, "url": ADMIN_URL})
    if 200 <= status < 300:
        return ""
    if status == 0:
        return "the panel at %s did not answer" % panel
    return answer.get("error") or "the panel answered HTTP %d" % status


def connect_panel():
    """Menu item: pair with an OpenLobby admin panel on this machine."""
    if not docker_ok():
        say("The OpenLobby admin panel runs in Docker, and Docker is not running here.")
        say("Start Docker (or install it: %s), then try again." % (DOCKER_LINUX if mode() == "docker"
                                                                 else DOCKER_DOWNLOAD))
        return
    panel = find_panel()
    if not panel:
        say("No OpenLobby admin panel is running on this computer. Start it, then try again.")
        return
    env = read_env()
    if not env.get("DDR_ADMIN_TOKEN"):
        write_env({"DDR_ADMIN_TOKEN": secrets.token_urlsafe(24)})
        env = read_env()
        if server_running():
            restart_server()
    if not ensure_relay():
        return
    say("Found the admin panel at %s." % panel)
    say('In the panel, open Settings, then Modules, and click "Pair with a setup program".')
    say("It shows a code of 8 characters.")
    code = re.sub(r"[\s-]", "", ask("Type the code (Enter to cancel)"))
    if not code:
        return
    pairing, why = pair(panel, code, env["DDR_ADMIN_TOKEN"])
    if not pairing:
        say("Pairing did not work: %s" % why)
        return
    write_env({"OPENLOBBY_PAIRING": pairing})
    say("Paired. Dance Dance Revolution now shows in the admin panel.")


def new_admin_token(env, choices):
    """Settings item: a new admin token, passed on to a paired panel."""
    say("The admin token lets the OpenLobby panel manage this server. Make a new one if the")
    say("old one may have leaked.")
    if not ask_yes("Make a new one?", False):
        return False
    token = secrets.token_urlsafe(24)
    write_env({"DDR_ADMIN_TOKEN": token})
    pairing = env.get("OPENLOBBY_PAIRING")
    if pairing and docker_ok():
        panel = find_panel()
        why = pair_update(panel, pairing, token) if panel else "the panel is not running"
        say("The panel has the new token." if not why else
            "Could not tell the panel the new token (%s). Pair again from the menu." % why)
    return True


# --- start with Windows ----------------------------------------------------------------------

def startup_folder():
    return os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Microsoft", "Windows",
                        "Start Menu", "Programs", "Startup")


def startup_command():
    """The command that starts the server at logon, without a menu."""
    if FROZEN:
        cmd = [sys.executable]
    else:
        cmd = [sys.executable, os.path.abspath(__file__)]
    return cmd + ["--folder", ROOT, "--start"]


def startup_script():
    """The Startup folder file. A .cmd there runs at every logon of this user
    and needs no administrator rights, unlike a logon Scheduled Task."""
    line = " ".join('"%s"' % part for part in startup_command())
    return ("@echo off\r\n"
            "chcp 65001 >nul\r\n"
            "rem Written by %s: starts the DDR Online server when you log in.\r\n"
            "rem Delete this file (or use the setup menu) to stop that.\r\n"
            "start \"DDR Online\" /min %s\r\n" % (APP, line))


def autostart_on():
    return os.path.exists(os.path.join(startup_folder(), STARTUP_FILE))


def toggle_autostart():
    path = os.path.join(startup_folder(), STARTUP_FILE)
    if autostart_on():
        if ask_yes("The server starts with Windows. Stop that?", False):
            os.remove(path)
            say("It no longer starts with Windows.")
        return
    say("The server will start each time you log in to Windows, in a small window that")
    say("closes by itself.")
    if FROZEN:
        say("Keep %s where it is now: the start-up entry runs it from there." % os.path.basename(sys.executable))
    if ask_yes("Start it with Windows?"):
        os.makedirs(startup_folder(), exist_ok=True)
        # UTF-8, with chcp 65001 at its top, so a folder name outside ASCII survives.
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(startup_script())
        say("Done. It starts the next time you log in.")


# --- finishing ---------------------------------------------------------------------------

def finish(choices):
    address = player_address(choices)
    say()
    say("=" * 72)
    say("Your server is running.")
    say()
    say("The games find the server by name. Point these names at %s:" % address)
    for name, games, _ in DNS_NAMES:
        say("  %-32s %s" % (name, games))
    say()
    say("PCSX2: open Settings, then Network & HDD. Turn on the network adapter, set the")
    say("device type to Sockets, tick Intercept DHCP and set DNS 1 to Internal. Then add")
    say("each name above to the Hosts list with the address %s." % address)
    say()
    say("A PlayStation 2: set its DNS server to one you control that answers these names")
    say("with %s (your router's own DNS settings, Pi-hole or dnsmasq can)." % address)
    say()
    say("Each game also needs a patched disc to get past the old DNAS check. Setup can")
    say('make one from your disc image: choose "Patch a disc" in the menu. On a real')
    say("console with the original disc, see docs/cheats.md instead.")
    if choices.get("who") == "internet":
        say()
        if choices.get("router") == "open":
            say("Your router has the ports open.")
        else:
            say("Friends can join once the ports above are open on your router.")
        say("Setup cannot test the internet side from inside your home. Ask a friend to try.")
    say()
    say("The boards (live standings) are at http://%s:19581 (Extreme 2), :19582" % address)
    say("(SuperNOVA) and :19583 (SuperNOVA 2).")
    say()
    if mode() == "native":
        say("The server keeps running when you close this window, until you shut down or")
        say("restart the computer.")
    else:
        say("The server keeps running when you close this window, and starts again with Docker.")
    say("Run %s again to stop it, change settings or make backups." % APP)
    say("The full guide is docs/setup.md in %s" % ROOT)
    say("=" * 72)


def first_run(dry_run=False):
    say(APP)
    say("=" * len(APP))
    say("This sets up a server for Dance Dance Revolution Extreme 2, SuperNOVA and SuperNOVA 2")
    say("on this computer. Answer three questions and setup does the rest in a few minutes.")
    choices = read_choices()
    env = read_env()
    who = ask_who(choices.get("who", "home"))
    address = ask_address(who, choices.get("address", ""))
    chosen = find_discs()
    name = ask_name(env.get("DDR_SERVER_NAME") or DEFAULT_NAME)
    changes = first_settings(name, env)
    choices.update(who=who, address=address, name=name, discs=disc_records(chosen))

    heading("Ready")
    say("  Players:  %s" % {"me": "just you, on this computer", "home": "people on your home network",
                            "internet": "friends over the internet"}[who])
    say("  Address:  %s" % address)
    say("  Discs:    %s" % (", ".join(d.game for d in chosen.values()) or "none (the boards show without art)"))
    say("  Name:     %s" % name)
    say("  Runs:     %s" % ("in Docker (docker compose)" if mode() == "docker" else
                            "on this computer, no Docker needed"))
    if dry_run:
        say()
        say("Dry run: nothing was written. Setup would write these settings to %s:" % ENV)
        for key, value in changes.items():
            if key != "DDR_ADMIN_TOKEN":
                say("  %s=%s" % (key, value))
        if "DDR_ADMIN_TOKEN" in changes:
            say("  DDR_ADMIN_TOKEN: made at random")
        return
    if not ask_yes("Start?"):
        return
    write_env(changes)
    write_choices(choices)
    say()
    say("Details of every step go to %s" % LOG)
    if who == "internet":
        heading("Router")
        ok, router = open_router_ports()
        choices["router"] = "open" if ok else "closed"
        write_choices(choices)
        if not ok:
            show_port_help(router)
    if chosen:
        heading("Your discs")
        progress = proglib.Progress()
        with log_file() as log:
            use_discs(chosen, progress, log)
    heading("Starting")
    if mode() == "native" and os.name == "nt" and who != "me":
        say("Windows may ask whether %s may use the network. Tick Private networks" % APP)
        say("and click Allow, or other devices cannot reach the server.")
    if not start_server():
        say("Fix the cause, then run %s again and choose Start the server." % APP)
        return
    finish(choices)
    clean = [d for d in chosen.values() if not d.online]
    if clean and ask_yes("Make the patched copy of your disc%s now?" % ("s" if len(clean) > 1 else "")):
        patch_discs(chosen)
    if docker_ok() and find_panel() and ask_yes("An OpenLobby admin panel runs on this computer. Connect to it?"):
        connect_panel()


# --- menu --------------------------------------------------------------------------------

def change_settings():
    """The settings menu. Returns once the host goes back."""
    while True:
        env, choices = read_env(), read_choices()
        hooks = sum(1 for g in ("E2", "SN", "SN2") if env.get("DDR_BOARDS_%s_DISCORD_WEBHOOK" % g))
        items = [
            ("Who will play (now: %s, at %s)" % ({"me": "just you", "home": "home network",
                                                  "internet": "friends over the internet"}.get(
                choices.get("who"), "home network"), player_address(choices)), change_who),
            ("Server name and welcome message (now: %s)" % (env.get("DDR_SERVER_NAME") or DEFAULT_NAME),
             change_name),
            ("Players connect through another machine, like a VPS or tunnel (now: %s)"
             % (env.get("DDR_PUBLIC_ADDR") or "no"), change_public),
            ("Discord posts from the boards (now: %d of 3 games)" % hooks, change_discord),
            ("Make a new admin token for the OpenLobby panel", new_admin_token),
        ]
        heading("Change settings")
        for i, (title, _) in enumerate(items, 1):
            say("  %d. %s" % (i, title))
        say("  0. Back")
        pick = ask("Type a number", "0")
        if pick == "0":
            return
        if pick.isdigit() and 1 <= int(pick) <= len(items):
            running = server_running()
            if items[int(pick) - 1][1](env, read_choices()) and running:
                say("Restarting the server with the new settings...")
                restart_server()


def change_who(env, choices):
    who = ask_who(choices.get("who", "home"))
    choices.update(who=who, address=ask_address(who, choices.get("address", "")))
    if who == "internet":
        ok, router = open_router_ports()
        choices["router"] = "open" if ok else "closed"
        if not ok:
            show_port_help(router)
    write_choices(choices)
    say("Players now point the game's names at %s." % choices["address"])
    return False


def change_name(env, choices):
    name = ask_name(env.get("DDR_SERVER_NAME") or DEFAULT_NAME)
    say("The welcome message shows in a box when a player logs in. Keep it short.")
    motd = ask("Welcome message", env.get("DDR_MOTD") or "Welcome to %s!" % name)
    motd = plain_text(motd)[:MOTD_MAX]
    write_env({"DDR_SERVER_NAME": name, "DDR_MOTD": motd})
    choices["name"] = name
    write_choices(choices)
    return True


def change_public(env, choices):
    say("Only for a server that players reach through another machine (a VPS, a tunnel,")
    say("a proxy) which passes their own addresses on. Then type the address or name")
    say("players connect to. For an ordinary home connection, leave this empty: the")
    say("server finds its internet address by itself.")
    value = ask("Address players connect to (empty for automatic)", env.get("DDR_PUBLIC_ADDR", ""))
    write_env({"DDR_PUBLIC_ADDR": value.strip() or None})
    return True


def change_discord(env, choices):
    say("Each game's board can post its standings to a Discord channel. In Discord, open")
    say("the channel's settings, Integrations, Webhooks, make one and copy its URL.")
    changes = {}
    for key, game in (("E2", "Extreme 2"), ("SN", "SuperNOVA"), ("SN2", "SuperNOVA 2")):
        name = "DDR_BOARDS_%s_DISCORD_WEBHOOK" % key
        value = ask("Webhook for %s (empty for none, - to remove)" % game, env.get(name, ""))
        changes[name] = None if value.strip() in ("", "-") else value.strip()
    write_env(changes)
    return True


def start_menu():
    if server_running():
        say("The server is already running.")
        return
    start_server()


def stop_menu():
    if not server_running():
        say("The server is not running.")
        return
    if ask_yes("Stop the server? Players in the game are disconnected.", False):
        stop_server()
        say("Stopped. It starts again when you choose Start the server.")


def update():
    """Fetch the new version and restart the server with it."""
    if os.path.exists(os.path.join(ROOT, ".git")):
        if run(["git", "pull", "--ff-only"], check=False).returncode != 0:
            say("git pull failed (local changes?). Nothing was changed.")
            return
    else:
        release = latest_release()
        if not release:
            say("Could not reach %s. Check the internet connection." % RELEASES)
            return
        tag, url = release
        if tag == installed_version():
            say("This is the newest version (%s)." % tag)
            return
        say("Downloading %s..." % tag)
        archive = os.path.join(ROOT, "logs", "update.zip")
        os.makedirs(os.path.dirname(archive), exist_ok=True)
        try:
            urllib.request.urlretrieve(url, archive)
            unpack_server(archive, ROOT, tag)
        except (OSError, zipfile.BadZipFile) as e:
            say("The download failed (%s). Nothing was changed." % e)
            return
        finally:
            if os.path.exists(archive):
                os.remove(archive)
        say("Updated the server's files to %s." % tag)
        if FROZEN:
            say("A new %s is also on %s" % (APP, RELEASES))
    if server_running() or mode() == "docker":
        say("Restarting the server...")
        restart_server()


def backup_name():
    return os.path.join(BACKUPS, "ddr-%s.zip" % datetime.datetime.now().strftime("%Y%m%d-%H%M%S"))


def backup():
    os.makedirs(BACKUPS, exist_ok=True)
    target = backup_name()
    say("Saving accounts, results and settings...")
    if mode() == "native":
        try:
            statefiles.backup(STATE, target)
        except (OSError, ValueError) as e:
            say("The backup failed: %s" % e)
            return
    else:
        owner = "%d:%d" % (os.getuid(), os.getgid()) if hasattr(os, "getuid") else ""
        cmd = in_container("gate", ["-v", "%s:/repo:ro" % ROOT, "-v", "%s:/backups" % BACKUPS],
                           ["python3", "/repo/hostsetup/statefiles.py", "backup", "/state",
                            "/backups/" + os.path.basename(target)] + (["--owner", owner] if owner else []))
        if run(cmd, check=False).returncode != 0:
            say("The backup failed (above).")
            return
    say("Saved %s" % target)
    say("Also keep a copy of %s somewhere safe: it holds the admin token and Discord settings." % ENV)


def restore():
    zips = sorted(f for f in os.listdir(BACKUPS) if f.endswith(".zip")) if os.path.isdir(BACKUPS) else []
    if not zips:
        say("No backups in %s." % BACKUPS)
        return
    for i, name in enumerate(zips, 1):
        say("  %d. %s" % (i, name))
    pick = ask("Restore which one (number, Enter to cancel)")
    if not pick.isdigit() or not 1 <= int(pick) <= len(zips):
        return
    name = zips[int(pick) - 1]
    say("This replaces every account, player file and result with the ones in %s." % name)
    say("Play since then is lost. The server is stopped meanwhile.")
    if not ask_yes("Go on?", False):
        return
    was_running = server_running()
    stop_server()
    if mode() == "native":
        try:
            statefiles.restore(os.path.join(BACKUPS, name), STATE)
        except (OSError, ValueError, zipfile.BadZipFile) as e:
            say("The restore failed: %s" % e)
            return
    else:
        cmd = in_container("gate", ["-v", "%s:/repo:ro" % ROOT, "-v", "%s:/backups:ro" % BACKUPS],
                           ["python3", "/repo/hostsetup/statefiles.py", "restore", "/backups/" + name, "/state"])
        if run(cmd, check=False).returncode != 0:
            say("The restore failed (above).")
            return
    say("Restored %s." % name)
    if was_running or mode() == "docker":
        start_server()


def patch_menu():
    """Menu item: patch a disc the setup knows, or one the host points at."""
    choices = read_choices()
    known = [d for d in chosen_discs(choices).values() if not d.online]
    options = ["%s: %s" % (d.game, d.shown()) for d in known] + ["Another disc image"]
    pick = ask_choice("Which disc?", options, 1)
    if pick <= len(known):
        target = {known[pick - 1].serial: known[pick - 1]}
    else:
        path = ask_path("The disc image (.iso or .zip; you can drag it into this window)")
        found = disclib.identify(path) if path and os.path.isfile(path) else []
        if not found:
            say("That is not a DDR disc image setup can read (Extreme 2, SuperNOVA or SuperNOVA 2, USA, as .iso).")
            return
        target = disclib.pick(found)
    patch_discs(target)


def bake_menu():
    choices = read_choices()
    chosen = chosen_discs(choices)
    if chosen and ask_yes("Use the same discs as last time (%s)?" % ", ".join(d.game for d in chosen.values())):
        pass
    else:
        chosen = find_discs()
        if not chosen:
            return
        choices["discs"] = disc_records(chosen)
        write_choices(choices)
    progress = proglib.Progress()
    with log_file() as log:
        use_discs(chosen, progress, log)
    say("The boards pick the new art up within a minute.")


def follow(path, lines=200):
    """Show the end of a file and then what is added to it, until Ctrl+C."""
    for line in tail_lines(path, lines):
        say(line)
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            while True:
                chunk = f.read()
                if chunk:
                    sys.stdout.write(chunk)
                    sys.stdout.flush()
                else:
                    time.sleep(1)
    except OSError:
        say("There is no log yet (%s)." % path)


def logs():
    say("Showing what the server is doing. Press Ctrl+C to go back to the menu.")
    try:
        if mode() == "native":
            follow(SERVER_LOG)
        else:
            compose("logs", "-f", "--tail", "200", check=False)
    except KeyboardInterrupt:
        pass


def router_again():
    choices = read_choices()
    if choices.get("who") != "internet":
        say("Your server is set up for your home network only, so the router needs no open ports.")
        say("Choose Change settings, then Who will play, to change that.")
        return
    ok, router = open_router_ports()
    choices["router"] = "open" if ok else "closed"
    write_choices(choices)
    if not ok:
        show_port_help(router)


def tell_players():
    finish(read_choices())


def menu_items():
    items = [("Start the server", start_menu),
             ("Stop the server", stop_menu),
             ("Change settings", change_settings),
             ("Update", update),
             ("Make a backup", backup),
             ("Restore a backup", restore),
             ("Patch a disc for online play", patch_menu),
             ("Bake the board art again", bake_menu),
             ("Show what the server is doing (logs)", logs),
             ("Check that the server works", smoke),
             ("Open the router ports again", router_again),
             ("Connect to an OpenLobby admin panel", connect_panel),
             ("Show what to tell players", tell_players)]
    if mode() == "native" and os.name == "nt":
        items.append(("Start with Windows (now: %s)" % ("on" if autostart_on() else "off"), toggle_autostart))
    return items


def menu():
    while True:
        items = menu_items()
        heading("DDR Online server: %s (players use %s)" % ("running" if server_running() else "stopped",
                                                            player_address(read_choices())))
        for i, (title, _) in enumerate(items, 1):
            say("  %2d. %s" % (i, title))
        say("   0. Quit")
        pick = ask("Type a number", "0")
        if pick == "0":
            return
        if pick.isdigit() and 1 <= int(pick) <= len(items):
            try:
                items[int(pick) - 1][1]()
            except KeyboardInterrupt:
                say()
            except SystemExit as e:
                say(str(e))


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog=APP, description=(
        "Sets up and runs a DDR Online server. The first run asks three questions; later runs show a menu."))
    ap.add_argument("--folder", help="the server folder (default: the one this runs from, or "
                                     "'%s' in your home folder for the setup program)" % DEFAULT_FOLDER)
    ap.add_argument("--dry-run", action="store_true",
                    help="ask the questions and look for the discs, then show what would be done; "
                         "writes nothing and needs no Docker")
    ap.add_argument("--start", action="store_true",
                    help="start the server without the menu (what 'Start with Windows' runs)")
    ap.add_argument("--stop", action="store_true", help="stop the server without the menu")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    use_root(find_root(args.folder))
    try:
        if args.dry_run:
            say("Server folder: %s%s" % (ROOT, "" if os.path.exists(COMPOSE) else
                                         " (the server's files would be unpacked here)"))
            say("Runs: %s" % mode())
            first_run(dry_run=True)
            return
        if not ensure_server_files():
            return
        os.chdir(ROOT)
        if mode() == "docker":
            wait_for_docker(wait=not (args.start or args.stop))
        if args.start or args.stop:
            if not os.path.exists(ENV):
                say("Run %s once without --start first: it asks three questions." % APP)
                return
            if args.stop:
                stop_server()
            else:
                start_server()
            return
        if not os.path.exists(ENV):
            first_run()
            return
        menu()
    except KeyboardInterrupt:
        say()
        sys.exit(1)


def script_argv(argv):
    """The script and its arguments when this program was asked to run one,
    else None: `--run-script x.py ...`, or, in the frozen program, `[-u] x.py
    ...` as a Python would take it, since server code that starts a helper
    with sys.executable (server/selftest.py does) gets this program."""
    if argv[:1] == ["--run-script"]:
        return argv[1:]
    if FROZEN:
        rest = argv[1:] if argv[:1] == ["-u"] else argv
        if rest and rest[0].endswith(".py") and os.path.isfile(rest[0]):
            return rest
    return None


if __name__ == "__main__":
    script = script_argv(sys.argv[1:])
    if script is not None:
        run_script(script)
    else:
        quiet = any(a in ("--start", "--stop", "--help", "-h") for a in sys.argv[1:])
        try:
            main()
        finally:
            if FROZEN and not quiet:
                # A double-clicked program's window closes when it ends: keep it open to be read.
                try:
                    input("Press Enter to close this window.")
                except (EOFError, KeyboardInterrupt):
                    pass
