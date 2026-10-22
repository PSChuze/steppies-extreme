"""Find the host's DDR disc images: in the usual folders, in PCSX2's game
folders, or where they point us.

A disc is told apart by the serial its SYSTEM.CNF boots (BOOT2 = cdrom0:\\
SLUS_213.77;1), the same way tools/isopatch.py and server/boardart.py do, so
file names do not matter. Zips are looked into but not unpacked here (setup.py
unpacks the one it uses). 7z has no reader in the standard library, so a .7z
is only reported, for the host to unpack.

Only 2048-byte-sector .iso images are read: the patcher cannot rewrite a raw
2352-byte .bin either.
"""
import os
import re
import struct
import sys
import zipfile

GAMES = {"SLUS-21174": "Extreme 2", "SLUS-21377": "SuperNOVA", "SLUS-21608": "SuperNOVA 2"}
IMAGE_EXT = (".iso",)
ZIP_EXT = (".zip",)
SEVENZIP_EXT = (".7z",)
SECTOR = 2048
MIN_IMAGE = 100 << 20       # smaller files are not DVD images
# SYSTEM.CNF sits near the start of every disc we know. A zip member has to be
# decompressed up to the place we seek to, so do not go further than this.
MAX_SEEK = 64 << 20
SKIP_DIRS = {"node_modules", "appdata", "library", "$recycle.bin", "windows", "program files",
             "program files (x86)", "system volume information", ".git", ".cache", "__pycache__"}


class Disc:
    """One disc found: path (the image, or the zip holding it), member (the file
    inside the zip, or None) and serial (SLUS-21377 and so on)."""

    def __init__(self, path, serial, member=None):
        self.path, self.serial, self.member = path, serial, member

    def __repr__(self):
        return "Disc(%r, %r%s)" % (self.path, self.serial, ", %r" % self.member if self.member else "")

    def __eq__(self, other):
        return (self.path, self.serial, self.member) == (other.path, other.serial, other.member)

    def __hash__(self):
        return hash((self.path, self.serial, self.member))

    @property
    def game(self):
        return GAMES.get(self.serial, self.serial)

    @property
    def online(self):
        """True for an image this project's patcher already wrote. The name is
        all there is to go on short of checking every patched byte, which is
        isopatch.py's job."""
        return "[online]" in os.path.basename(self.member or self.path).lower()

    def shown(self):
        return "%s (inside %s)" % (self.member, self.path) if self.member else self.path


def _root_entry(f, wanted):
    """(offset, size) of the file `wanted` in an ISO9660 root directory, or None."""
    f.seek(16 * SECTOR)
    pvd = f.read(SECTOR)
    if len(pvd) < 190 or pvd[1:6] != b"CD001":
        return None
    rec = pvd[156:156 + 34]
    lba, size = struct.unpack_from("<I", rec, 2)[0], struct.unpack_from("<I", rec, 10)[0]
    if lba * SECTOR > MAX_SEEK or size > 64 * SECTOR:
        return None
    f.seek(lba * SECTOR)
    data = f.read(size)
    pos = 0
    while pos < len(data):
        rlen = data[pos]
        if rlen == 0:                               # padding to the next sector
            pos = (pos // SECTOR + 1) * SECTOR
            continue
        r = data[pos:pos + rlen]
        if len(r) < 34:
            break
        name = r[33:33 + r[32]].decode("latin-1").split(";")[0].upper()
        if name == wanted:
            return struct.unpack_from("<I", r, 2)[0] * SECTOR, struct.unpack_from("<I", r, 10)[0]
        pos += rlen
    return None


def read_serial(f):
    """The boot serial of the ISO image open as f ("SLUS-21377"), or ""."""
    entry = _root_entry(f, "SYSTEM.CNF")
    if not entry or entry[0] > MAX_SEEK or entry[1] > 4096:
        return ""
    f.seek(entry[0])
    for line in f.read(entry[1]).decode("latin-1").splitlines():
        if line.upper().startswith("BOOT2"):
            name = line.split("=", 1)[-1].strip().replace("/", "\\").split("\\")[-1].split(";")[0]
            return name.replace("_", "-").replace(".", "", 1).strip().upper()
    return ""


def identify(path):
    """The DDR discs in one file: [Disc] (empty when it holds none)."""
    low = path.lower()
    try:
        if low.endswith(IMAGE_EXT):
            with open(path, "rb") as f:
                serial = read_serial(f)
            return [Disc(path, serial)] if serial in GAMES else []
        if low.endswith(ZIP_EXT):
            found = []
            with zipfile.ZipFile(path) as z:
                for info in z.infolist():
                    if info.filename.lower().endswith(IMAGE_EXT) and info.file_size >= MIN_IMAGE:
                        with z.open(info) as f:
                            serial = read_serial(f)
                        if serial in GAMES:
                            found.append(Disc(path, serial, info.filename))
            return found
    except (OSError, zipfile.BadZipFile, NotImplementedError, RuntimeError, ValueError):
        pass
    return []


def _candidate(name, size):
    return name.lower().endswith(IMAGE_EXT + ZIP_EXT) and size >= MIN_IMAGE


def scan(folder, depth=3, limit=20000, sevenzips=None):
    """Every DDR disc under folder, looking `depth` folders down and at most
    `limit` entries, so a big Documents folder does not stall setup. .7z files
    that look like DDR go into the list `sevenzips` when one is given."""
    found, seen = [], 0
    stack = [(folder, 0)]
    while stack and seen < limit:
        d, level = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in sorted(entries, key=lambda e: e.name.lower()):
            seen += 1
            try:
                if e.is_dir(follow_symlinks=False):
                    if level < depth and not e.name.startswith(".") and e.name.lower() not in SKIP_DIRS:
                        stack.append((e.path, level + 1))
                elif e.is_file() and _candidate(e.name, e.stat().st_size):
                    found += identify(e.path)
                elif sevenzips is not None and e.name.lower().endswith(SEVENZIP_EXT) and looks_like_ddr(e.name):
                    sevenzips.append(e.path)
            except OSError:
                continue
    return found


def looks_like_ddr(name):
    low = name.lower()
    return "dance dance" in low or "ddr" in low or "supernova" in low or "slus-21" in low or "slus_21" in low


def pcsx2_configs(home=None, platform=None, env=None):
    """The PCSX2.ini files this user may have (the Qt versions, 1.7 and 2.x)."""
    home = home or os.path.expanduser("~")
    platform = platform or sys.platform
    env = os.environ if env is None else env
    if platform.startswith("win"):
        bases = [os.path.join(home, "Documents", "PCSX2")]
    elif platform == "darwin":
        bases = [os.path.join(home, "Library", "Application Support", "PCSX2")]
    else:
        config = env.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
        bases = [os.path.join(config, "PCSX2"),
                 os.path.join(home, ".var", "app", "net.pcsx2.PCSX2", "config", "PCSX2")]
    return [os.path.join(b, "inis", "PCSX2.ini") for b in bases]


def pcsx2_game_folders(ini_text):
    """The game list folders of a PCSX2.ini: its Paths and RecursivePaths lines."""
    return [m.group(1).strip() for m in re.finditer(r"(?m)^\s*(?:Recursive)?Paths\s*=\s*(.+?)\s*$", ini_text)
            if m.group(1).strip()]


def likely_folders(extra=(), home=None, platform=None, env=None):
    """Where discs usually are: the given folders first, then Downloads,
    Documents, Desktop, Games and PCSX2's game folders. Only folders that exist."""
    home = home or os.path.expanduser("~")
    folders = list(extra) + [os.path.join(home, n) for n in ("Downloads", "Documents", "Desktop", "Games")]
    for ini in pcsx2_configs(home, platform, env):
        try:
            with open(ini, encoding="utf-8", errors="replace") as f:
                folders += pcsx2_game_folders(f.read())
        except OSError:
            pass
    out, seen = [], set()
    for d in folders:
        key = os.path.normcase(os.path.abspath(d))
        if key not in seen and os.path.isdir(d):
            seen.add(key)
            out.append(d)
    return out


def search(folders, depth=3, sevenzips=None):
    """Scan the folders in order; each disc file is listed once."""
    found, seen = [], set()
    for d in folders:
        for disc in scan(d, depth, sevenzips=sevenzips):
            key = (os.path.normcase(os.path.abspath(disc.path)), disc.member)
            if key not in seen:
                seen.add(key)
                found.append(disc)
    if sevenzips:
        unique = {os.path.normcase(os.path.abspath(p)): p for p in sevenzips}
        sevenzips[:] = list(unique.values())
    return found


def pick(found):
    """{serial: Disc}, one per game: a plain image before a zip (no unpacking
    needed), a clean image before a patched one (the patcher wants a clean
    one; the board art reads either), the first one found among equals."""
    chosen = {}
    for serial in GAMES:
        discs = [d for d in found if d.serial == serial]
        if discs:
            chosen[serial] = sorted(discs, key=lambda d: (d.member is not None, d.online))[0]
    return chosen
