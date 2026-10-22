"""Back up and restore the server's state folder.

    python3 statefiles.py backup  <state folder> <backup.zip> [--owner UID:GID]
    python3 statefiles.py restore <backup.zip> <state folder>

The state folder holds ddr.db (accounts, player files, results), the keys the
gate recovered, the operator page's token and content.json. ddr.db runs in WAL
mode, so a plain copy of the file alone can miss the newest writes, and a copy
of the three files taken while the gate writes can disagree with itself. The
backup goes through sqlite3's backup API instead, which gives one consistent
database even with the server running.

This file runs on its own, with nothing else from this repository: on Linux the
state lives in a Docker volume, and setup.py runs this inside a container that
has the volume mounted. --owner hands the zip back to the host's user there,
since the container writes it as root.

Left out: the baked board art (it is your disc's art, and setup can bake it
again), the live lobby snapshot, and the server runner's own files.
"""
import os
import sqlite3
import sys
import tempfile
import zipfile

DB = "ddr.db"
SKIP_FILES = {DB, DB + "-wal", DB + "-shm", DB + "-journal", "live.json", "serve.pid", "serve.stop"}
SKIP_DIRS = {"boardart"}


def backup(state, archive, owner=None):
    """Write the state folder to the zip `archive`. Returns the names it holds."""
    names = []
    os.makedirs(os.path.dirname(os.path.abspath(archive)), exist_ok=True)
    tmp = archive + ".tmp"
    with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
        db = os.path.join(state, DB)
        if os.path.exists(db):
            fd, copy = tempfile.mkstemp(suffix=".db")
            os.close(fd)
            try:
                src = sqlite3.connect(db)
                dst = sqlite3.connect(copy)
                with dst:
                    src.backup(dst)
                dst.close()
                src.close()
                z.write(copy, DB)
                names.append(DB)
            finally:
                os.remove(copy)
        for base, dirs, files in os.walk(state):
            rel_base = os.path.relpath(base, state)
            if rel_base == ".":
                dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            dirs.sort()
            for name in sorted(files):
                if rel_base == "." and name in SKIP_FILES:
                    continue
                if name.endswith(".tmp"):
                    continue
                rel = os.path.normpath(os.path.join(rel_base, name)).replace(os.sep, "/")
                z.write(os.path.join(base, name), rel)
                names.append(rel)
    os.replace(tmp, archive)
    if owner and hasattr(os, "chown"):
        uid, _, gid = owner.partition(":")
        os.chown(archive, int(uid), int(gid or uid))
    return names


def restore(archive, state):
    """Put a backup's files into the state folder; the server must be stopped.
    The database's WAL files go first, or SQLite would replay the old server's
    last writes over the restored database. Returns the names restored."""
    with zipfile.ZipFile(archive) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
        if DB not in names:
            raise ValueError("%s is not a DDR Online backup (it has no %s)" % (archive, DB))
        os.makedirs(state, exist_ok=True)
        for leftover in (DB + "-wal", DB + "-shm", DB + "-journal"):
            try:
                os.remove(os.path.join(state, leftover))
            except OSError:
                pass
        root = os.path.normpath(os.path.abspath(state))
        for name in names:
            target = os.path.normpath(os.path.join(root, name))
            if not target.startswith(root + os.sep):
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(name) as src, open(target + ".tmp", "wb") as dst:
                while True:
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    dst.write(chunk)
            os.replace(target + ".tmp", target)
    return names


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    owner = None
    if "--owner" in argv:
        i = argv.index("--owner")
        owner = argv[i + 1] if i + 1 < len(argv) else None
        del argv[i:i + 2]
    if len(argv) != 3 or argv[0] not in ("backup", "restore"):
        sys.exit("usage:\n" + "\n".join(__doc__.strip().splitlines()[2:4]))
    try:
        if argv[0] == "backup":
            names = backup(argv[1], argv[2], owner)
        else:
            names = restore(argv[1], argv[2])
    except (OSError, ValueError, zipfile.BadZipFile, sqlite3.Error) as e:
        sys.exit("%s failed: %s" % (argv[0], e))
    print("%s: %d files" % (argv[0], len(names)))


if __name__ == "__main__":
    main()
