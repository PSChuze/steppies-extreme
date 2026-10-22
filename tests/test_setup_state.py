"""Backups of the state folder: ddr.db in WAL mode comes out whole even while
another connection holds writes in its WAL, and a restore does not let an old
WAL replay over the restored database."""
import io
import os
import shutil
import sqlite3
import tempfile
import unittest
import zipfile
from unittest import mock

from hostsetup import statefiles


class Backup(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        self.state = os.path.join(self.dir, "state")
        os.makedirs(os.path.join(self.state, "boardart", "sn"))
        for name, data in (("xorkey.bin", b"\x01\x02\x03\x04"), ("admin_token", b"t"), ("live.json", b"{}"),
                           ("serve.pid", b"1"), ("boardart/sn/bg.png", b"png")):
            with open(os.path.join(self.state, *name.split("/")), "wb") as f:
                f.write(data)

    def open_db(self):
        db = sqlite3.connect(os.path.join(self.state, "ddr.db"))
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA wal_autocheckpoint=0")       # keep the rows in the WAL, as a busy gate does
        self.addCleanup(db.close)
        return db

    def test_backup_while_running_and_restore(self):
        db = self.open_db()
        db.execute("CREATE TABLE accounts (name TEXT)")
        db.executemany("INSERT INTO accounts VALUES (?)", [("ALICE",), ("BOB",)])
        db.commit()
        self.assertTrue(os.path.getsize(os.path.join(self.state, "ddr.db-wal")) > 0)
        archive = os.path.join(self.dir, "backups", "one.zip")
        names = statefiles.backup(self.state, archive)
        self.assertEqual(sorted(names), ["admin_token", "ddr.db", "xorkey.bin"])
        with zipfile.ZipFile(archive) as z:
            self.assertNotIn("ddr.db-wal", z.namelist())

        # Play goes on after the backup, then the host restores it.
        db.execute("INSERT INTO accounts VALUES ('CAROL')")
        db.commit()
        db.close()
        statefiles.restore(archive, self.state)
        self.assertFalse(os.path.exists(os.path.join(self.state, "ddr.db-wal")))
        check = sqlite3.connect(os.path.join(self.state, "ddr.db"))
        self.addCleanup(check.close)
        rows = [r[0] for r in check.execute("SELECT name FROM accounts ORDER BY name")]
        self.assertEqual(rows, ["ALICE", "BOB"])
        with open(os.path.join(self.state, "boardart", "sn", "bg.png"), "rb") as f:
            self.assertEqual(f.read(), b"png")      # left alone

    def test_restore_refuses_other_zips(self):
        other = os.path.join(self.dir, "other.zip")
        with zipfile.ZipFile(other, "w") as z:
            z.writestr("../evil", "x")
        with self.assertRaises(ValueError):
            statefiles.restore(other, self.state)

    def test_restore_stays_inside_the_state_folder(self):
        bad = os.path.join(self.dir, "bad.zip")
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("ddr.db", b"")
            z.writestr("../outside.txt", "x")
        statefiles.restore(bad, self.state)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "outside.txt")))

    def test_command_line(self):
        self.open_db().execute("CREATE TABLE t (x)")
        archive = os.path.join(self.dir, "cli.zip")
        with mock.patch("sys.stdout", io.StringIO()) as out:
            statefiles.main(["backup", self.state, archive])
        self.assertIn("backup: 3 files", out.getvalue())
        self.assertTrue(os.path.exists(archive))
        with self.assertRaises(SystemExit):
            statefiles.main(["sideways"])


if __name__ == "__main__":
    unittest.main()
