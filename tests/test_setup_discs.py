"""setup.py's disc search: telling DDR discs apart by the serial SYSTEM.CNF
boots, looking in the usual folders and PCSX2's, and choosing one per game.
The images here are a few sectors of ISO9660 made on the spot, nothing from a
real disc."""
import os
import shutil
import struct
import tempfile
import unittest
import zipfile
from unittest import mock

from hostsetup import discs

SECTOR = 2048


def dir_record(name, lba, size):
    ident = name.encode("ascii")
    rlen = 33 + len(ident) + (1 - len(ident) % 2)
    rec = bytearray(rlen)
    rec[0] = rlen
    struct.pack_into("<I", rec, 2, lba)
    struct.pack_into("<I", rec, 10, size)
    rec[32] = len(ident)
    rec[33:33 + len(ident)] = ident
    return bytes(rec)


def iso(serial="SLUS_213.77", boot2=None):
    """A minimal ISO: the volume descriptor at sector 16, the root directory at
    18 and SYSTEM.CNF at 19."""
    cnf = (boot2 or "BOOT2 = cdrom0:\\%s;1" % serial).encode("ascii") + b"\r\nVER = 1.00\r\n"
    root = dir_record("\x00", 18, SECTOR) + dir_record("\x01", 18, SECTOR) + dir_record("SYSTEM.CNF;1", 19, len(cnf))
    pvd = bytearray(SECTOR)
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[156:156 + 34] = dir_record("\x00", 18, SECTOR)
    image = bytearray(20 * SECTOR)
    image[16 * SECTOR:17 * SECTOR] = pvd
    image[18 * SECTOR:18 * SECTOR + len(root)] = root
    image[19 * SECTOR:19 * SECTOR + len(cnf)] = cnf
    return bytes(image)


class Serials(unittest.TestCase):
    def read(self, data):
        import io
        return discs.read_serial(io.BytesIO(data))

    def test_the_three_games(self):
        self.assertEqual(self.read(iso("SLUS_211.74")), "SLUS-21174")
        self.assertEqual(self.read(iso("SLUS_213.77")), "SLUS-21377")
        self.assertEqual(self.read(iso("SLUS_216.08")), "SLUS-21608")

    def test_junk_and_other_games(self):
        self.assertEqual(self.read(b""), "")
        self.assertEqual(self.read(bytes(40 * SECTOR)), "")
        self.assertEqual(self.read(iso("SLUS_200.01")), "SLUS-20001")      # read, but not DDR
        self.assertEqual(self.read(iso(boot2="VER = 1.00")), "")


class Files(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        # Real discs are gigabytes; let small test files through.
        patcher = mock.patch.object(discs, "MIN_IMAGE", 0)
        patcher.start()
        self.addCleanup(patcher.stop)

    def put(self, rel, data):
        path = os.path.join(self.dir, *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def test_identify_images_and_zips(self):
        sn = self.put("DDR SuperNOVA (USA).iso", iso("SLUS_213.77"))
        self.assertEqual(discs.identify(sn), [discs.Disc(sn, "SLUS-21377")])
        self.assertEqual(discs.identify(self.put("other.iso", iso("SLUS_200.01"))), [])
        self.assertEqual(discs.identify(self.put("text.iso", b"hello")), [])
        z = os.path.join(self.dir, "e2.zip")
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as f:
            f.writestr("readme.txt", "x")
            f.writestr("DDR Extreme 2 (USA).iso", iso("SLUS_211.74"))
        self.assertEqual(discs.identify(z), [discs.Disc(z, "SLUS-21174", "DDR Extreme 2 (USA).iso")])

    def test_search_finds_nested_and_7z(self):
        a = self.put("games/ps2/sn2.iso", iso("SLUS_216.08"))
        self.put("games/DDR SuperNOVA.7z", b"7z")
        self.put("games/holiday.7z", b"7z")
        sevens = []
        found = discs.search([self.dir, self.dir], sevenzips=sevens)
        self.assertEqual(found, [discs.Disc(a, "SLUS-21608")])
        self.assertEqual([os.path.basename(p) for p in sevens], ["DDR SuperNOVA.7z"])

    def test_pick_prefers_plain_clean_images(self):
        z = discs.Disc("/g/sn.zip", "SLUS-21377", "sn.iso")
        online = discs.Disc("/g/sn [ONLINE].iso", "SLUS-21377")
        plain = discs.Disc("/g/sn.iso", "SLUS-21377")
        e2 = discs.Disc("/g/e2 [ONLINE].iso", "SLUS-21174")
        self.assertEqual(discs.pick([z, online, plain, e2]), {"SLUS-21377": plain, "SLUS-21174": e2})
        self.assertTrue(e2.online)
        self.assertFalse(plain.online)
        self.assertEqual(e2.game, "Extreme 2")


class Folders(unittest.TestCase):
    def test_pcsx2_game_folders(self):
        text = "[GameList]\nRecursivePaths = D:\\PS2\\Games\nPaths = E:\\iso\n\n[Other]\nX = 1\n"
        self.assertEqual(discs.pcsx2_game_folders(text), ["D:\\PS2\\Games", "E:\\iso"])

    def test_pcsx2_configs(self):
        win = discs.pcsx2_configs("/home/u", "win32", {})
        self.assertEqual(win, [os.path.join("/home/u", "Documents", "PCSX2", "inis", "PCSX2.ini")])
        linux = discs.pcsx2_configs("/home/u", "linux", {"XDG_CONFIG_HOME": "/cfg"})
        self.assertEqual(linux[0], os.path.join("/cfg", "PCSX2", "inis", "PCSX2.ini"))

    def test_likely_folders(self):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "Downloads"))
        games = os.path.join(d, "ps2games")
        os.makedirs(games)
        ini = os.path.join(d, "Documents", "PCSX2", "inis", "PCSX2.ini")
        os.makedirs(os.path.dirname(ini))
        with open(ini, "w") as f:
            f.write("[GameList]\nRecursivePaths = %s\n" % games)
        folders = discs.likely_folders(home=d, platform="win32", env={})
        self.assertEqual(folders, [os.path.join(d, "Downloads"), os.path.join(d, "Documents"), games])


if __name__ == "__main__":
    unittest.main()
