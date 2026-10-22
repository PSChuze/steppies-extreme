"""setup.py's first run and menu: what the three answers turn into, the ports
players need, the .env file, the server files of a release, the commands it
runs for the discs, and the start-with-Windows file. Nothing here talks to
Docker or starts a server."""
import io
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

import setup
from hostsetup import discs


def answers(*lines):
    return mock.patch("builtins.input", side_effect=list(lines))


class InTempFolder(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        root = setup.ROOT
        setup.use_root(self.dir)
        self.addCleanup(setup.use_root, root)
        self.out = io.StringIO()
        p = mock.patch("sys.stdout", self.out)
        p.start()
        self.addCleanup(p.stop)


class Settings(unittest.TestCase):
    def test_first_settings(self):
        c = setup.first_settings("Dance Hall", {})
        self.assertEqual(c["DDR_SERVER_NAME"], "Dance Hall")
        self.assertEqual(c["DDR_MOTD"], "Welcome to Dance Hall!")
        self.assertGreaterEqual(len(c["DDR_ADMIN_TOKEN"]), 32)

    def test_existing_values_stay(self):
        c = setup.first_settings("X", {"DDR_ADMIN_TOKEN": "keep", "DDR_MOTD": "Hello"})
        self.assertEqual(c, {"DDR_SERVER_NAME": "X"})

    def test_names_fit_the_game(self):
        self.assertEqual(setup.clean_name("  Dance Hall  "), "Dance Hall")
        self.assertEqual(setup.clean_name("Caf\u00e9 \u2665 Dance"), "Caf  Dance")
        self.assertEqual(len(setup.clean_name("A" * 40)), setup.NAME_MAX)
        self.assertEqual(setup.clean_name('Club "$HOME" #1'), "Club HOME 1")
        self.assertEqual(setup.clean_name("\u2665\u2665"), "")

    def test_ports(self):
        ports = setup.ports_to_open()
        self.assertIn((9573, "TCP"), ports)
        self.assertIn((19580, "TCP"), ports)
        self.assertIn((3479, "UDP"), ports)
        self.assertEqual([p for p, proto in ports if proto == "UDP" and p >= 19600], list(range(19600, 19616)))
        self.assertEqual(setup.port_ranges(setup.UDP_PORTS), [(3478, 3479), (19600, 19615)])
        self.assertEqual(setup.port_ranges(setup.TCP_PORTS),
                         [(9573, 9573), (19570, 19570), (19573, 19573), (19580, 19580), (29570, 29570),
                          (29573, 29573)])

    def test_mode(self):
        with mock.patch.dict(os.environ, {"DDR_SETUP_MODE": ""}):
            with mock.patch.object(setup.sys, "platform", "linux"):
                self.assertEqual(setup.mode(), "docker")
            for platform in ("win32", "darwin"):
                with mock.patch.object(setup.sys, "platform", platform):
                    self.assertEqual(setup.mode(), "native")
        with mock.patch.dict(os.environ, {"DDR_SETUP_MODE": "native"}), \
                mock.patch.object(setup.sys, "platform", "linux"):
            self.assertEqual(setup.mode(), "native")


class EnvFile(InTempFolder):
    def test_first_write_and_later_ones(self):
        setup.write_env({"DDR_SERVER_NAME": "A", "DDR_ADMIN_TOKEN": "t"})
        with open(setup.ENV, encoding="utf-8") as f:
            text = f.read()
        self.assertTrue(text.startswith("# Settings for the DDR Online server"))
        setup.write_env({"DDR_SERVER_NAME": "B", "DDR_PUBLIC_ADDR": "203.0.113.10"})
        self.assertEqual(setup.read_env(), {"DDR_SERVER_NAME": "B", "DDR_ADMIN_TOKEN": "t",
                                            "DDR_PUBLIC_ADDR": "203.0.113.10"})
        setup.write_env({"DDR_PUBLIC_ADDR": None})
        self.assertNotIn("DDR_PUBLIC_ADDR", setup.read_env())
        with open(setup.ENV, encoding="utf-8") as f:
            self.assertIn("#DDR_PUBLIC_ADDR=203.0.113.10\n", f.read())


class FirstRun(InTempFolder):
    def setUp(self):
        super().setUp()
        for target, value in (("lan_address", "192.168.1.20"), ("public_address", "203.0.113.9")):
            p = mock.patch.object(setup, target, return_value=value)
            p.start()
            self.addCleanup(p.stop)
        found = [discs.Disc("/games/DDR SuperNOVA (USA).iso", "SLUS-21377"),
                 discs.Disc("/games/e2.zip", "SLUS-21174", "DDR Extreme 2 (USA).iso")]
        for target, value in (("likely_folders", ["/games"]), ("search", found)):
            p = mock.patch.object(discs, target, return_value=value)
            p.start()
            self.addCleanup(p.stop)

    def test_three_questions(self):
        with answers("3", "play.example.net", "", "Dance Hall"):
            setup.first_run(dry_run=True)
        out = self.out.getvalue()
        self.assertIn("Question 1 of 3: Who will play on this server?", out)
        self.assertIn("Your internet address is 203.0.113.9.", out)
        self.assertIn("Extreme 2: DDR Extreme 2 (USA).iso (inside /games/e2.zip)", out)
        self.assertIn("  Address:  play.example.net\n", out)
        self.assertIn("  DDR_SERVER_NAME=Dance Hall\n", out)
        self.assertIn("  DDR_ADMIN_TOKEN: made at random\n", out)
        self.assertFalse(os.path.exists(setup.ENV))
        self.assertNotIn("\u2014", out)

    def test_defaults_and_no_discs(self):
        with answers("", "n", "", ""):
            setup.first_run(dry_run=True)
        out = self.out.getvalue()
        self.assertIn("Players point the game's names at this computer's address: 192.168.1.20", out)
        self.assertIn("  Discs:    none", out)
        self.assertIn("  DDR_SERVER_NAME=DDR Online\n", out)

    def test_a_long_name_is_shortened(self):
        with answers("", "", "Dance Dance Revolution Club", "y"):
            setup.first_run(dry_run=True)
        self.assertIn("  DDR_SERVER_NAME=Dance Dance Revo\n", self.out.getvalue())

    def test_whole_first_run(self):
        """Every step after the questions, with the steps that start things replaced."""
        with mock.patch.object(setup, "use_discs") as use_discs, \
                mock.patch.object(setup, "start_server", return_value=True) as start, \
                mock.patch.object(setup, "open_router_ports", return_value=(True, "")) as router, \
                mock.patch.object(setup, "docker_ok", return_value=False), \
                mock.patch.object(setup, "patch_discs") as patch, \
                answers("3", "", "", "Dance Hall", "", "y"):
            setup.first_run()
        env = setup.read_env()
        self.assertEqual(env["DDR_SERVER_NAME"], "Dance Hall")
        self.assertIn("DDR_ADMIN_TOKEN", env)
        choices = setup.read_choices()
        self.assertEqual((choices["who"], choices["address"], choices["router"]),
                         ("internet", "203.0.113.9", "open"))
        self.assertEqual(sorted(d["serial"] for d in choices["discs"]), ["SLUS-21174", "SLUS-21377"])
        use_discs.assert_called_once()
        start.assert_called_once()
        router.assert_called_once()
        patch.assert_called_once()
        out = self.out.getvalue()
        self.assertIn("dx2gate01.konamionline.com", out)
        self.assertIn("Point these names at 203.0.113.9", out)
        self.assertNotIn("\u2014", out)


class Menu(unittest.TestCase):
    def test_items(self):
        titles = [t for t, _ in setup.menu_items()]
        for wanted in ("Start the server", "Stop the server", "Change settings", "Update", "Make a backup",
                       "Restore a backup", "Patch a disc for online play", "Bake the board art again",
                       "Show what the server is doing (logs)", "Connect to an OpenLobby admin panel",
                       "Show what to tell players"):
            self.assertIn(wanted, titles)
        self.assertTrue(all(callable(fn) for _, fn in setup.menu_items()))

    def test_start_with_windows_only_on_windows(self):
        with mock.patch.object(setup, "mode", return_value="native"), mock.patch.object(setup.os, "name", "nt"), \
                mock.patch.object(setup, "autostart_on", return_value=False):
            self.assertIn("Start with Windows (now: off)", [t for t, _ in setup.menu_items()])
        with mock.patch.object(setup, "mode", return_value="docker"):
            self.assertFalse(any(t.startswith("Start with Windows") for t, _ in setup.menu_items()))

    def test_a_number_runs_its_item(self):
        called = []
        items = [(t, (lambda t=t: called.append(t))) for t, _ in setup.menu_items()]
        with mock.patch.object(setup, "menu_items", return_value=items), \
                mock.patch.object(setup, "server_running", return_value=False), \
                mock.patch.object(setup, "read_choices", return_value={"address": "10.0.0.5"}), \
                mock.patch("sys.stdout", io.StringIO()), answers("2", "x", "99", "9", "0"):
            setup.menu()
        self.assertEqual(called, ["Stop the server", "Show what the server is doing (logs)"])

    def test_settings_restart_a_running_server(self):
        with mock.patch.object(setup, "read_env", return_value={}), \
                mock.patch.object(setup, "read_choices", return_value={}), \
                mock.patch.object(setup, "server_running", return_value=True), \
                mock.patch.object(setup, "change_public", return_value=True) as change, \
                mock.patch.object(setup, "restart_server") as restart, \
                mock.patch("sys.stdout", io.StringIO()), answers("3", "0"):
            setup.change_settings()
        change.assert_called_once()
        restart.assert_called_once_with()


class ServerFiles(InTempFolder):
    def release(self, name, files):
        path = os.path.join(self.dir, name)
        with zipfile.ZipFile(path, "w") as z:
            for rel, text in files.items():
                z.writestr("steppies-extreme-1.0/" + rel, text)
        return path

    def test_unpack_and_update(self):
        root = os.path.join(self.dir, "server")
        os.makedirs(os.path.join(root, "state"))
        with open(os.path.join(root, ".env"), "w") as f:
            f.write("mine")
        first = self.release("a.zip", {"docker-compose.yml": "1", "old.py": "x", ".env": "theirs",
                                       "state/ddr.db": "no", "setup.json": "no", "../escape": "no"})
        setup.unpack_server(first, root, "v1.0.0")
        self.assertEqual(sorted(setup.read_manifest(root)), ["docker-compose.yml", "old.py"])
        with open(os.path.join(root, ".env")) as f:
            self.assertEqual(f.read(), "mine")
        self.assertFalse(os.path.exists(os.path.join(root, "state", "ddr.db")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "escape")))
        second = self.release("b.zip", {"docker-compose.yml": "2", "new.py": "y"})
        setup.unpack_server(second, root, "v1.1.0")
        self.assertFalse(os.path.exists(os.path.join(root, "old.py")))
        with open(os.path.join(root, ".setup-version")) as f:
            self.assertEqual(f.read().strip(), "v1.1.0")

    def test_root(self):
        self.assertEqual(setup.find_root(self.dir), os.path.abspath(self.dir))
        self.assertEqual(setup.find_root(), os.path.dirname(os.path.abspath(setup.__file__)))

    def test_server_imports(self):
        names = setup.server_imports(os.path.dirname(os.path.abspath(setup.__file__)))
        for wanted in ("sqlite3", "socket", "http.server", "urllib.request"):
            self.assertIn(wanted, names)
        for own in ("gate", "db", "boardart", "serve"):
            self.assertNotIn(own, names)


class Commands(InTempFolder):
    def test_script_cmd(self):
        with mock.patch.object(setup, "FROZEN", False):
            self.assertEqual(setup.script_cmd("/s/x.py", "a"), [sys.executable, "-u", "/s/x.py", "a"])
        with mock.patch.object(setup, "FROZEN", True), mock.patch.object(setup.sys, "executable", "/p/setup"):
            self.assertEqual(setup.script_cmd("/s/x.py", "a"), ["/p/setup", "--run-script", "/s/x.py", "a"])

    def test_run_script(self):
        script = os.path.join(self.dir, "hello.py")
        helper = os.path.join(self.dir, "helper_mod_for_test.py")
        with open(helper, "w") as f:
            f.write("WORD = 'beside'\n")
        with open(script, "w") as f:
            f.write("import sys, helper_mod_for_test\nprint(__name__, sys.argv[1:], helper_mod_for_test.WORD)\n")
        argv, path = list(sys.argv), list(sys.path)
        try:
            setup.run_script([script, "one", "two"])
        finally:
            sys.argv[:], sys.path[:] = argv, path
            sys.modules.pop("helper_mod_for_test", None)
        self.assertIn("__main__ ['one', 'two'] beside", self.out.getvalue())

    def test_script_argv(self):
        script = os.path.join(self.dir, "x.py")
        open(script, "w").close()
        self.assertEqual(setup.script_argv(["--run-script", "y.py", "a"]), ["y.py", "a"])
        with mock.patch.object(setup, "FROZEN", False):
            self.assertIsNone(setup.script_argv([script]))
        with mock.patch.object(setup, "FROZEN", True):
            self.assertEqual(setup.script_argv([script, "--port", "1"]), [script, "--port", "1"])
            self.assertEqual(setup.script_argv(["-u", script]), [script])
            self.assertIsNone(setup.script_argv(["--start"]))
            self.assertIsNone(setup.script_argv([os.path.join(self.dir, "missing.py")]))

    def test_disc_commands_native(self):
        with mock.patch.object(setup, "mode", return_value="native"), mock.patch.object(setup, "FROZEN", False):
            bake = setup.bake_command(["/d/a.iso", "/d/b.iso"])
            key = setup.loginkey_command("/d/a.iso")
        self.assertEqual(bake[2:], [os.path.join(setup.SERVER_DIR, "boardart.py"), "/d/a.iso", "/d/b.iso",
                                    "--out", os.path.join(setup.STATE, "boardart")])
        self.assertEqual(key[-2:], ["/d/a.iso", os.path.join(setup.STATE, "loginkey.bin")])

    def test_disc_commands_docker(self):
        with mock.patch.object(setup, "mode", return_value="docker"):
            bake = setup.bake_command(["/d/a.iso", "/e/b.iso"])
            key = setup.loginkey_command("/d/a.iso")
        self.assertEqual(bake[:6], ["docker", "compose", "run", "--rm", "--no-deps", "-T"])
        self.assertIn("%s:/discs/1:ro" % os.path.abspath("/d"), bake)
        self.assertIn("%s:/discs/2:ro" % os.path.abspath("/e"), bake)
        self.assertEqual(bake[-4:], ["python3", "boardart.py", "/discs/1/a.iso", "/discs/2/b.iso"])
        self.assertEqual(key[-4:], ["python3", "/repo/tools/loginkey.py", "/discs/1/a.iso", "/state/loginkey.bin"])

    def test_patched_name_sits_beside_the_original(self):
        iso = discs.Disc(os.path.join(self.dir, "DDR SuperNOVA (USA).iso"), "SLUS-21377")
        zipped = discs.Disc(os.path.join(self.dir, "z", "sn.zip"), "SLUS-21377", "inner/DDR SN2 (USA).iso")
        self.assertEqual(setup.patched_name(iso), os.path.join(self.dir, "DDR SuperNOVA (USA) [ONLINE].iso"))
        self.assertEqual(setup.patched_name(zipped), os.path.join(self.dir, "z", "DDR SN2 (USA) [ONLINE].iso"))

    def test_startup_script(self):
        with mock.patch.object(setup, "FROZEN", True), \
                mock.patch.object(setup.sys, "executable", r"C:\Programs\DDR-Online-Setup.exe"):
            text = setup.startup_script()
        self.assertTrue(text.startswith("@echo off\r\n"))
        self.assertIn(r'"C:\Programs\DDR-Online-Setup.exe" "--folder" "%s" "--start"' % setup.ROOT, text)

    def test_tell_players_has_every_name(self):
        setup.finish({"who": "home", "address": "192.168.1.20"})
        out = self.out.getvalue()
        for name, _, _ in setup.DNS_NAMES:
            self.assertIn(name, out)
        self.assertIn("192.168.1.20", out)
        self.assertNotIn("\u2014", out)


class Smoke(unittest.TestCase):
    def test_nothing_listening(self):
        with mock.patch.object(setup, "can_connect", return_value=False), \
                mock.patch.object(setup.urllib.request, "urlopen", side_effect=OSError("refused")):
            results = setup.smoke_results()
        self.assertEqual([w for w, _ in results], [c[0] for c in setup.CHECKS])
        self.assertFalse(any(ok for _, ok in results))


if __name__ == "__main__":
    unittest.main()
