"""Pairing with an OpenLobby admin panel: the requests setup.py sends to
/api/pair and /api/pair/update, how it reads the answers, and the relay
container it starts. A stand-in panel answers over HTTP; nothing here needs
Docker."""
import http.server
import io
import json
import os
import shutil
import tempfile
import threading
import unittest
from unittest import mock

import setup


class Panel(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, body))
        status, answer = self.server.answers.pop(0)
        data = json.dumps(answer).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class Pairing(unittest.TestCase):
    def setUp(self):
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Panel)
        self.server.seen, self.server.answers = [], []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = "http://127.0.0.1:%d" % self.server.server_port

    def test_pair(self):
        self.server.answers.append((200, {"ok": True, "title": "Dance Dance Revolution", "pairing": "p-123"}))
        self.assertEqual(setup.pair(self.url, "AB12CD34", "tok"), ("p-123", ""))
        path, body = self.server.seen[0]
        self.assertEqual(path, "/api/pair")
        self.assertEqual(body, {"code": "AB12CD34", "key": "ddr", "title": "Dance Dance Revolution",
                                "url": "http://ddr:19591", "token": "tok"})

    def test_refusals_are_shown_as_given(self):
        for status, message in ((400, "That code is not valid."), (403, "That code has expired."),
                                (429, "Too many tries. Wait a minute.")):
            self.server.answers.append((status, {"error": message}))
            self.assertEqual(setup.pair(self.url, "x", "tok"), ("", message))
        self.server.answers.append((500, {}))
        self.assertEqual(setup.pair(self.url, "x", "tok"), ("", "the panel answered HTTP 500"))

    def test_no_panel(self):
        pairing, why = setup.pair("http://127.0.0.1:1", "x", "tok")
        self.assertEqual(pairing, "")
        self.assertIn("did not answer", why)

    def test_update(self):
        self.server.answers.append((200, {"ok": True}))
        self.assertEqual(setup.pair_update(self.url, "p-123", "new"), "")
        self.assertEqual(self.server.seen[0], ("/api/pair/update", {"key": "ddr", "pairing": "p-123",
                                                                    "token": "new", "url": "http://ddr:19591"}))
        self.server.answers.append((403, {"error": "Unknown pairing."}))
        self.assertEqual(setup.pair_update(self.url, "p-123", "new"), "Unknown pairing.")


class Menu(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        root = setup.ROOT
        setup.use_root(self.dir)
        self.addCleanup(setup.use_root, root)
        setup.write_env({"DDR_ADMIN_TOKEN": "tok"})
        self.out = io.StringIO()
        for name, value in (("docker_ok", True), ("find_panel", "http://127.0.0.1:8090"),
                            ("ensure_relay", True), ("server_running", False)):
            p = mock.patch.object(setup, name, return_value=value)
            p.start()
            self.addCleanup(p.stop)
        p = mock.patch("sys.stdout", self.out)
        p.start()
        self.addCleanup(p.stop)

    def test_connect_saves_the_pairing(self):
        with mock.patch.object(setup, "pair", return_value=("p-9", "")) as pair, \
                mock.patch("builtins.input", side_effect=["ab12 cd34"]):
            setup.connect_panel()
        pair.assert_called_once_with("http://127.0.0.1:8090", "ab12cd34", "tok")
        self.assertEqual(setup.read_env()["OPENLOBBY_PAIRING"], "p-9")
        self.assertIn("Settings, then Modules", self.out.getvalue())

    def test_a_refusal_saves_nothing(self):
        with mock.patch.object(setup, "pair", return_value=("", "That code has expired.")), \
                mock.patch("builtins.input", side_effect=["ZZZZZZZZ"]):
            setup.connect_panel()
        self.assertNotIn("OPENLOBBY_PAIRING", setup.read_env())
        self.assertIn("Pairing did not work: That code has expired.", self.out.getvalue())

    def test_new_token_reaches_the_panel(self):
        setup.write_env({"OPENLOBBY_PAIRING": "p-9"})
        with mock.patch.object(setup, "pair_update", return_value="") as update, \
                mock.patch("builtins.input", side_effect=["y"]):
            self.assertTrue(setup.new_admin_token(setup.read_env(), {}))
        token = setup.read_env()["DDR_ADMIN_TOKEN"]
        self.assertNotEqual(token, "tok")
        update.assert_called_once_with("http://127.0.0.1:8090", "p-9", token)

    def test_without_docker_nothing_is_tried(self):
        with mock.patch.object(setup, "docker_ok", return_value=False), \
                mock.patch.object(setup, "pair") as pair:
            setup.connect_panel()
            self.assertFalse(setup.openlobby_wanted({"OPENLOBBY_PAIRING": "p"}))
        pair.assert_not_called()
        self.assertIn("Docker is not running", self.out.getvalue())


class Relay(unittest.TestCase):
    def test_relay_command(self):
        cmd = setup.relay_command()
        self.assertEqual(cmd[:4], ["docker", "run", "-d", "--name"])
        for pair in (["--name", "ddr-admin"], ["--restart", "unless-stopped"], ["--network", "openlobby"],
                     ["--network-alias", "ddr"]):
            i = cmd.index(pair[0])
            self.assertEqual(cmd[i:i + 2], pair)
        labels = [cmd[i + 1] for i, a in enumerate(cmd) if a == "--label"]
        self.assertEqual(labels, ["org.openlobby.role=game", "org.openlobby.game.key=ddr",
                                  "org.openlobby.game.title=Dance Dance Revolution",
                                  "org.openlobby.admin.url=http://ddr:19591"])
        self.assertIn("%s:/app:ro" % setup.SERVER_DIR, cmd)
        self.assertEqual(cmd[-6:], ["python3", "/app/adminrelay.py", "--listen", "0.0.0.0:19591",
                                    "--to", "host.docker.internal:19591"])
        self.assertNotIn("-p", cmd)                 # the admin port is never published

    def test_waits_until_the_relay_listens(self):
        # The panel probes the game as soon as it is asked to pair, so a relay
        # that is still starting must be waited for, not reported as running.
        tries = iter([1, 1, 0])
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            return mock.Mock(returncode=next(tries), stdout="")
        with mock.patch.object(setup, "run", fake_run), mock.patch("time.sleep"):
            self.assertTrue(setup.relay_ready())
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0][:3], ["docker", "exec", setup.RELAY_NAME])

    def test_a_relay_that_never_listens_is_reported(self):
        out = io.StringIO()
        with mock.patch.object(setup, "run", lambda cmd, **kw: mock.Mock(returncode=1, stdout="")), \
                mock.patch("time.sleep"), mock.patch("sys.stdout", out):
            self.assertFalse(setup.relay_ready(wait=0))
        self.assertIn("docker logs", out.getvalue())

    def test_find_panel_reads_the_label(self):
        fake = mock.Mock(stdout="\nhttp://127.0.0.1:8090/\n")
        with mock.patch.object(setup, "run", return_value=fake) as run:
            self.assertEqual(setup.find_panel(), "http://127.0.0.1:8090")
        self.assertIn("label=org.openlobby.role=panel", run.call_args[0][0])


if __name__ == "__main__":
    unittest.main()
