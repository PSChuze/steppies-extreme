"""Updating from the admin panel: the version report the gate gives the panel
(server/updates.py), the request the panel's Update button leaves, the runner
doing the update (server/serve.py) and the setup program's unattended update.
GitHub is a stand-in; nothing here needs the internet or Docker."""
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "server"))
import serve  # noqa: E402
import updates  # noqa: E402

import setup  # noqa: E402

OLD = "a" * 40
NEW = "b" * 40
MID = "c" * 40
MERGE = "d" * 40
REPO = "owner/ddr"


def fake_github(release=True, behind_by=0, missing=False):
    """A stand-in for GitHub's API: OLD runs, NEW is the v2 release."""
    def get(path):
        if path == "/repos/%s/releases/latest" % REPO:
            return (200, {"tag_name": "v2"}) if release else (404, None)
        if path in ("/repos/%s/commits/v2" % REPO, "/repos/%s/commits/main" % REPO):
            return 200, {"sha": NEW, "commit": {"committer": {"date": "2026-10-22T08:30:00Z"}}}
        if path.startswith("/repos/%s/compare/" % REPO):
            if missing:
                return 404, None
            commits = [
                {"sha": MID, "parents": [{}], "commit": {"message": "Fix the lobby\n\nmore",
                                                         "committer": {"date": "2026-10-21T00:00:00Z"}}},
                {"sha": MERGE, "parents": [{}, {}], "commit": {"message": "Merge branch",
                                                               "committer": {"date": "2026-10-21T01:00:00Z"}}},
                {"sha": NEW, "parents": [{}], "commit": {"message": "Show tournaments",
                                                         "committer": {"date": "2026-10-22T08:30:00Z"}}}]
            return 200, {"ahead_by": 3, "behind_by": behind_by, "commits": commits}
        raise AssertionError(path)
    return get


class Report(unittest.TestCase):
    def test_available_lists_changes_newest_first_without_merges(self):
        r = updates.check(REPO, OLD, "", "release", fake_github())
        self.assertEqual(r["update"], "available")
        self.assertEqual(r["behind"], 3)
        self.assertEqual([c["commit"] for c in r["changes"]], [NEW, MID])
        self.assertEqual(r["changes"][1]["subject"], "Fix the lobby")
        self.assertEqual(r["latest"], {"commit": NEW, "date": "2026-10-22T08:30:00Z"})

    def test_current(self):
        r = updates.check(REPO, NEW, "", "release", fake_github())
        self.assertEqual((r["update"], r["behind"], r["changes"]), ("current", 0, []))

    def test_no_release_yet_is_unknown_with_a_reason(self):
        with self.assertRaises(updates.Failed) as e:
            updates.check(REPO, OLD, "", "release", fake_github(release=False))
        self.assertIn("No release", str(e.exception))

    def test_a_build_of_your_own(self):
        for kw in ({"missing": True}, {"behind_by": 2}):
            with self.assertRaises(updates.Failed):
                updates.check(REPO, OLD, "", "release", fake_github(**kw))

    def test_no_version_known(self):
        with self.assertRaises(updates.Failed):
            updates.check(REPO, "", "", "release", fake_github())

    def test_checker_never_waits_and_never_raises(self):
        def broken(path):
            raise RuntimeError("boom")
        c = updates.Checker(REPO, get=broken)
        with mock.patch.object(updates, "running", return_value=(OLD, "")):
            c.refresh()
        self.assertEqual(c.get_report()["update"], "unknown")

    def test_off(self):
        self.assertFalse(updates.Checker("off").enabled())
        self.assertIsNone(updates.status_block(updates.Checker("off"), tempfile.gettempdir()))


class Version(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def test_revision_setting_wins(self):
        with mock.patch.dict(os.environ, {"DDR_REVISION": NEW + " 2026-10-22T08:30:00Z"}):
            self.assertEqual(updates.running(), (NEW, "2026-10-22T08:30:00Z"))

    def test_git_checkout_is_read_without_git(self):
        git = os.path.join(self.dir, ".git", "refs", "heads")
        os.makedirs(git)
        with open(os.path.join(self.dir, ".git", "HEAD"), "w") as f:
            f.write("ref: refs/heads/main\n")
        with open(os.path.join(git, "main"), "w") as f:
            f.write(NEW + "\n")
        self.assertEqual(updates._git_head(self.dir), NEW)
        os.remove(os.path.join(git, "main"))
        with open(os.path.join(self.dir, ".git", "packed-refs"), "w") as f:
            f.write("# pack-refs\n%s refs/heads/main\n" % MID)
        self.assertEqual(updates._git_head(self.dir), MID)

    def test_version_file_is_filled_in_by_git_archive(self):
        with open(os.path.join(ROOT, ".gitattributes"), encoding="utf-8") as f:
            self.assertIn("server/version.txt export-subst", f.read())


class PanelRequest(unittest.TestCase):
    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.state)

    def test_only_a_supervised_server_takes_it(self):
        with mock.patch.dict(os.environ, {"DDR_SUPERVISED": ""}):
            code, answer = updates.request(self.state, "Wren")
        self.assertEqual(code, 503)
        self.assertIn("Setup", answer["msg"])

    def test_request_then_already_updating(self):
        with mock.patch.dict(os.environ, {"DDR_SUPERVISED": "1"}):
            self.assertEqual(updates.request(self.state, "Wren")[0], 202)
            self.assertEqual(updates.request(self.state, "Wren")[0], 409)
        with open(os.path.join(self.state, updates.REQUEST_FILE)) as f:
            self.assertEqual(json.load(f)["actor"], "Wren")

    def test_status_says_apply_and_progress(self):
        c = updates.Checker(REPO, get=fake_github())
        with mock.patch.object(updates, "running", return_value=(OLD, "")), \
                mock.patch.object(updates, "track", return_value="release"), \
                mock.patch.dict(os.environ, {"DDR_SUPERVISED": "1"}):
            c.refresh()
            updates.write_state(self.state, state="updating", message="Downloading v2...")
            block = updates.status_block(c, self.state)
        self.assertTrue(block["apply"])
        self.assertEqual((block["state"], block["message"]), ("updating", "Downloading v2..."))
        with mock.patch.dict(os.environ, {"DDR_SUPERVISED": ""}):
            self.assertNotIn("apply", updates.status_block(c, self.state))


class Runner(unittest.TestCase):
    """serve.py doing the update the panel asked for, with a stand-in for the
    setup program."""

    def setUp(self):
        self.state = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.state)
        self.runner = serve.Runner(self.state, {}, only={"stun"}, out=io.StringIO())

    def run_update(self, script):
        with mock.patch.object(self.runner, "setup_command",
                               return_value=[sys.executable, "-c", script]):
            return self.runner.update()

    def test_success_restarts_from_the_new_files(self):
        open(os.path.join(self.state, updates.REQUEST_FILE), "w").close()
        ok = self.run_update("print('Downloading v2...'); print('Updated the server files to v2.')")
        self.assertTrue(ok)
        self.assertFalse(os.path.exists(os.path.join(self.state, updates.REQUEST_FILE)))
        self.assertEqual(updates.read_state(self.state)["message"], serve.RESTARTING)

    def test_failure_keeps_the_old_version_and_says_why(self):
        ok = self.run_update("import sys; print('Downloading v2...'); "
                             "print('The download failed (timed out).'); sys.exit(1)")
        self.assertFalse(ok)
        self.assertEqual(updates.read_state(self.state),
                         {"state": "failed", "why": "The download failed (timed out).",
                          "at": updates.read_state(self.state)["at"]})

    def test_already_newest(self):
        self.assertFalse(self.run_update("print('This is the newest version (v2).')"))
        self.assertEqual(updates.read_state(self.state), {})

    def test_an_update_cut_short_does_not_stick(self):
        updates.write_state(self.state, state="updating", message="Downloading v2...")
        with mock.patch.object(serve.Runner, "check", side_effect=KeyboardInterrupt):
            self.runner.run(tick=0)
        self.assertEqual(updates.read_state(self.state)["state"], "failed")

    def test_the_restart_after_an_update_clears_it(self):
        updates.write_state(self.state, state="updating", message=serve.RESTARTING)
        with mock.patch.object(serve.Runner, "check", side_effect=KeyboardInterrupt):
            self.runner.run(tick=0)
        self.assertEqual(updates.read_state(self.state), {})

    def test_children_know_they_can_update(self):
        self.assertEqual(self.runner.child_env()["DDR_SUPERVISED"], "1")


class Unattended(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        self.old_root = setup.ROOT
        setup.use_root(self.root)
        self.addCleanup(setup.use_root, self.old_root)

    def test_exit_status_and_last_line(self):
        for outcome, code in (("failed", 1), ("current", 0)):
            out = io.StringIO()
            with mock.patch.object(setup, "update_files", return_value=(outcome, "Last line.")), \
                    mock.patch("sys.stdout", out):
                self.assertEqual(setup.update_unattended(), code)
            self.assertEqual(out.getvalue().strip().splitlines()[-1], "Last line.")

    def test_docker_restart_is_checked_through_docker(self):
        out = io.StringIO()
        with mock.patch.object(setup, "update_files", return_value=("updated", "Updated to v2.")), \
                mock.patch.object(setup, "mode", return_value="docker"), \
                mock.patch.object(setup, "compose") as compose, \
                mock.patch.object(setup, "server_running", return_value=True), \
                mock.patch("sys.stdout", out):
            self.assertEqual(setup.update_unattended(), 0)
        self.assertIn("--force-recreate", compose.call_args[0])
        self.assertTrue(out.getvalue().strip().endswith("Updated and running again."))

    def test_an_update_needing_modules_this_program_lacks_is_refused(self):
        archive = os.path.join(self.root, "v2.zip")
        with zipfile.ZipFile(archive, "w") as z:
            z.writestr("ddr-v2/server/gate.py", "import json\nimport nosuchmodule_ddr\n")
            z.writestr("ddr-v2/tools/isopatch.py", "import os\n")
        self.assertEqual(setup.modules_missing_for(archive), ["nosuchmodule_ddr"])


if __name__ == "__main__":
    unittest.main()
