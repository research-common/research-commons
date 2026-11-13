"""Against a real ``commons`` built from this tree.

Set ``COMMONS_TEST_BINARY`` to a built binary to skip the build; otherwise the test runs
``go build ./cmd/commons`` (skipped when no Go toolchain is on PATH).
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO, ROOT, build_real  # noqa: F401  (also puts src/ on sys.path)

import research_commons as rc
from research_commons import errors


class RealBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.binary = build_real(Path(cls._tmp.name))
        cls._saved = os.environ.get("COMMONS_BIN")
        os.environ["COMMONS_BIN"] = cls.binary

    @classmethod
    def tearDownClass(cls):
        if cls._saved is None:
            os.environ.pop("COMMONS_BIN", None)
        else:
            os.environ["COMMONS_BIN"] = cls._saved
        cls._tmp.cleanup()

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.addCleanup(self.d.cleanup)
        self.dir = Path(self.d.name)
        # keep an ambient store out of the way
        self._env = {k: os.environ.pop(k, None) for k in ("COMMONS_STORE", "COMMONS_POLICY", "COMMONS_KEY")}
        self.addCleanup(lambda: [os.environ.__setitem__(k, v) for k, v in self._env.items() if v is not None])

    def test_version(self):
        v = rc.version().json
        self.assertEqual(set(v) >= {"version", "commit"}, True)
        want = (REPO / "VERSION").read_text().strip() if (REPO / "VERSION").exists() else None
        if want and not os.environ.get("COMMONS_TEST_BINARY"):
            self.assertEqual(v["version"], want)

    def test_init_then_read_commands(self):
        r = rc.run("init", self.dir)
        self.assertEqual(r.json["result"], "created")
        self.assertEqual(rc.status(store=self.dir).json["store_state"], "nothing pending")
        listed = rc.list_(store=self.dir).json
        self.assertEqual((listed["count"], listed["blobs"], listed["resources"]), (0, [], []))

    def test_verify_unknown_digest_is_exit_3_verdict(self):
        rc.run("init", self.dir)
        d = "sha256:" + "a" * 64
        r = rc.verify(d, store=self.dir, check=False)
        self.assertEqual(r.exit, 3)
        self.assertIsNone(r.problem)
        self.assertEqual(r.json["grade"], "no statement held")
        self.assertEqual(r.json["exit_name"], "could not check")
        with self.assertRaises(errors.CouldNotCheck) as cm:
            rc.verify(d, store=self.dir)
        self.assertEqual(cm.exception.result.json["grade"], "no statement held")

    def test_no_store_is_a_did_not_start_problem(self):
        with self.assertRaises(errors.DidNotStart) as cm:
            rc.run("status", cwd=self.dir)
        e = cm.exception
        self.assertEqual(e.slug, "no-store")
        self.assertIs(e.committed, False)
        self.assertEqual(e.problem_class, "operational")
        self.assertEqual(e.exit, 2)

    def test_missing_argument_problem(self):
        rc.run("init", self.dir)
        with self.assertRaises(errors.DidNotStart) as cm:
            rc.run("verify", "--store", self.dir)
        self.assertEqual(cm.exception.slug, "missing-argument")
        self.assertEqual(cm.exception.problem_class, "intrinsic")

    def test_peer_text_stays_out_of_the_message(self):
        with self.assertRaises(errors.DidNotStart) as cm:
            rc.run("--no-such-option")
        e = cm.exception
        self.assertEqual(e.slug, "unknown-option")
        self.assertIn("--no-such-option", e.peer_text)
        self.assertNotIn("--no-such-option", str(e))

    def test_publish_then_show_round_trip(self):
        rc.run("init", self.dir)
        key = self.dir / "k.key"
        self.assertEqual(rc.run("key", "new", "--out", key).json["alg"], "ed25519")
        f = self.dir / "f.txt"
        f.write_text("hello\n")
        pub = rc.run("publish", "--store", self.dir, "--key", key, "--kind", "authored", "--content", f,
                     "--media-type", "text/plain").json
        self.assertIs(pub["committed"], True)
        digest = "sha256:" + __import__("hashlib").sha256(b"hello\n").hexdigest()
        shown = rc.show(digest, store=self.dir).json
        self.assertEqual((shown["digest"], shown["authorship"]), (digest, "sole author"))
        self.assertEqual(rc.list_(store=self.dir).json["count"], 1)

    def test_console_script_module_runs_the_real_binary(self):
        import sys
        from tests.helpers import SRC
        p = subprocess.run([sys.executable, "-m", "research_commons._cli", "--version"],
                           env=dict(os.environ, PYTHONPATH=str(SRC)), capture_output=True, text=True)
        self.assertEqual(p.returncode, 0)
        self.assertIn("version: ", p.stdout)


if __name__ == "__main__":
    unittest.main()
