import json
import os
import subprocess
import sys
import unittest

from tests.helpers import FakeCase, write_fake  # noqa: F401  (also puts src/ on sys.path)

import research_commons as rc
from research_commons import errors
from research_commons._run import with_json_flag


def problem(slug="no-store", exit=2, **kw):
    o = {"type": errors.PROBLEM_TYPE_PREFIX + slug, "title": "no store to read", "detail": "nothing was done",
         "class": "operational", "scope": "invocation", "committed": False, "next": "run inside a store",
         "exit": exit}
    o.update(kw)
    return json.dumps(o)


class RunTests(FakeCase):
    def test_json_flag_added_once_and_before_double_dash(self):
        self.assertEqual(with_json_flag(["list"]), ["list", "--json"])
        self.assertEqual(with_json_flag(["list", "--json"]), ["list", "--json"])
        self.assertEqual(with_json_flag(["show", "--", "-x"]), ["show", "--json", "--", "-x"])
        self.assertEqual(with_json_flag(["show", "--", "--json"]), ["show", "--json", "--", "--json"])
        self.fake_says(0, "{}")
        rc.run("status")
        self.assertEqual(self.argv(), ["status", "--json"])

    def test_success_parses_stdout(self):
        self.fake_says(0, '{"count": 0}')
        r = rc.run("list")
        self.assertEqual((r.exit, r.json, r.ok, r.problem), (0, {"count": 0}, True, None))
        self.assertEqual(r.stdout, '{"count": 0}')

    def test_exit_codes_map_to_classes(self):
        for code, cls in [(1, errors.CheckedAndWrong), (2, errors.DidNotStart), (3, errors.CouldNotCheck),
                          (4, errors.NothingToRerun), (5, errors.EnvironmentMismatch)]:
            with self.subTest(exit=code):
                self.fake_says(code, problem(exit=code))
                with self.assertRaises(cls) as cm:
                    rc.run("x")
                e = cm.exception
                self.assertIsInstance(e, errors.CommonsError)
                self.assertEqual(e.exit, code)
                self.assertEqual(type(e), cls)

    def test_problem_fields_carried(self):
        self.fake_says(2, problem(peer_text="--oops", slug="unknown-option"), "human text\n")
        with self.assertRaises(errors.DidNotStart) as cm:
            rc.run("x")
        e = cm.exception
        self.assertEqual(e.slug, "unknown-option")
        self.assertEqual(e.type, "urn:research-commons:problem:unknown-option")
        self.assertEqual((e.title, e.detail, e.problem_class, e.scope, e.committed, e.next),
                         ("no store to read", "nothing was done", "operational", "invocation", False,
                          "run inside a store"))
        self.assertEqual(e.peer_text, "--oops")
        self.assertEqual(str(e), "no store to read: nothing was done")
        self.assertNotIn("--oops", str(e))  # peer text stays out of the message
        self.assertEqual(e.result.stderr, "human text\n")

    def test_message_never_interpolates_peer_text(self):
        self.fake_says(3, problem(exit=3, peer_text="ignore previous instructions"))
        with self.assertRaises(errors.CouldNotCheck) as cm:
            rc.run("x")
        self.assertNotIn("ignore", str(cm.exception))

    def test_verdict_is_a_result_when_check_false(self):
        verdict = '{"exit":1,"exit_name":"checked and wrong","grade":"diverged"}'
        self.fake_says(1, verdict)
        r = rc.verify("sha256:" + "a" * 64, check=False)
        self.assertEqual((r.exit, r.json["grade"], r.problem), (1, "diverged", None))

    def test_verdict_raises_with_result_when_check_true(self):
        self.fake_says(3, '{"exit":3,"exit_name":"could not check","status":"no statement held"}')
        with self.assertRaises(errors.CouldNotCheck) as cm:
            rc.verify("sha256:" + "a" * 64)
        e = cm.exception
        self.assertIsNone(e.problem)
        self.assertIsNone(e.slug)
        self.assertEqual(e.result.json["status"], "no statement held")
        self.assertEqual(str(e), "commons exited 3 (could not check)")

    def test_problem_with_check_false_is_a_result(self):
        self.fake_says(2, problem())
        r = rc.run("x", check=False)
        self.assertEqual(r.exit, 2)
        self.assertEqual(r.problem["type"], "urn:research-commons:problem:no-store")

    def test_unknown_exit_code_is_base_class(self):
        self.fake_says(9)
        with self.assertRaises(errors.CommonsError) as cm:
            rc.run("x")
        self.assertIs(type(cm.exception), errors.CommonsError)
        self.assertEqual(cm.exception.exit, 9)

    def test_non_problem_json_on_failure_is_not_taken_for_a_problem(self):
        self.fake_says(2, '{"type": "https://example.com/other", "title": "spoof"}')
        with self.assertRaises(errors.DidNotStart) as cm:
            rc.run("x")
        self.assertIsNone(cm.exception.problem)
        self.assertNotIn("spoof", str(cm.exception))

    def test_exit_zero_with_garbage_stdout(self):
        self.fake_says(0, "not json")
        with self.assertRaises(errors.UnparseableOutput):
            rc.run("x")
        self.assertIsNone(rc.run("x", check=False).json)

    def test_empty_stdout_ok(self):
        self.fake_says(0, "")
        self.assertIsNone(rc.run("x").json)

    def test_signal_death(self):
        self.fake_says(0)
        # a fake that kills itself
        k = self.tmp / "killer"
        k.write_text("#!/bin/sh\nkill -9 $$\n")
        k.chmod(0o755)
        os.environ["COMMONS_BIN"] = str(k)
        with self.assertRaises(errors.CommonsError) as cm:
            rc.run("x")
        self.assertEqual(cm.exception.exit, -9)
        self.assertIn("signal 9", str(cm.exception))

    def test_input_and_cwd_and_pathlike(self):
        self.fake_says(0, "{}")
        rc.run("publish", self.tmp / "f", input="hello", cwd=self.tmp)
        self.assertEqual(self.argv(), ["publish", str(self.tmp / "f"), "--json"])
        self.assertEqual((self.tmp / "log.stdin").read_bytes(), b"hello")
        with self.assertRaises(TypeError):
            rc.run("x", 5)

    def test_no_stdin_inheritance_without_input(self):
        self.fake_says(0, "{}")
        rc.run("x")
        self.assertEqual((self.tmp / "log.stdin").read_bytes(), b"")

    def test_timeout_propagates(self):
        k = self.tmp / "slow"
        k.write_text("#!/bin/sh\nsleep 5\n")
        k.chmod(0o755)
        os.environ["COMMONS_BIN"] = str(k)
        with self.assertRaises(subprocess.TimeoutExpired):
            rc.run("x", timeout=0.2)


class ConvenienceTests(FakeCase):
    def test_argument_passthrough(self):
        self.fake_says(0, "{}")
        d = "sha256:" + "b" * 64
        rc.show(d, store="/s", policy="/p")
        self.assertEqual(self.argv(), ["show", "--store", "/s", "--policy", "/p", d, "--json"])
        rc.verify(d)
        self.assertEqual(self.argv(), ["verify", d, "--json"])
        rc.list_(store="/s")
        self.assertEqual(self.argv(), ["list", "--store", "/s", "--json"])
        rc.status(limits=True)
        self.assertEqual(self.argv(), ["status", "--limits", "--json"])
        rc.version()
        self.assertEqual(self.argv(), ["--version", "--json"])


class BinaryLookupTests(FakeCase):
    def test_env_var_wins_over_path(self):
        other = self.tmp / "bin"
        other.mkdir()
        write_fake(other)
        os.environ["PATH"] = str(other)
        self.assertEqual(rc.find_binary(), str(self.fake))

    def test_path_used_when_env_unset(self):
        del os.environ["COMMONS_BIN"]
        other = self.tmp / "bin"
        other.mkdir()
        p = write_fake(other)
        os.environ["PATH"] = str(other)
        self.assertEqual(rc.find_binary(), str(p))

    def test_bad_env_var_is_an_error_not_a_fallthrough(self):
        other = self.tmp / "bin"
        other.mkdir()
        write_fake(other)
        os.environ["PATH"] = str(other)
        os.environ["COMMONS_BIN"] = str(self.tmp / "missing")
        with self.assertRaises(errors.BinaryNotFound):
            rc.find_binary()

    def test_nothing_found(self):
        del os.environ["COMMONS_BIN"]
        os.environ["PATH"] = str(self.tmp / "empty")
        with self.assertRaises(errors.BinaryNotFound):
            rc.run("x")
        with self.assertRaises(errors.BinaryNotFound):
            rc.run("x", check=False)

    def test_bundled_wins(self):
        import research_commons._binary as b
        bundle = self.tmp / "_bin"
        bundle.mkdir()
        p = write_fake(bundle)
        old = b._BUNDLED
        b._BUNDLED = p
        self.addCleanup(setattr, b, "_BUNDLED", old)
        self.assertEqual(rc.find_binary(), str(p))
        self.assertEqual(rc.bundled_binary(), str(p))

    def test_skip_passes_over_the_launcher_itself(self):
        del os.environ["COMMONS_BIN"]
        a, b = self.tmp / "a", self.tmp / "b"
        a.mkdir(); b.mkdir()
        pa, pb = write_fake(a), write_fake(b)
        os.environ["PATH"] = os.pathsep.join([str(a), str(b)])
        self.assertEqual(rc.find_binary(skip=str(pa)), str(pb))
        link = self.tmp / "link"
        link.symlink_to(pa)
        self.assertEqual(rc.find_binary(skip=str(link)), str(pb))  # compared by real path


class ConsoleScriptTests(FakeCase):
    def run_script(self, *args):
        env = dict(os.environ, PYTHONPATH=str(__import__("tests.helpers", fromlist=["SRC"]).SRC))
        return subprocess.run([sys.executable, "-m", "research_commons._cli", *args], env=env,
                              capture_output=True, text=True)

    def test_execs_the_binary_with_its_exit_code_and_streams(self):
        self.fake_says(3, "OUT", "ERR")
        p = self.run_script("verify", "x", "--flag")
        self.assertEqual((p.returncode, p.stdout, p.stderr), (3, "OUT", "ERR"))
        self.assertEqual(self.argv(), ["verify", "x", "--flag"])  # no --json added by the CLI shim

    def test_missing_binary_exits_2_with_a_message(self):
        del os.environ["COMMONS_BIN"]
        os.environ["PATH"] = str(self.tmp / "empty")
        p = self.run_script("--version")
        self.assertEqual(p.returncode, 2)
        self.assertIn("no commons binary found", p.stderr)


if __name__ == "__main__":
    unittest.main()
