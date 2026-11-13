"""The wire-format test vectors, through the wrapper and a real ``commons``.

The only CLI path that takes one received statement is ``pull`` of a one-statement package, so that is the
path used: each positive vector (signed lines, both algorithms) must be admitted and then be readable with
``show``; each negative vector that is a *delivered line* (N1-N5) must be refused with its class and reason.
The remaining negatives (N6-N13 and the Ed25519 edge cases) hand a signature and a string to a verifier
function, not a line to the CLI; there is no command for them and none is added here.

Skipped unless the vectors file is in the tree and a binary can be built.
"""

import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.helpers import REPO, build_real  # noqa: F401  (also puts src/ on sys.path)

import research_commons as rc
from research_commons import errors

VECTORS = REPO / "docs" / "DESIGN-notes-wire-format.vectors.json"
SECP_LOG = "0xf71e7c9cce990243bd7fbeff34a4bad1c4750e7a"


def line_of(v):
    """The stored line of a positive vector: the signed payload with ``sig`` inserted beside ``signer``."""
    m = re.match(r"DSSEv1 (\d+) (\S+) (\d+) (.*)$", v["signed_string"], re.S)
    return m.group(4).replace('"signer":', '"sig":"%s","signer":' % v["sig"], 1)


@unittest.skipUnless(VECTORS.is_file(), "wire-format vectors not in this tree")
class VectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.binary = build_real(Path(cls._tmp.name))
        cls._saved = {k: os.environ.pop(k, None) for k in ("COMMONS_STORE", "COMMONS_POLICY", "COMMONS_KEY")}
        cls._saved["COMMONS_BIN"] = os.environ.get("COMMONS_BIN")
        os.environ["COMMONS_BIN"] = cls.binary
        cls.vec = json.loads(VECTORS.read_text())

    @classmethod
    def tearDownClass(cls):
        for k, v in cls._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        cls._tmp.cleanup()

    def pull_one(self, log_dir, name, data):
        """A fresh store and a package of one statement file; returns (store, pull result)."""
        d = Path(tempfile.mkdtemp(dir=self._tmp.name))
        store, pkg = d / "store", d / "pkg"
        rc.run("init", store)
        (pkg / "statements" / log_dir).mkdir(parents=True)
        shutil.copy(store / "rc-store", pkg / "rc-store")
        (pkg / "statements" / log_dir / name).write_text(data)
        return store, rc.run("pull", pkg, "--store", store, check=False)

    def test_positive_vectors_are_admitted_and_readable(self):
        vs = self.vec["ed25519"]["positive"] + self.vec["positive"]
        self.assertGreaterEqual(len(vs), 14)
        for v in vs:
            with self.subTest(vector=v["name"]):
                line = line_of(v)
                signer = re.search(r'"signer":"([^"]+)"', line).group(1)
                store, r = self.pull_one(signer.replace(":", "-"), v["id"], line)
                self.assertEqual(r.exit, 0, r.stdout)
                self.assertEqual(r.json["counts"]["refused"], 0)
                self.assertEqual(len(r.json["objects"]), 1)
                self.assertIn(r.json["objects"][0]["verdict"], ("admitted", "admitted and labelled"))
                # the id the tool read is the id the vector names: show finds the statement under it
                shown = rc.run("show", v["id"], "--store", store)
                self.assertNotEqual(shown.json.get("status"), "no statement held", v["name"])
                # control: an id the store does not hold reads as not held, so the check above can fail
                other = rc.run("show", "0" * 64, "--store", store, check=False)
                self.assertEqual(other.json.get("status"), "no statement held")

    def test_negative_delivered_lines_are_refused_with_their_class(self):
        want = {
            "N1": ("intrinsic", "malformed statement", 'duplicate key "licence"'),
            "N2": ("intrinsic", "malformed statement", "non-finite number"),
            "N3": ("intrinsic", "malformed statement", "non-integer number"),
            "N4": ("operational", "depth limit", "depth limit 16"),
            "N5": ("intrinsic", "line in another key's log", None),
        }
        v1 = self.vec["positive"][0]["id"]
        seen = set()
        for n in self.vec["negative"]:
            if n["name"] not in want:
                continue
            seen.add(n["name"])
            with self.subTest(vector=n["name"]):
                cls, reason, detail = want[n["name"]]
                log = n.get("log", SECP_LOG)
                # control: the same package shape with the untouched V1 line is admitted (the harness reaches the check)
                _, ok = self.pull_one(SECP_LOG, v1, line_of(self.vec["positive"][0]))
                self.assertEqual(ok.exit, 0)
                store, r = self.pull_one(log, v1, n["delivered"])
                self.assertEqual(r.exit, 1, r.stdout)
                with self.assertRaises(errors.CheckedAndWrong):
                    rc.run("pull", store.parent / "pkg", "--store", store)  # check=True: exit 1 raises
                row = r.json["objects"][0]
                self.assertEqual((row["verdict"], row["class"], row["reason"]), ("refused", cls, reason))
                if detail:
                    self.assertIn(detail, row["detail"])
                # nothing landed
                self.assertEqual(rc.list_(store=store).json["count"], 0)
        self.assertEqual(seen, set(want))


if __name__ == "__main__":
    unittest.main()
