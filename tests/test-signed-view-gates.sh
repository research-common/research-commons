#!/usr/bin/env bash
# Reader-only phase 1 integration: manually signed views, real CLI/Git gates.
# No network, containers, operational keys, or production-code modifications.
# Run: bash tests/test-signed-view-gates.sh
# Alternate tool: COMMONS=/abs/baseline/bin/commons bash tests/test-signed-view-gates.sh
# Optional unittest names/flags may follow the script path.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 - "$REPO" "$@" <<'PY'
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
REPO = Path(sys.argv.pop(1))
COMMONS = Path(os.environ.get("COMMONS", str(REPO / "bin/commons"))).resolve()
# The fixture projection is independent of the selected tool, so a baseline
# without view readers/gates fails assertions rather than fixture construction.
sys.path.insert(0, str(REPO / "lib"))
from manifest_views import view_digest


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class SignedViewGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = tempfile.TemporaryDirectory(prefix="commons-signed-view-gates-")
        cls.addClassCleanup(cls.lab.cleanup)
        cls.lab_root = Path(cls.lab.name)
        cls.env = dict(os.environ)
        for name in list(cls.env):
            if name.startswith("COMMONS_") and name != "COMMONS_VIEM_DIR":
                cls.env.pop(name)
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            cls.env.pop(name, None)
        # The legacy COMMONS_REQUIRE_SIG flag requires an attestation rather than
        # a publisher statement; keep that separate policy out of these cases.
        cls.env.update(
            COMMONS_AGENT="view-test", COMMONS_EXEC="sandbox", COMMONS_REQUIRE_SIG="0",
            GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
            GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_NAME="View regression",
            GIT_AUTHOR_EMAIL="view-test@example.invalid",
            GIT_COMMITTER_NAME="View regression",
            GIT_COMMITTER_EMAIL="view-test@example.invalid",
            PYTHONDONTWRITEBYTECODE="1")
        cls.keys = []
        cls.addresses = []
        cls.serial = 0
        for number in (3, 4, 5):
            key = cls.lab_root / ("disposable-%d.key" % number)
            key.write_text("0x" + format(number, "064x") + "\n")
            key.chmod(0o600)
            cls.keys.append(key)
            cls.addresses.append(cls.sign("disposable fixture identity",
                                          len(cls.keys) - 1)["address"])
        cls.template = cls.lab_root / "template"
        # All fixtures and Git histories live under the disposable lab.
        cls.cli(cls.lab_root, "hub", "init", str(cls.template),
                "--name", "signed-view-regression", expected=0)
        cls.register(cls.template)
        cls.aid = cls.publish(cls.template, "baseline synthetic report\n")
        cls.legacy = cls.read_manifest(cls.template, cls.aid)
        if "publisher_sig" in cls.legacy:
            raise AssertionError("phase 1 fixture expects the legacy CLI writer")
        cls.legacy_ref = cls.commit(cls.template, "legacy signed publish")
        viewed = cls.attach_view(cls.template, cls.legacy)
        cls.append_event(cls.template, viewed)
        cls.viewed_ref = cls.commit(cls.template, "owner adopts a signed view")
        cls.viewed = cls.read_manifest(cls.template, cls.aid)

    @classmethod
    def environment(cls, root, key=0):
        return dict(cls.env, COMMONS_ROOT=str(root),
                    COMMONS_SIGNING_KEY=str(cls.keys[key]))

    @classmethod
    def command(cls, root, argv, key=0, expected=None):
        result = subprocess.run([str(arg) for arg in argv], cwd=root,
                                env=cls.environment(root, key), text=True,
                                capture_output=True, timeout=30)
        if expected is not None and result.returncode != expected:
            raise AssertionError(
                "%s\nexpected exit %s, got %s\n%s%s" %
                (" ".join(map(str, argv)), expected, result.returncode,
                 result.stdout, result.stderr))
        return result

    @classmethod
    def cli(cls, root, *args, key=0, expected=None):
        return cls.command(root, [sys.executable, COMMONS, *args],
                       key=key, expected=expected)

    @classmethod
    def git(cls, root, *args):
        return cls.command(root, ["git", "-c", "commit.gpgsign=false",
                              "-c", "core.hooksPath=" + os.devnull, *args],
                       expected=0).stdout.strip()

    @classmethod
    def register(cls, root):
        for index, address in enumerate(cls.addresses):
            cls.cli(root, "peer", "add", address, "--agent-id",
                    "owner" if index == 0 else "foreign", "--trust", "full",
                    expected=0)

    @classmethod
    def sign(cls, message, key=0):
        result = subprocess.run(
            ["node", str(REPO / "lib/sign-message.mjs"), "--stdin"],
            input=message, text=True, capture_output=True, timeout=20,
            env=cls.environment(cls.lab_root, key))
        if result.returncode:
            raise AssertionError("real test signer failed: " + result.stderr)
        return json.loads(result.stdout)

    @classmethod
    def namespace(cls, root, key=0):
        # Used only to build fixtures, never to replace a gate or crypto verifier.
        os.environ.update(cls.environment(root, key))
        return runpy.run_path(str(COMMONS))

    @classmethod
    def stamp(cls):
        cls.serial += 1
        return (datetime(2026, 1, 1, tzinfo=timezone.utc)
                + timedelta(seconds=cls.serial)).strftime("%Y-%m-%dT%H:%M:%SZ")

    @classmethod
    def manifest_path(cls, root, aid):
        return root / "registry/artifacts" / (aid + ".json")

    @classmethod
    def read_manifest(cls, root, aid):
        return json.loads(cls.manifest_path(root, aid).read_text())

    @classmethod
    def write_manifest(cls, root, manifest):
        cls.manifest_path(root, manifest["id"]).write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n")

    @classmethod
    def attach_view(cls, root, manifest, key=0, version="manifest-view/1"):
        manifest = copy.deepcopy(manifest)
        namespace = cls.namespace(root, key)
        statement = {
            "rc": "manifest/1", "id": manifest["id"],
            "sha256": manifest["content"]["sha256"],
            "view_version": version, "view": view_digest(manifest),
            "ts": cls.stamp(),
        }
        signed = cls.sign(canonical(statement), key)
        manifest["publisher_sig"] = {
            "addr": signed["address"], "sig": signed["signature"],
            "statement": statement,
        }
        # Even an unsupported-version fixture has a real signature.
        if not namespace["_verify_message"](
                canonical(statement), signed["signature"], signed["address"])[0]:
            raise AssertionError("publisher fixture signature must really verify")
        cls.write_manifest(root, manifest)
        return manifest

    @classmethod
    def append_event(cls, root, manifest, key=0, view=True, digest=None,
                     action="republish"):
        namespace = cls.namespace(root, key)
        event = {
            "schema": namespace["SCHEMA"], "agent": "view-test",
            "action": action, "id": manifest["id"],
            "sha256": manifest["content"]["sha256"], "ts": cls.stamp(),
        }
        if view:
            event["view"] = (digest if digest is not None else
                             manifest["publisher_sig"]["statement"]["view"])
        addr, sig, sig2 = namespace["sign_entry"](event, dual=True)
        event.update(addr=addr, sig=sig, sig2=sig2)
        if not namespace["verify_entry"](event, sig, addr)[0]:
            raise AssertionError("ledger fixture signatures must really verify")
        namespace["ledger_commit"](event)

    @classmethod
    def publish(cls, root, body, key=0, kind="synthesis"):
        cls.serial += 1
        path = cls.lab_root / ("content-%d.txt" % cls.serial)
        path.write_text(body)
        args = ["publish", kind, str(path), "Synthetic view gate report",
                "--license", "Apache-2.0"]
        if kind == "synthesis":
            args += ["--tier", "T2", "--criteria", "manual test review"]
        output = cls.cli(root, *args, key=key, expected=0)
        matches = re.findall(r"\b(?:sy|sk|cl)-[0-9a-f]{8}\b", output.stdout)
        if not matches:
            raise AssertionError("publish returned no artifact id: " + output.stdout)
        return matches[0]

    @classmethod
    def commit(cls, root, message):
        cls.git(root, "add", "-A")
        cls.git(root, "commit", "-qm", message)
        return cls.git(root, "rev-parse", "HEAD")

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(prefix="case-", dir=self.lab_root))
        self.addCleanup(shutil.rmtree, self.case)
        self.source = self.case / "source"
        shutil.copytree(self.template, self.source)
        self.receiver_root = None

    def receiver(self):
        if self.receiver_root is None:
            self.receiver_root = self.case / "receiver"
            self.git(self.case, "clone", "-q", str(self.source),
                     str(self.receiver_root))
            self.register(self.receiver_root)
        return self.receiver_root

    @staticmethod
    def output(result):
        return result.stdout + result.stderr

    def check(self, base=None, expected=0):
        return self.cli(self.source, "hub", "check", "--base",
                        base or self.viewed_ref, expected=expected)

    def pull(self, expected, dry=False):
        args = ["pull", "origin", "--branch", "main"]
        if dry:
            args.append("--dry-run")
        return self.cli(self.receiver(), *args, expected=expected)

    def assert_refused(self, diagnostic, base=None):
        root = self.receiver()
        before = self.git(root, "rev-parse", "HEAD")
        manifest_before = self.read_manifest(root, self.aid)
        check = self.check(base=base, expected=1)
        self.assertRegex(self.output(check).lower(), diagnostic)
        # Exercise the actual merge path; a refusal must leave held data intact.
        pull = self.pull(expected=1)
        self.assertRegex(self.output(pull).lower(), diagnostic)
        self.assertEqual(self.git(root, "rev-parse", "HEAD"), before)
        self.assertEqual(self.read_manifest(root, self.aid), manifest_before)

    def assert_readers(self, state, label, fail=False):
        show = self.cli(self.source, "show", self.aid, expected=0)
        self.assertIn(label, self.output(show))
        listing = self.cli(self.source, "list", "--json", expected=0)
        row = next(row for row in json.loads(listing.stdout) if row["id"] == self.aid)
        self.assertEqual(row["view_state"], state)
        self.assertTrue(row["view_detail"])
        brief = self.cli(self.source, "status", self.aid, "--brief", expected=3)
        self.assertEqual(len(brief.stdout.splitlines()), 1)
        self.assertIn("view=" + state, brief.stdout)
        if fail:
            self.assertRegex(brief.stdout, r"\[T[0-3]\?\]")
        verify = self.cli(self.source, "verify", self.aid,
                          expected=1 if fail else 3)
        self.assertIn(label, self.output(verify))
        fsck = self.cli(self.source, "fsck", "--views", expected=1 if fail else 0)
        self.assertIn(label, self.output(fsck))

    def test_valid_view_readers_and_audit(self):
        self.assert_readers("signed", "metadata signed")

    def test_view_reader_resolves_helpers_through_cli_symlink(self):
        shim = self.lab_root / "commons-shim"
        shim.symlink_to(COMMONS)
        shown = self.command(self.source, [sys.executable, shim, "show", self.aid],
                             expected=0)
        self.assertIn("metadata signed", shown.stdout)

    def test_altered_view_show_json_verify_and_fsck(self):
        manifest = self.read_manifest(self.source, self.aid)
        manifest["title"] = "tampered title"
        self.write_manifest(self.source, manifest)
        self.assert_readers("altered", "METADATA ALTERED", fail=True)

    def test_stripped_view_show_json_verify_and_fsck(self):
        manifest = self.read_manifest(self.source, self.aid)
        manifest.pop("publisher_sig")
        self.write_manifest(self.source, manifest)
        self.assert_readers("stripped", "METADATA SIGNATURE REMOVED", fail=True)

    def test_unknown_version_readers_report_unknown(self):
        self.attach_view(self.source, self.viewed, version="manifest-view/999")
        self.assert_readers("unknown-view-version", "unknown view version")

    def test_owner_adopts_legacy_view_with_new_event_and_repeated_hub_checks(self):
        self.git(self.source, "reset", "--hard", self.legacy_ref)
        manifest = self.attach_view(self.source, self.legacy)
        self.append_event(self.source, manifest)
        self.commit(self.source, "adopt owner view with bound event")
        self.check(base=self.legacy_ref)
        self.check(base=self.legacy_ref)
        self.check(base=self.git(self.source, "rev-parse", "HEAD"))

    def test_foreign_view_event_cannot_strip_legacy_or_freeze_its_owner(self):
        self.git(self.source, "reset", "--hard", self.legacy_ref)
        root = self.receiver()
        # A real v2 statement in the foreign signer's own append-only log.
        # Nothing about the held artifact or its publisher signature is changed.
        self.append_event(self.source, self.legacy, key=1, digest="0" * 64)
        poisoned_base = self.commit(self.source, "foreign claims a view of owner's legacy artifact")
        self.assert_readers("legacy", "UNSIGNED METADATA (legacy)")
        self.check(base=self.legacy_ref)
        self.cli(self.source, "hub", "check", expected=0)
        self.pull(expected=0, dry=True)
        self.pull(expected=0)
        self.assertEqual(self.read_manifest(root, self.aid), self.legacy)
        # The foreign line is now held. It must not freeze A's adoption authority.
        manifest = self.attach_view(self.source, self.legacy)
        self.append_event(self.source, manifest)
        self.commit(self.source, "owner adopts after foreign view claim is held")
        self.check(base=poisoned_base)
        self.pull(expected=0)
        self.assertEqual(self.read_manifest(root, self.aid)["publisher_sig"],
                         manifest["publisher_sig"])

    def test_owner_view_event_still_detects_stripping_of_legacy_manifest(self):
        self.git(self.source, "reset", "--hard", self.legacy_ref)
        self.receiver()
        self.append_event(self.source, self.legacy, digest="0" * 64)
        self.commit(self.source, "owner view evidence without publisher statement")
        self.assert_readers("stripped", "METADATA SIGNATURE REMOVED", fail=True)
        self.assert_refused(r"metadata.*stripped", base=self.legacy_ref)
        self.cli(self.source, "hub", "check", expected=1)
        namespace = self.namespace(self.source)
        held = namespace["_ledger_raw_lines_local"]()
        gate = namespace["ManifestEditGate"](held, held, lambda _digest: None)
        self.assertEqual(gate._authority(self.aid, self.legacy), set())
        self.assertIn("stripped", " ".join(
            gate.view_problems(self.aid, self.legacy, self.legacy) or []))

    def test_extra_publisher_cannot_hide_stripping_from_held_owner(self):
        for already_held in (False, True):
            with self.subTest(stripping_already_held=already_held):
                self.setUp()
                self.git(self.source, "reset", "--hard", self.legacy_ref)
                if not already_held:
                    self.receiver()
                self.append_event(self.source, self.legacy, digest="0" * 64)
                owner_evidence = self.commit(self.source, "owner view evidence without statement")
                if already_held:
                    self.receiver()
                # A second publisher makes HEAD ambiguous, but cannot erase the
                # receiver/base's established owner or its stripping evidence.
                self.append_event(self.source, self.legacy, key=1,
                                  action="publish", view=False)
                self.commit(self.source, "extra publish attempts to hide owner's view evidence")
                self.assert_refused(r"metadata.*stripped",
                                    base=owner_evidence if already_held else self.legacy_ref)

    def test_incoming_history_cannot_hide_already_held_view_evidence(self):
        for unrelated in (False, True):
            with self.subTest(unrelated_history=unrelated):
                self.setUp()
                self.git(self.source, "reset", "--hard", self.legacy_ref)
                self.append_event(self.source, self.legacy,
                                  digest=view_digest(self.legacy))
                self.commit(self.source, "held owner view evidence with statement missing")
                root = self.receiver()
                before = self.git(root, "rev-parse", "HEAD")
                self.git(self.source, "reset", "--hard", self.legacy_ref)
                self.publish(self.source, "new report alongside an old legacy copy\n", key=1)
                if unrelated:
                    shutil.rmtree(self.source / ".git")
                    self.git(self.source, "init", "-q", "-b", "main")
                self.commit(self.source, "incoming legacy copy omits held view event")
                rejected = self.pull(expected=1)
                self.assertRegex(self.output(rejected).lower(), r"metadata.*stripped")
                self.assertEqual(self.git(root, "rev-parse", "HEAD"), before)
                self.assertEqual(self.read_manifest(root, self.aid), self.legacy)

    def test_collection_maintainer_authority_survives_foreign_view_event(self):
        self.git(self.source, "reset", "--hard", self.legacy_ref)
        aid = self.publish(self.source, json.dumps({
            "schema": "rc.v1", "scope": "view authority regression",
            "maintainers": [{"addr": self.addresses[1]}],
            "includes": [],
        }), kind="collection")
        legacy = self.read_manifest(self.source, aid)
        collection_base = self.commit(self.source, "legacy collection with pinned maintainer")
        root = self.receiver()
        self.append_event(self.source, legacy, key=2, digest="0" * 64)
        foreign_base = self.commit(self.source, "outsider claims a collection view")
        self.check(base=collection_base)
        self.cli(self.source, "hub", "check", expected=0)
        self.pull(expected=0)
        listing = json.loads(self.cli(root, "list", "--json", expected=0).stdout)
        self.assertEqual(next(row for row in listing if row["id"] == aid)["view_state"],
                         "legacy")
        manifest = self.attach_view(self.source, legacy, key=1)
        self.append_event(self.source, manifest, key=1)
        self.commit(self.source, "pinned maintainer adopts after foreign claim")
        self.check(base=foreign_base)
        self.pull(expected=0)
        self.assertEqual(self.read_manifest(root, aid)["publisher_sig"],
                         manifest["publisher_sig"])

    def test_collection_maintainer_view_event_detects_stripping(self):
        self.git(self.source, "reset", "--hard", self.legacy_ref)
        aid = self.publish(self.source, json.dumps({
            "schema": "rc.v1", "scope": "view stripping regression",
            "maintainers": [{"addr": self.addresses[1]}],
            "includes": [],
        }), kind="collection")
        legacy = self.read_manifest(self.source, aid)
        self.append_event(self.source, legacy, key=1, digest="0" * 64)
        self.commit(self.source, "maintainer view evidence without statement")
        listing = json.loads(self.cli(self.source, "list", "--json", expected=0).stdout)
        self.assertEqual(next(row for row in listing if row["id"] == aid)["view_state"],
                         "stripped")
        self.cli(self.source, "hub", "check", expected=1)

    def test_legacy_browse_rows_are_compact_but_show_keeps_detail(self):
        self.git(self.source, "reset", "--hard", self.legacy_ref)
        for command in (("list",), ("search", "Synthetic view gate report")):
            row = self.cli(self.source, *command, expected=0).stdout
            self.assertIn("view=legacy", row)
            self.assertNotIn("UNSIGNED METADATA", row)
            self.assertNotIn("no publisher signature", row)
        self.assertIn("UNSIGNED METADATA (legacy): no publisher signature",
                      self.cli(self.source, "show", self.aid, expected=0).stdout)

    def test_legacy_browse_does_not_start_ledger_signature_verifier(self):
        self.git(self.source, "reset", "--hard", self.legacy_ref)
        wrappers = self.case / "wrappers"
        wrappers.mkdir()
        calls = self.case / "node-calls.txt"
        node = wrappers / "node"
        node.write_text(
            "#!" + sys.executable + "\n"
            "import os, sys\n"
            "with open(" + repr(str(calls)) + ", 'a') as stream:\n"
            "    stream.write(sys.argv[1] + '\\n')\n"
            "os.execv(" + repr(shutil.which("node")) + ", ['node'] + sys.argv[1:])\n")
        node.chmod(0o755)
        env = dict(self.environment(self.source),
                   PATH=str(wrappers) + os.pathsep + self.env["PATH"])
        # All fixture events remain genuinely signed. The wrapper records only
        # which helper executes; it neither stubs nor bypasses cryptography.
        for command in (("list",), ("search", "Synthetic view gate report")):
            result = subprocess.run([sys.executable, str(COMMONS), *command],
                                    cwd=self.source, env=env, capture_output=True,
                                    text=True, timeout=30)
            self.assertEqual(result.returncode, 0, self.output(result))
            self.assertFalse(calls.exists(), calls.read_text() if calls.exists() else "")

    def test_owner_updates_view_with_new_event_and_repeated_checks(self):
        manifest = copy.deepcopy(self.viewed)
        manifest["title"] = "owner's revised title"
        manifest = self.attach_view(self.source, manifest)
        self.append_event(self.source, manifest)
        self.commit(self.source, "owner signs revised metadata")
        self.check()
        self.check()
        self.check(base=self.git(self.source, "rev-parse", "HEAD"))

    def test_foreign_valid_signature_and_bound_event_cannot_replace_held_view(self):
        self.receiver()
        manifest = copy.deepcopy(self.viewed)
        manifest["title"] = "foreign replacement"
        manifest = self.attach_view(self.source, manifest, key=1)
        self.append_event(self.source, manifest, key=1)
        self.commit(self.source, "foreign signs replacement and matching event")
        self.assert_refused(r"metadata.*(unauthorised|unauthorized|authority)")

    def test_ride_along_edit_after_genuine_signed_view_republish_is_refused(self):
        self.receiver()
        manifest = self.read_manifest(self.source, self.aid)
        manifest["title"] = "owner's legitimate update"
        manifest = self.attach_view(self.source, manifest)
        self.append_event(self.source, manifest)
        self.commit(self.source, "genuine signed view update")
        manifest["license"] = "CC0-1.0"
        self.write_manifest(self.source, manifest)
        self.commit(self.source, "third party rides on genuine republish")
        self.assert_refused(r"metadata.*altered")

    def test_removed_signature_refused_even_with_signed_legacy_republish(self):
        self.receiver()
        manifest = self.read_manifest(self.source, self.aid)
        manifest.pop("publisher_sig")
        self.write_manifest(self.source, manifest)
        # Legacy manifest authorisation: content-bound republish without view.
        # Keep sig2 so the independent ledger floor cannot mask this regression.
        self.append_event(self.source, manifest, view=False)
        self.commit(self.source, "strip signature with content-only republish")
        self.assert_refused(r"metadata.*(stripped|signature removed)")

    def test_replacement_view_needs_new_matching_event(self):
        self.receiver()
        manifest = copy.deepcopy(self.viewed)
        manifest["title"] = "owner-signed but not ledger-backed"
        self.attach_view(self.source, manifest)
        self.commit(self.source, "new statement without a new view event")
        self.assert_refused(r"matching.*(event|publish)|event.*matching")

    def test_unknown_version_gates_refuse(self):
        self.receiver()
        manifest = self.attach_view(
            self.source, self.viewed, version="manifest-view/999")
        self.append_event(self.source, manifest)
        self.commit(self.source, "unsupported signed view version")
        self.assert_refused(r"unknown.view.version|unsupported view version")

    def incoming_view(self, key=0, kind="synthesis"):
        aid = self.publish(self.source, "new incoming synthetic report\n",
                           key=key, kind=kind)
        manifest = self.attach_view(
            self.source, self.read_manifest(self.source, aid), key=key)
        return aid, manifest

    def test_pull_new_viewed_manifest_and_repeat_accepted_view_checks(self):
        root = self.receiver()
        aid, manifest = self.incoming_view()
        self.append_event(self.source, manifest, action="publish")
        self.commit(self.source, "new valid viewed manifest")
        self.check()
        before = self.git(root, "rev-parse", "HEAD")
        self.pull(expected=0, dry=True)
        self.assertEqual(self.git(root, "rev-parse", "HEAD"), before)
        self.assertFalse(self.manifest_path(root, aid).exists())
        self.pull(expected=0)
        held = self.read_manifest(root, aid)
        self.assertEqual(held["publisher_sig"], manifest["publisher_sig"])
        self.assertEqual(held["title"], manifest["title"])
        accepted = self.git(root, "rev-parse", "HEAD")
        self.pull(expected=0)
        self.assertEqual(self.git(root, "rev-parse", "HEAD"), accepted)
        self.cli(root, "hub", "check", "--base", self.viewed_ref, expected=0)
        listing = json.loads(self.cli(root, "list", "--json", expected=0).stdout)
        self.assertEqual(next(row for row in listing if row["id"] == aid)["view_state"],
                         "signed")

    def test_pull_new_incoming_view_checks_real_statement_signature(self):
        root = self.receiver()
        aid, manifest = self.incoming_view()
        self.append_event(self.source, manifest)
        # A real owner signature over a different statement: correct shape and
        # matching digest/event, but cryptographic verification must fail.
        manifest["publisher_sig"]["sig"] = self.sign(canonical({
            **manifest["publisher_sig"]["statement"], "ts": self.stamp(),
        }))["signature"]
        self.write_manifest(self.source, manifest)
        self.commit(self.source, "invalid incoming publisher signature")
        self.assert_refused(r"metadata.*altered")
        self.assertFalse(self.manifest_path(root, aid).exists())

    def test_pull_new_view_requires_exact_event_digest_and_same_signer(self):
        for variant in ("missing", "wrong-digest", "wrong-signer"):
            with self.subTest(binding=variant):
                self.setUp()
                root = self.receiver()
                aid, manifest = self.incoming_view()
                if variant == "wrong-digest":
                    self.append_event(self.source, manifest, digest="f" * 64)
                elif variant == "wrong-signer":
                    self.append_event(self.source, manifest, key=1)
                self.commit(self.source, "incoming view binding " + variant)
                self.assert_refused(r"matching.*(event|publish)|event.*matching")
                self.assertFalse(self.manifest_path(root, aid).exists())

    def test_pull_new_view_applies_receivers_local_signer_trust(self):
        for trust in ("none", "datasets-only", "unregistered"):
            with self.subTest(receiver_trust=trust):
                self.setUp()
                root = self.receiver()
                # datasets-only permits reports, but cannot supply a method.
                kind = "skill" if trust == "datasets-only" else "synthesis"
                aid, manifest = self.incoming_view(key=1, kind=kind)
                self.append_event(self.source, manifest, key=1)
                self.commit(self.source, "cryptographically valid foreign report")
                self.check()  # Hub signature checks have no receiver trust policy.
                if trust == "unregistered":
                    self.cli(root, "peer", "rm", self.addresses[1], expected=0)
                else:
                    self.cli(root, "peer", "add", self.addresses[1],
                             "--agent-id", "foreign", "--trust", trust,
                             "--force", expected=0)
                before = self.git(root, "rev-parse", "HEAD")
                result = self.pull(expected=1)
                self.assertRegex(self.output(result).lower(),
                                 r"trust|unregistered|registered|matching.*event")
                self.assertEqual(self.git(root, "rev-parse", "HEAD"), before)
                self.assertFalse(self.manifest_path(root, aid).exists())
                self.assertEqual(self.read_manifest(root, self.aid), self.viewed)

    def test_pull_owner_adoption_from_legacy_and_repeated_pull(self):
        self.git(self.source, "reset", "--hard", self.legacy_ref)
        root = self.receiver()
        manifest = self.attach_view(self.source, self.legacy)
        self.append_event(self.source, manifest)
        self.commit(self.source, "legacy owner adopts signed view")
        self.check(base=self.legacy_ref)
        self.pull(expected=0)
        self.assertEqual(self.read_manifest(root, self.aid)["publisher_sig"],
                         manifest["publisher_sig"])
        accepted = self.git(root, "rev-parse", "HEAD")
        self.pull(expected=0)
        self.assertEqual(self.git(root, "rev-parse", "HEAD"), accepted)

    def test_accepted_view_survives_later_unrelated_incoming_commit(self):
        root = self.receiver()
        # No new event for the already accepted view: only another artifact.
        aid = self.publish(self.source, "unrelated later synthetic report\n")
        self.commit(self.source, "new unrelated artifact after view acceptance")
        self.check()
        before = self.git(root, "rev-parse", "HEAD")
        self.pull(expected=0)
        self.assertNotEqual(self.git(root, "rev-parse", "HEAD"), before)
        self.assertEqual(self.read_manifest(root, self.aid)["publisher_sig"],
                         self.viewed["publisher_sig"])
        self.assertTrue(self.manifest_path(root, aid).exists())
        self.cli(root, "hub", "check", "--base", self.viewed_ref, expected=0)


unittest.main(verbosity=2)
PY
