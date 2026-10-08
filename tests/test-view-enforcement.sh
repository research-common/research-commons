#!/usr/bin/env bash
# Phase 3 integration: real CLI, Git histories, and EIP-191 signatures; no mocks.
# Legacy fixtures use unsigned CLI publishing plus authenticated ledger events.
# No historical commit objects are needed, including in shallow/squashed checkouts.
# Run: bash tests/test-view-enforcement.sh [unittest test names/flags]
# Red baseline: COMMONS=/abs/phase1/bin/commons bash tests/test-view-enforcement.sh
# If needed, COMMONS_VIEM_DIR=/dir/containing/node_modules supplies the real signer.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 - "$REPO" "$@" <<'PY'
import copy
from contextlib import contextmanager
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
MISSING = object()
VIEW_REQUIRED = r"signed[- ]views? required|require_signed_views"
POLICY_REFUSED = r"\.commons-hub"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class ViewEnforcementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = tempfile.TemporaryDirectory(prefix="commons-view-enforcement-")
        cls.addClassCleanup(cls.lab.cleanup)
        cls.lab_root = Path(cls.lab.name)
        cls.env = dict(os.environ)
        for name in list(cls.env):
            if name.startswith("COMMONS_") and name != "COMMONS_VIEM_DIR":
                cls.env.pop(name)
            if name.startswith("GIT_"):
                cls.env.pop(name)
        cls.env.update(
            COMMONS_AGENT="view-enforcement-test", COMMONS_EXEC="sandbox",
            COMMONS_REQUIRE_SIG="0", COMMONS_REQUIRE_VIEWS="0",
            GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
            GIT_TERMINAL_PROMPT="0", GIT_AUTHOR_NAME="View enforcement regression",
            GIT_AUTHOR_EMAIL="view-test@example.invalid",
            GIT_COMMITTER_NAME="View enforcement regression",
            GIT_COMMITTER_EMAIL="view-test@example.invalid",
            PYTHONDONTWRITEBYTECODE="1")
        cls.env.setdefault("COMMONS_VIEM_DIR", str(REPO))
        cls.fixture_cli = REPO / "bin/commons"
        # Fixture projection and crypto are independent of selected COMMONS and
        # Git history. A baseline can fail assertions without breaking setup.
        sys.path.insert(0, str(REPO / "lib"))
        from manifest_views import view_digest
        cls.view_digest = staticmethod(view_digest)
        cls.serial = 0
        cls.keys, cls.addresses = [], []
        for number in (3, 4):
            key = cls.lab_root / ("disposable-%d.key" % number)
            key.write_text("0x" + format(number, "064x") + "\n")
            key.chmod(0o600)
            cls.keys.append(key)
            cls.addresses.append(cls.sign("disposable fixture identity",
                                          key=len(cls.keys) - 1)["address"])
        cls.template = cls.lab_root / "legacy-template"
        cls.cli(cls.lab_root, "hub", "init", str(cls.template),
                "--name", "view-enforcement-regression",
                tool=cls.fixture_cli, expected=0)
        cls.register(cls.template)
        cls.aid = cls.publish_legacy(cls.template, "held legacy synthetic report\n")
        cls.legacy = cls.read_manifest(cls.template, cls.aid)
        cls.legacy_ref = cls.commit(cls.template, "synthetic legacy with signed publish")
        cls.required_template = cls.lab_root / "required-template"
        shutil.copytree(cls.template, cls.required_template)
        cls.set_policy(cls.required_template, True)
        cls.required_ref = cls.commit(cls.required_template, "reviewed view enforcement")

    @classmethod
    def environment(cls, root, key=0, env=None):
        result = dict(cls.env, COMMONS_ROOT=str(root),
                      COMMONS_SIGNING_KEY=str(cls.keys[key]))
        result.update(env or {})
        return result

    @classmethod
    def command(cls, root, argv, key=0, env=None, expected=None):
        result = subprocess.run(
            [str(arg) for arg in argv], cwd=root,
            env=cls.environment(root, key, env), text=True,
            capture_output=True, timeout=45)
        if expected is not None and result.returncode != expected:
            raise AssertionError("%s\nexpected exit %s, got %s\n%s%s" %
                                 (" ".join(map(str, argv)), expected,
                                  result.returncode, result.stdout, result.stderr))
        return result

    @classmethod
    def cli(cls, root, *args, key=0, env=None, tool=None, expected=None):
        return cls.command(root, [sys.executable, tool or COMMONS, *args],
                           key=key, env=env, expected=expected)

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
                    tool=cls.fixture_cli, expected=0)

    @classmethod
    def sign(cls, message, key=0):
        result = subprocess.run(
            ["node", str(REPO / "lib/sign-message.mjs"), "--stdin"],
            input=message, text=True, capture_output=True, timeout=20,
            env=cls.environment(cls.lab_root, key))
        if result.returncode:
            raise AssertionError("real EIP-191 fixture signer failed: " + result.stderr)
        return json.loads(result.stdout)

    @classmethod
    @contextmanager
    def fixture_namespace(cls, root, key=0, tool=None):
        previous = dict(os.environ)
        try:
            os.environ.clear()
            os.environ.update(cls.environment(root, key))
            yield runpy.run_path(str(tool or cls.fixture_cli))
        finally:
            os.environ.clear()
            os.environ.update(previous)

    @classmethod
    def stamp(cls):
        cls.serial += 1
        return (datetime(2026, 1, 1, tzinfo=timezone.utc)
                + timedelta(seconds=cls.serial)).strftime("%Y-%m-%dT%H:%M:%SZ")

    @staticmethod
    def manifest_path(root, aid):
        return root / "registry/artifacts" / (aid + ".json")

    @classmethod
    def read_manifest(cls, root, aid):
        return json.loads(cls.manifest_path(root, aid).read_text())

    @classmethod
    def write_manifest(cls, root, manifest):
        cls.manifest_path(root, manifest["id"]).write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n")

    @staticmethod
    def set_policy(root, value):
        path = root / ".commons-hub"
        marker = json.loads(path.read_text())
        if value is MISSING:
            marker.pop("require_signed_views", None)
        else:
            marker["require_signed_views"] = value
        path.write_text(json.dumps(marker, sort_keys=True, indent=2) + "\n")

    @classmethod
    def publish_legacy(cls, root, body, key=0):
        cls.serial += 1
        path = cls.lab_root / ("content-%d.txt" % cls.serial)
        path.write_text(body + "fixture serial %d\n" % cls.serial)
        unsigned_log = root / "registry/ledger/local-unsigned.jsonl"
        held_unsigned = unsigned_log.read_bytes() if unsigned_log.exists() else None
        result = cls.cli(
            root, "publish", "synthesis", str(path), "Synthetic enforcement report",
            "--license", "Apache-2.0", "--tier", "T2",
            "--criteria", "manual test review", tool=cls.fixture_cli,
            env={"COMMONS_SIGNING_KEY": ""}, expected=0)
        matches = re.findall(r"\bsy-[0-9a-f]{8}\b", result.stdout)
        if not matches:
            raise AssertionError("legacy publish returned no artifact id: " + result.stdout)
        aid = matches[0]
        if "publisher_sig" in cls.read_manifest(root, aid):
            raise AssertionError("unsigned fixture publish must not create a signed view")
        # Keep the CLI's manifest/blob unchanged. Replace only its freshly made
        # unsigned publish with a real dual-signed content-only publish; otherwise
        # a hub's independent unsigned-ledger gate would mask the view regression.
        after = unsigned_log.read_bytes()
        before = held_unsigned or b""
        if not after.startswith(before):
            raise AssertionError("unsigned fixture publish rewrote held ledger bytes")
        new_lines = [json.loads(line) for line in after[len(before):].splitlines()
                     if line.strip()]
        if len(new_lines) != 1 or new_lines[0].get("id") != aid \
                or new_lines[0].get("action") != "publish" or new_lines[0].get("sig"):
            raise AssertionError("fixture may replace only its own unsigned publish event")
        if held_unsigned is None:
            unsigned_log.unlink()
        else:
            unsigned_log.write_bytes(held_unsigned)
        cls.append_event(root, cls.read_manifest(root, aid), key=key,
                         view=False, action="publish")
        return aid

    @classmethod
    def attach_view(cls, root, manifest, key=0):
        # Same manual statement + bound event fixture as test-signed-view-gates.
        manifest = copy.deepcopy(manifest)
        statement = {
            "rc": "manifest/1", "id": manifest["id"],
            "sha256": manifest["content"]["sha256"],
            "view_version": "manifest-view/1", "view": cls.view_digest(manifest),
            "ts": cls.stamp(),
        }
        signed = cls.sign(canonical(statement), key)
        manifest["publisher_sig"] = {
            "addr": signed["address"], "sig": signed["signature"],
            "statement": statement,
        }
        with cls.fixture_namespace(root, key) as ns:
            if not ns["_verify_message"](
                    canonical(statement), signed["signature"], signed["address"])[0]:
                raise AssertionError("publisher fixture must really verify")
        cls.write_manifest(root, manifest)
        return manifest

    @classmethod
    def append_event(cls, root, manifest, key=0, view=True, action="republish"):
        with cls.fixture_namespace(root, key) as ns:
            event = {
                "schema": ns["SCHEMA"], "agent": "view-enforcement-test",
                "action": action, "id": manifest["id"],
                "sha256": manifest["content"]["sha256"], "ts": cls.stamp(),
            }
            if view:
                event["view"] = manifest["publisher_sig"]["statement"]["view"]
            addr, sig, sig2 = ns["sign_entry"](event, dual=True)
            event.update(addr=addr, sig=sig, sig2=sig2)
            if not ns["verify_entry"](event, sig, addr)[0]:
                raise AssertionError("dual-signed ledger fixture must really verify")
            ns["ledger_commit"](event)

    @classmethod
    def signed_note(cls, root, key=1, dual=False, invalid_v2=False):
        # A distinct note, not a stripped copy of another event: replay checks
        # must not conceal the new enforcement rule about earlier v1 prefixes.
        with cls.fixture_namespace(root, key) as ns:
            event = {
                "schema": ns["SCHEMA"], "agent": "view-enforcement-test",
                "action": "note", "id": cls.aid,
                "sha256": cls.legacy["content"]["sha256"], "ts": cls.stamp(),
            }
            signed = ns["sign_entry"](event, dual=dual)
            event.update(addr=signed[0], sig=signed[1])
            if dual:
                event["sig2"] = signed[2]
            if not ns["verify_entry"](event, event["sig"], event["addr"])[0]:
                raise AssertionError("note fixture must really verify")
            if invalid_v2:
                # Genuine signature for different bytes: valid sig, invalid sig2.
                event["sig2"] = cls.sign("different v2 note payload", key)["signature"]
        return event

    def commit_note(self, root, event):
        with self.fixture_namespace(root) as ns:
            ns["ledger_commit"](copy.deepcopy(event))

    def v2_floor_problems(self, held, head):
        with self.fixture_namespace(self.source, tool=COMMONS) as ns:
            self.assertIn("enforced_v2_event_problems", ns,
                          "selected CLI has no phase 3 event-floor helper")
            return ns["enforced_v2_event_problems"](
                [canonical(e) for e in held], [canonical(e) for e in head])

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
        self.base = self.legacy_ref
        self.receiver_root = None
        self.pull_env = {}

    def required_source(self):
        shutil.rmtree(self.source)
        shutil.copytree(self.required_template, self.source)
        self.base = self.required_ref

    def receiver(self, mode=None):
        if self.receiver_root is None:
            self.receiver_root = self.case / "receiver"
            self.git(self.case, "clone", "-q", str(self.source), str(self.receiver_root))
            self.register(self.receiver_root)
        if mode == "env":
            self.pull_env = {"COMMONS_REQUIRE_VIEWS": "1"}
        elif mode == "local":
            self.set_policy(self.receiver_root, True)
            self.commit(self.receiver_root, "receiver locally enables signed views")
        return self.receiver_root

    def incoming(self, signed=False, key=0):
        aid = self.publish_legacy(self.source, "new incoming synthetic report\n", key=key)
        if signed:
            manifest = self.attach_view(self.source, self.read_manifest(self.source, aid),
                                        key=key)
            self.append_event(self.source, manifest, key=key, action="publish")
        self.commit(self.source, "new %s artifact" % ("viewed" if signed else "legacy"))
        return aid

    def modify_legacy(self, signed=False, key=0):
        manifest = self.read_manifest(self.source, self.aid)
        manifest["title"] = "revised synthetic metadata"
        if signed:
            manifest = self.attach_view(self.source, manifest, key=key)
        else:
            self.write_manifest(self.source, manifest)
        # The unsigned-view negative has a genuine authorised content-only
        # republish; it must fail for view policy, not missing legacy authority.
        self.append_event(self.source, manifest, key=key, view=signed)
        self.commit(self.source, "authorised %s republish" % ("viewed" if signed else "legacy"))
        return manifest

    def symlink_legacy(self):
        path = self.manifest_path(self.source, self.aid)
        held = path.read_bytes()
        (self.source / "registry/legacy-cache.json").write_bytes(held)
        path.unlink()
        path.symlink_to("../legacy-cache.json")
        self.commit(self.source, "replace regular legacy manifest with identical symlink")
        rel = str(path.relative_to(self.source))
        self.assertEqual(self.git(self.source, "diff", "--name-status", "--no-renames",
                                  self.base, "HEAD", "--", rel), "T\t" + rel)
        self.assertEqual(path.read_bytes(), held)
        self.assertEqual(self.read_manifest(self.source, self.aid), self.legacy)
        self.assertEqual(self.git(self.source, "ls-files", "--", "registry/legacy-cache.json"),
                         "registry/legacy-cache.json")

    @staticmethod
    def output(result):
        return result.stdout + result.stderr

    def check(self, expected=0, full=False, base=None):
        args = ["hub", "check"]
        if not full:
            args += ["--base", base or self.base]
        result = self.cli(self.source, *args, expected=expected)
        self.assertNotIn("Traceback", self.output(result))
        return result

    def assert_hub_view_refused(self, aid=None, **kwargs):
        result = self.check(expected=1, **kwargs)
        self.assertRegex(self.output(result).lower(), VIEW_REQUIRED)
        self.assertIn(aid or self.aid, self.output(result))

    def pull(self, expected=0, flags=()):
        result = self.cli(self.receiver(), "pull", "origin", "--branch", "main",
                          *flags, env=self.pull_env, expected=expected)
        self.assertNotIn("Traceback", self.output(result))
        return result

    def snapshot(self, root):
        # Include every held manifest, ledger, and blob, plus the policy itself.
        files = {}
        for directory in ("registry/artifacts", "registry/ledger", "store"):
            for path in sorted((root / directory).rglob("*")):
                if path.is_file():
                    files[str(path.relative_to(root))] = path.read_bytes()
        for name in (".commons-hub", "registry/ledger.jsonl", "registry/peers.json"):
            path = root / name
            files[name] = path.read_bytes() if path.exists() else None
        return self.git(root, "rev-parse", "HEAD"), files

    def assert_pull_refused(self, diagnostic=VIEW_REQUIRED, aid=None, flags=()):
        root = self.receiver()
        before = self.snapshot(root)
        result = self.pull(expected=1, flags=flags)
        self.assertRegex(self.output(result).lower(), diagnostic)
        if aid:
            self.assertIn(aid, self.output(result))
        self.assertEqual(self.snapshot(root), before, "refusal changed held data or policy")
        self.assertFalse((root / ".git/MERGE_HEAD").exists(), "refusal left a merge in progress")
        return result

    def test_hub_required_added_legacy_refused(self):
        self.required_source()
        self.assert_hub_view_refused(self.incoming())

    def test_hub_required_modified_legacy_refused(self):
        self.required_source()
        self.modify_legacy()
        self.assert_hub_view_refused()

    def test_hub_required_legacy_symlink_typechange_refused(self):
        self.required_source()
        self.symlink_legacy()
        self.assert_hub_view_refused()

    def test_pull_required_legacy_symlink_typechange_force_refused(self):
        self.receiver("local")
        self.symlink_legacy()
        self.assert_pull_refused(aid=self.aid, flags=("--force",))

    def test_hub_required_unchanged_legacy_grandfathered_with_base(self):
        self.required_source()
        self.check()
        self.check(base=self.git(self.source, "rev-parse", "HEAD"))

    def test_hub_required_full_audit_refuses_held_legacy(self):
        self.required_source()
        self.assert_hub_view_refused(full=True)

    def test_hub_required_full_audit_accepts_all_adopted(self):
        self.required_source()
        self.modify_legacy(signed=True)
        self.check(full=True)

    def test_hub_required_new_view_accepts_and_preserves_held_legacy(self):
        self.required_source()
        aid = self.incoming(signed=True)
        self.check()
        self.assertEqual(self.read_manifest(self.source, self.aid), self.legacy)
        self.assertIn("publisher_sig", self.read_manifest(self.source, aid))

    def test_hub_required_owner_adopts_then_updates(self):
        self.required_source()
        self.modify_legacy(signed=True)
        self.check()
        self.base = self.git(self.source, "rev-parse", "HEAD")
        manifest = self.read_manifest(self.source, self.aid)
        manifest["title"] = "second owner-signed view"
        manifest = self.attach_view(self.source, manifest)
        self.append_event(self.source, manifest)
        self.commit(self.source, "owner updates signed view")
        self.check()

    def test_hub_head_activation_grandfathers_untouched_legacy(self):
        self.set_policy(self.source, True)
        self.commit(self.source, "activate enforcement only")
        self.check()

    def test_hub_head_activation_accepts_valid_touched_view(self):
        self.set_policy(self.source, True)
        self.modify_legacy(signed=True)
        self.check()

    def test_hub_adopting_keys_do_not_grant_foreign_authority(self):
        self.required_source()
        marker = json.loads((self.source / ".commons-hub").read_text())
        marker["adopting_keys"] = [self.addresses[1]]
        (self.source / ".commons-hub").write_text(canonical(marker) + "\n")
        self.modify_legacy(signed=True, key=1)
        result = self.check(expected=1)
        self.assertRegex(self.output(result).lower(), r"metadata.*(unauthorised|unauthorized|authority)")

    def test_pull_optional_legacy_addition_and_authorised_edit_allowed(self):
        self.receiver()
        aid = self.incoming()
        self.modify_legacy()
        self.pull()
        self.assertTrue(self.manifest_path(self.receiver_root, aid).exists())
        self.assertEqual(self.read_manifest(self.receiver_root, self.aid)["title"],
                         "revised synthetic metadata")

    def test_pull_common_base_allows_receiver_only_marker_edits(self):
        root = self.receiver("local")
        marker = json.loads((root / ".commons-hub").read_text())
        marker["name"] = "receiver reviewed local name"
        marker["adopting_keys"] = [self.addresses[1]]
        (root / ".commons-hub").write_text(canonical(marker) + "\n")
        self.commit(root, "subsequent receiver-only configuration")
        marker_before = (root / ".commons-hub").read_bytes()
        aid = self.incoming(signed=True)
        self.pull()
        self.assertEqual((root / ".commons-hub").read_bytes(), marker_before)
        self.assertEqual(self.read_manifest(root, self.aid), self.legacy)
        self.assertIn("publisher_sig", self.read_manifest(root, aid))

    def test_pull_common_base_does_not_hide_peer_change_matching_receiver(self):
        root = self.receiver("local")
        # Equal tips still changed on the peer since their common base.
        self.set_policy(self.source, True)
        self.commit(self.source, "peer copies receiver policy")
        self.assertEqual((root / ".commons-hub").read_bytes(),
                         (self.source / ".commons-hub").read_bytes())
        self.incoming(signed=True)
        self.assert_pull_refused(POLICY_REFUSED, flags=("--allow-code", "--force"))

    def test_v2_floor_helper_unseen_v1_prefix_before_distinct_v2_refused(self):
        v1 = self.signed_note(self.source)
        v2 = self.signed_note(self.source, dual=True)
        problems = self.v2_floor_problems([], [v1, v2])
        self.assertEqual(len(problems), 1)
        self.assertIn("v1-only", problems[0])
        self.assertIn(self.addresses[1].lower(), problems[0].lower())

    def test_v2_floor_helper_valid_held_v2_establishes_evidence(self):
        v2 = self.signed_note(self.source, dual=True)
        v1 = self.signed_note(self.source)
        self.assertEqual(len(self.v2_floor_problems([v2], [v1])), 1)

    def test_v2_floor_helper_invalid_head_v2_does_not_establish_evidence(self):
        v1 = self.signed_note(self.source)
        invalid = self.signed_note(self.source, dual=True, invalid_v2=True)
        self.assertEqual(self.v2_floor_problems([], [v1, invalid]), [])

    def test_v2_floor_helper_invalid_held_v2_does_not_establish_evidence(self):
        invalid = self.signed_note(self.source, dual=True, invalid_v2=True)
        v1 = self.signed_note(self.source)
        self.assertEqual(self.v2_floor_problems([invalid], [v1]), [])

    def test_v2_floor_helper_unchanged_held_v1_grandfathered(self):
        v1 = self.signed_note(self.source)
        v2 = self.signed_note(self.source, dual=True)
        self.assertEqual(self.v2_floor_problems([v1], [v1, v2]), [])

    def test_v2_floor_helper_unknown_v1_sender_has_no_upgrade_evidence(self):
        v1 = self.signed_note(self.source)
        other_key_v2 = self.signed_note(self.source, key=0, dual=True)
        self.assertEqual(self.v2_floor_problems([], [v1, other_key_v2]), [])

    def test_hub_v2_floor_unseen_v1_prefix_before_distinct_v2_refused(self):
        self.required_source()
        self.commit_note(self.source, self.signed_note(self.source))
        self.commit_note(self.source, self.signed_note(self.source, dual=True))
        self.commit(self.source, "unseen v1 prefix before distinct valid v2")
        result = self.check(expected=1)
        self.assertRegex(self.output(result).lower(), r"signed views required: v1-only")
        self.assertNotIn("replayed signed ledger event", self.output(result).lower())
        self.assertNotIn("after this signer's v2 floor", self.output(result).lower())

    def test_hub_v2_floor_unchanged_held_v1_grandfathered(self):
        self.required_source()
        self.commit_note(self.source, self.signed_note(self.source))
        self.base = self.commit(self.source, "held unknown sender's valid v1 note")
        self.commit_note(self.source, self.signed_note(self.source, dual=True))
        self.commit(self.source, "same sender upgrades to v2")
        self.check()

    def test_hub_v2_floor_unknown_sender_v1_remains_allowed(self):
        self.required_source()
        self.commit_note(self.source, self.signed_note(self.source))
        self.commit(self.source, "unknown sender has no v2 upgrade evidence")
        self.check()

    def test_pull_unrelated_identical_marker_accepts_valid_data(self):
        root = self.receiver()
        marker_before = (root / ".commons-hub").read_bytes()
        shutil.rmtree(self.source / ".git")
        self.git(self.source, "init", "-q", "-b", "main")
        self.commit(self.source, "independent history with same marker")
        # Different signer log: extending the same log on two independent
        # histories produces a Git add/add collision unrelated to marker policy.
        aid = self.incoming(signed=True, key=1)
        self.pull()
        self.assertEqual((root / ".commons-hub").read_bytes(), marker_before)
        self.assertTrue(self.manifest_path(root, aid).exists())


# Generate individually named unittest cases so counts include each policy value,
# touched-manifest direction, receiver mode, and bypass flag combination.
def hub_optional_case(policy, touched):
    def test(self):
        if policy is not MISSING:
            self.set_policy(self.source, policy)
            self.base = self.commit(self.source, "reviewed optional views")
        self.incoming() if touched == "added" else self.modify_legacy()
        self.check()
    return test


def hub_sticky_case(change, touched):
    def test(self):
        if change != "activate":
            self.required_source()
        if change == "delete_marker":
            (self.source / ".commons-hub").unlink()
        else:
            self.set_policy(self.source, {
                "activate": True, "disable": False, "remove_flag": MISSING,
            }[change])
        aid = self.incoming() if touched == "added" else self.aid
        if touched == "modified":
            self.modify_legacy()
        self.assert_hub_view_refused(aid)
    return test


def malformed_case(value, location, raw=False):
    def test(self):
        root = self.receiver() if location == "receiver" else self.source
        if raw:
            (root / ".commons-hub").write_text(value)
        else:
            self.set_policy(root, value)
        if location == "base":
            self.base = self.commit(root, "invalid base policy")
            (root / ".commons-hub").write_bytes((self.template / ".commons-hub").read_bytes())
            self.commit(root, "repair HEAD policy")
        elif location == "head":
            self.commit(root, "invalid HEAD policy")
        if location == "receiver":
            self.incoming(signed=True)
            result = self.assert_pull_refused(POLICY_REFUSED, flags=("--allow-code", "--force"))
        else:
            result = self.check(expected=1)
            self.assertRegex(self.output(result).lower(), POLICY_REFUSED)
        self.assertRegex(self.output(result).lower(),
                         r"boolean|policy|json object|metadata")
    return test


def enforced_pull_case(mode, touched, flags=()):
    def test(self):
        self.receiver(mode)
        aid = self.incoming() if touched == "added" else self.aid
        if touched == "modified":
            self.modify_legacy()
        self.assert_pull_refused(aid=aid, flags=flags)
    return test


def valid_pull_case(mode, adoption=False):
    def test(self):
        root = self.receiver(mode)
        marker_before = (root / ".commons-hub").read_bytes()
        manifest = self.modify_legacy(signed=True) if adoption else None
        aid = self.aid if adoption else self.incoming(signed=True)
        before = self.snapshot(root)
        self.pull(flags=("--dry-run",))
        self.assertEqual(self.snapshot(root), before)
        self.pull()
        held = self.read_manifest(root, aid)
        if adoption:
            self.assertEqual(held["publisher_sig"], manifest["publisher_sig"])
        else:
            self.assertEqual(self.read_manifest(root, self.aid), self.legacy)
        self.assertIn("publisher_sig", held)
        self.assertEqual((root / ".commons-hub").read_bytes(), marker_before)
        accepted = self.snapshot(root)
        self.pull()
        self.assertEqual(self.snapshot(root), accepted, "repeat pull changed held data")
    return test


def force_view_integrity_case(mode, foreign=False):
    def test(self):
        if foreign:
            self.modify_legacy(signed=True)
        root = self.receiver(mode)
        if foreign:
            # The replacement has a real foreign signature and its own bound
            # event, but that key cannot acquire the held owner's authority.
            self.modify_legacy(signed=True, key=1)
            aid = self.aid
            diagnostic = r"unauthorised|unauthorized|authority"
        else:
            aid = self.publish_legacy(self.source, "signed incoming without view event\n")
            self.attach_view(self.source, self.read_manifest(self.source, aid))
            self.commit(self.source, "valid view signature without matching view event")
            diagnostic = r"matching.*(event|publish)|event.*matching"
        self.assert_pull_refused(diagnostic, aid=aid, flags=("--force",))
        if not foreign:
            self.assertFalse(self.manifest_path(root, aid).exists())
    return test


def v2_floor_pull_case(mode, grandfather=False):
    def test(self):
        if grandfather:
            self.commit_note(self.source, self.signed_note(self.source))
            self.commit(self.source, "already-held v1 note")
        root = self.receiver(mode)
        if not grandfather:
            self.commit_note(self.source, self.signed_note(self.source))
        self.commit_note(self.source, self.signed_note(self.source, dual=True))
        self.commit(self.source, "later distinct valid v2 from same signer")
        if grandfather:
            self.pull()
            self.assertEqual(self.read_manifest(root, self.aid), self.legacy)
        else:
            result = self.assert_pull_refused(
                r"signed views required: v1-only", flags=("--force", "--allow-code"))
            self.assertNotIn("replayed signed ledger event", self.output(result).lower())
            self.assertNotIn("after this signer's v2 floor", self.output(result).lower())
    return test


def v2_floor_local_evidence_case(mode):
    def test(self):
        root = self.receiver(mode)
        self.commit_note(root, self.signed_note(root, dual=True))
        self.commit(root, "receiver alone holds valid v2 signer evidence")
        self.commit_note(self.source, self.signed_note(self.source))
        self.commit(self.source, "peer sends unseen v1 without its own v2 evidence")
        self.assert_pull_refused(r"signed views required: v1-only", flags=("--force",))
    return test


def v2_floor_unknown_sender_case(mode):
    def test(self):
        root = self.receiver(mode)
        self.commit_note(self.source, self.signed_note(self.source))
        self.commit(self.source, "incoming v1 sender has no upgrade evidence")
        self.pull()
        self.assertEqual(self.read_manifest(root, self.aid), self.legacy)
    return test


def force_view_trust_case(mode, unregistered=False):
    def test(self):
        root = self.receiver(mode)
        if unregistered:
            self.cli(root, "peer", "rm", self.addresses[0], expected=0)
        else:
            self.cli(root, "peer", "add", self.addresses[0], "--agent-id", "owner",
                     "--trust", "none", "--force", expected=0)
        aid = self.incoming(signed=True)
        self.assert_pull_refused(r"trusted|matching.*event|trust", aid=aid, flags=("--force",))
        self.assertFalse(self.manifest_path(root, aid).exists())
    return test


def marker_change_case(change, flags=(), unrelated=False):
    def test(self):
        if change in ("disable", "remove_flag"):
            self.required_source()
        if change == "add_marker":
            (self.source / ".commons-hub").unlink()
            self.commit(self.source, "legacy layout without marker")
        root = self.receiver()
        if unrelated:
            # Same valid fixture, genuinely independent root commit.
            shutil.rmtree(self.source / ".git")
            self.git(self.source, "init", "-q", "-b", "main")
            self.commit(self.source, "independently bootstrapped peer")
        path = self.source / ".commons-hub"
        if change == "delete_marker":
            path.unlink()
        elif change == "add_marker":
            path.write_bytes((self.template / ".commons-hub").read_bytes())
        elif change == "disable":
            self.set_policy(self.source, False)
        elif change == "remove_flag":
            self.set_policy(self.source, MISSING)
        elif change == "activate":
            self.set_policy(self.source, True)
        elif change == "malformed":
            path.write_text('{"require_signed_views":')
        elif change == "formatting":
            path.write_text(canonical(json.loads(path.read_text())) + "\n")
        else:
            marker = json.loads(path.read_text())
            if change == "adopting_keys":
                marker["adopting_keys"] = [self.addresses[1]]
            else:
                marker["name"] = "peer-controlled hub name"
            path.write_text(canonical(marker) + "\n")
        # Pair policy attack with otherwise valid data to prove atomic refusal.
        aid = self.incoming(signed=True)
        self.assert_pull_refused(POLICY_REFUSED, flags=flags)
        self.assertFalse(self.manifest_path(root, aid).exists())
    return test


for label, policy in (("absent", MISSING), ("false", False)):
    for touched in ("added", "modified"):
        setattr(ViewEnforcementTests, "test_hub_optional_%s_%s" % (label, touched),
                hub_optional_case(policy, touched))

for change in ("activate", "disable", "remove_flag", "delete_marker"):
    for touched in ("added", "modified"):
        setattr(ViewEnforcementTests, "test_hub_%s_still_requires_%s" % (change, touched),
                hub_sticky_case(change, touched))

for label, value, raw in (
        ("null", None, False), ("zero", 0, False), ("one", 1, False),
        ("string_true", "true", False), ("string_false", "false", False),
        ("array", [], False), ("object", {}, False),
        ("invalid_json", '{"require_signed_views":', True),
        ("nonobject_json", "[]\n", True)):
    for location in ("head", "base", "receiver"):
        setattr(ViewEnforcementTests, "test_policy_%s_%s_refused" % (location, label),
                malformed_case(value, location, raw))

for mode in ("env", "local"):
    for touched in ("added", "modified"):
        for label, flags in (("normal", ()), ("dry_run", ("--dry-run",)),
                             ("force", ("--force",)),
                             ("force_allow_code", ("--force", "--allow-code"))):
            setattr(ViewEnforcementTests, "test_pull_%s_%s_legacy_%s_refused" %
                    (mode, touched, label), enforced_pull_case(mode, touched, flags))
    for label, adoption in (("new_view", False), ("owner_adoption", True)):
        setattr(ViewEnforcementTests, "test_pull_%s_%s_dry_merge_repeat" % (mode, label),
                valid_pull_case(mode, adoption))
    for label, foreign in (("foreign_bound_replacement", True),
                           ("new_view_without_event", False)):
        setattr(ViewEnforcementTests, "test_pull_%s_force_%s_refused" % (mode, label),
                force_view_integrity_case(mode, foreign))
    for label, grandfather in (("unseen_v1_prefix_refused", False),
                               ("held_v1_grandfathered", True)):
        setattr(ViewEnforcementTests, "test_pull_%s_v2_floor_%s" % (mode, label),
                v2_floor_pull_case(mode, grandfather))
    setattr(ViewEnforcementTests, "test_pull_%s_v2_floor_receiver_only_evidence_refused" % mode,
            v2_floor_local_evidence_case(mode))
    setattr(ViewEnforcementTests, "test_pull_%s_v2_floor_unknown_sender_v1_allowed" % mode,
            v2_floor_unknown_sender_case(mode))
    for label, unregistered in (("unregistered", True), ("trust_none", False)):
        setattr(ViewEnforcementTests, "test_pull_%s_force_view_signer_%s_refused" % (mode, label),
                force_view_trust_case(mode, unregistered))

for change in ("activate", "disable", "remove_flag", "adopting_keys", "delete_marker",
               "add_marker", "rename", "formatting", "malformed"):
    for label, flags in (("normal", ()), ("force_allow_code", ("--allow-code", "--force"))):
        setattr(ViewEnforcementTests, "test_pull_peer_marker_%s_%s_refused" % (change, label),
                marker_change_case(change, flags))

for change in ("rename", "add_marker", "delete_marker"):
    setattr(ViewEnforcementTests, "test_pull_unrelated_marker_%s_refused" % change,
            marker_change_case(change, ("--allow-code", "--force"), unrelated=True))

unittest.main(verbosity=2)
PY
