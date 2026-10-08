#!/usr/bin/env bash
# Bounded signed-view regressions: real EIP-191 crypto, no network or hub checkout.
# Run: bash tests/test-view-ledger.sh
#
# A per-signer floor is a policy over the log currently held by the reader.
# prev is excluded from sig2: neither physical position nor a transitive chain
# commitment is authenticated by sig2. These tests do NOT claim that a floor
# prevents stripping an unseen first v2, or moving a stripped line before it.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$REPO" <<'PY'
import copy
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

REPO = Path(sys.argv.pop(1))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class SignedViewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = tempfile.TemporaryDirectory(prefix="commons-view-ledger-")
        cls.addClassCleanup(cls.lab.cleanup)
        cls.root = Path(cls.lab.name)
        # Public, disposable test keys; never read a developer's wallet/key.
        cls.keys = []
        for number in (1, 2):
            path = cls.root / ("disposable-%d.key" % number)
            path.write_text("0x" + format(number, "064x") + "\n")
            path.chmod(0o600)
            cls.keys.append(path)
        for name in ("COMMONS_SIGNING_KEY", "COMMONS_AGENT", "COMMONS_EXEC",
                     "COMMONS_REQUIRE_SIG"):
            os.environ.pop(name, None)
        os.environ["COMMONS_ROOT"] = str(cls.root)
        cls.ns = runpy.run_path(str(REPO / "bin/commons"))
        cls.ledger = Path(cls.ns["LEDGER_DIR"])
        cls.ledger.mkdir(parents=True)
        cls.first = cls.event(result="sy-11111111")
        cls.second = cls.event(result="sy-22222222")
        cls.legacy_before = cls.event(
            dual=False, aid="tk-before", ts="2026-01-03T00:00:00Z")
        cls.legacy_after = cls.event(
            dual=False, aid="tk-after", ts="2026-01-01T00:00:00Z")
        cls.other_legacy = cls.event(dual=False, aid="tk-other", key=1)
        cls.publish_before = cls.event(
            dual=False, action="publish", aid="sy-before",
            ts="2026-01-03T00:00:00Z")
        cls.publish_after = cls.event(
            dual=False, action="publish", aid="sy-credit",
            ts="2026-01-01T00:00:00Z")
        cls.other_publish = cls.event(
            dual=False, action="publish", aid="sy-credit", key=1)
        cls.publish_v2 = cls.event(action="publish", aid="sy-valid")
        cls.addr = cls.first["addr"].lower()
        cls.other_addr = cls.other_legacy["addr"].lower()
        Path(cls.ns["PEERS"]).write_text(canonical({
            "schema": cls.ns["SCHEMA"],
            "peers": [{"addr": cls.addr, "agent": "test", "trust": "full",
                       "active": True}],
        }))
        cls.params = {"COMPARATOR": "", "EPSILON": "1e-6"}
        cls.att_v2 = cls.attestation(rc="attestation/2", params=cls.params)
        cls.att_v1 = cls.attestation()
        cls.att_unknown = cls.attestation(rc="attestation/999", params=cls.params)
        cls.view_old = cls.signed_manifest("original", authority=[cls.other_addr])
        cls.view_new = cls.signed_manifest("updated", authority=[cls.other_addr])
        old_digest = cls.view_old["publisher_sig"]["statement"]["view"]
        new_digest = cls.view_new["publisher_sig"]["statement"]["view"]
        cls.view_publish = cls.event(action="publish", aid="ds-aaaaaaaa",
                                     view=old_digest, ts="2026-01-03T00:00:00Z")
        cls.view_update = cls.event(action="republish", aid="ds-aaaaaaaa",
                                    view=new_digest, ts="2026-01-02T00:00:00Z")
        cls.view_restore = cls.event(action="republish", aid="ds-aaaaaaaa",
                                     view=old_digest, ts="2026-01-01T00:00:00Z")
        cls.view_update_again = cls.event(action="republish", aid="ds-aaaaaaaa",
                                          view=new_digest, ts="2026-01-04T00:00:00Z")
        cls.delegate_update = cls.event(action="republish", aid="ds-aaaaaaaa",
                                        view=new_digest, key=1,
                                        ts="2030-01-01T00:00:00Z")

    @classmethod
    def sign(cls, message, key=0, pair=False):
        env = dict(os.environ, COMMONS_SIGNING_KEY=str(cls.keys[key]))
        argv = ["node", str(REPO / "lib/sign-message.mjs"), "--stdin"]
        if pair:
            argv.append("--pair")
        result = subprocess.run(argv, input=message, text=True,
                                capture_output=True, env=env, timeout=20)
        if result.returncode:
            raise RuntimeError("real EIP-191 signer failed: " + result.stderr.strip())
        return json.loads(result.stdout)

    @classmethod
    def event(cls, result="sy-11111111", dual=True, aid="tk-test",
              ts="2026-01-02T00:00:00Z", key=0, action="accept", view=None):
        event = {"schema": cls.ns["SCHEMA"], "action": action, "agent": "test",
                 "id": aid, "sha256": "a" * 64, "ts": ts}
        if action == "accept":
            event.update(task=aid, result=result)
        if view is not None:
            event["view"] = view
        # Pin the wire contract independently of production payload builders.
        v1 = {field: event[field]
              for field in ("action", "agent", "id", "sha256", "ts")}
        if dual:
            out = cls.sign(canonical({"m1": canonical(v1),
                                     "m2": canonical({"rc": "ledger/2",
                                                       "entry": event})}), key, True)
            event["sig2"] = out["signature2"]
        else:
            out = cls.sign(canonical(v1), key)
        event.update(addr=out["address"], sig=out["signature"])
        return event

    @classmethod
    def attestation(cls, rc=None, params=None):
        statement = {"attests": "sy-test", "sha256": "b" * 64,
                     "criteria": "observed comparator output",
                     "observed": "2026-01-02T00:00:00Z"}
        if rc is not None:
            statement["rc"] = rc
        if params is not None:
            statement["params"] = copy.deepcopy(params)
        out = cls.sign(canonical(statement))
        return {"addr": out["address"], "sig": out["signature"],
                "statement": statement}

    @classmethod
    def signed_manifest(cls, title, key=0, authority=None):
        manifest = {"schema": cls.ns["SCHEMA"], "id": "ds-aaaaaaaa",
                    "type": "dataset", "content": {"sha256": "a" * 64},
                    "title": title, "verification": {"tier": "T0"}}
        if authority is not None:
            manifest["authority"] = authority
        statement = {"rc": "manifest/1", "id": manifest["id"],
                     "sha256": manifest["content"]["sha256"],
                     "view_version": "manifest-view/1",
                     "view": cls.ns["view_digest"](manifest),
                     "ts": "2026-01-02T00:00:00Z"}
        signed = cls.sign(canonical(statement), key=key)
        manifest["publisher_sig"] = {"statement": statement,
                                     "addr": signed["address"],
                                     "sig": signed["signature"]}
        return manifest

    def setUp(self):
        for path in self.ledger.glob("*.jsonl"):
            path.unlink()
        # Clear filesystem/derived caches, never replace crypto or reader policy.
        globals_ = self.ns["read_ledger_entries"].__globals__
        globals_["_LEDGER_CACHE"].update(key=None, rows=None)
        globals_["_LINES_CACHE"].update(key=None, rows=None)
        globals_["_FIRSTPUB_CACHE"].update(key=None, map=None, flags=None)
        globals_["_ANCHOR_CACHE"].update(key=None, map=None)

    def write_log(self, addr, events):
        # Build a structurally consistent chain even for tampered/foreign rows.
        lines = []
        previous = None
        for original in events:
            event = dict(original, prev=previous)
            line = canonical(event)
            lines.append(line)
            previous = hashlib.sha256(line.encode()).hexdigest()
        (self.ledger / (addr + ".jsonl")).write_text("\n".join(lines) + "\n")

    def rows(self):
        return [event for event, path in self.ns["read_ledger_entries"]()]

    def verify(self, event):
        self.assertTrue(self.ns["verify_entry"](
            event, event["sig"], event["addr"])[0], "fixture must really verify")

    def stripped(self, alternate=False):
        event = dict(self.first)
        event.pop("sig2")
        if alternate:
            recovery = int(event["sig"][-2:], 16)
            self.assertIn(recovery, (27, 28))
            event["sig"] = event["sig"][:-2] + format(recovery - 27, "02x")
        self.verify(event)
        return event

    def gate(self, base, head):
        return self.ns["replayed_ledger_events"](
            [canonical(event) for event in base],
            [canonical(event) for event in head])

    def assert_stripped_replay(self, replayed):
        self.assertEqual(len(replayed), 1, replayed)
        self.assertRegex(replayed[0], r"^accept tk-test(?: \(stripped sig2\))?$")

    def manifest(self, attestation, params=None):
        verification = {"tier": "T3", "criteria": "observed comparator output",
                        "attested_by": copy.deepcopy(attestation)}
        if params is not None:
            verification["params"] = copy.deepcopy(params)
        return {"id": "sy-test", "content": {"sha256": "b" * 64},
                "verification": verification}

    def assert_state(self, manifest, expected):
        state, detail = self.ns["check_attestation"](manifest)
        self.assertEqual(state, expected, detail)

    def assert_view_state(self, manifest, expected, entries=None):
        state, detail = self.ns["manifest_view_state"](manifest, entries=entries)
        self.assertEqual(state, expected, detail)

    def test_distinct_dual_signed_accepts_have_distinct_identity(self):
        self.verify(self.first)
        self.verify(self.second)
        self.assertEqual(self.first["sig"], self.second["sig"])
        identity = self.ns["authenticated_event_identity"]
        self.assertIsNotNone(identity(self.first))
        self.assertNotEqual(identity(self.first), identity(self.second))

    def test_distinct_dual_signed_accepts_both_fold(self):
        self.write_log(self.addr, [self.first, self.second])
        self.assertCountEqual([event["result"] for event in self.rows()],
                              ["sy-11111111", "sy-22222222"])

    def test_known_v2_stripped_copy_is_dropped_across_logs(self):
        for alternate in (False, True):
            with self.subTest(alternate_recovery_byte=alternate):
                self.setUp()
                self.write_log(self.addr, [self.first])
                # A later foreign log has no own-signer floor for this event:
                # dropping it must use the known original's v1 identity.
                self.write_log("0x" + "f" * 40, [self.stripped(alternate)])
                rows = self.rows()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0].get("sig2"), self.first["sig2"])

    def test_earlier_foreign_log_stripped_copy_cannot_displace_own_v2(self):
        foreign = "0x" + "0" * 40
        self.assertLess(foreign + ".jsonl", self.addr + ".jsonl")
        for alternate in (False, True):
            with self.subTest(alternate_recovery_byte=alternate):
                self.setUp()
                stripped = self.stripped(alternate)
                # Both v1 signatures are genuine, but the stripped copy's
                # unsigned result is forged. Filename order must not retain it.
                stripped["result"] = "sy-forged"
                self.verify(stripped)
                self.write_log(foreign, [stripped])
                self.write_log(self.addr, [self.first, self.second])
                rows = self.rows()
                self.assertCountEqual([event["result"] for event in rows],
                                      ["sy-11111111", "sy-22222222"])
                self.assertTrue(all(event.get("sig2") for event in rows))
                physical = self.ns["ledger_lines"]()
                self.assertCountEqual([event["result"] for event, *_ in physical],
                                      ["sy-11111111", "sy-22222222"])
                self.assertTrue(all(Path(path).name == self.addr + ".jsonl"
                                    for _event, path, _index, _sha in physical))
                snapshot = self.ns["_ledger_raw_lines_local"]()
                self.assert_stripped_replay(
                    self.ns["replayed_ledger_events"]([], snapshot))

    def test_exact_duplicate_v2_is_ignored_by_fold_and_gate(self):
        line = canonical(dict(self.first, prev=None)) + "\n"
        # Byte-identical duplicates (unlike rebuilding prev for an append).
        (self.ledger / (self.addr + ".jsonl")).write_text(line + line)
        self.assertEqual(len(self.rows()), 1)
        self.assertEqual(self.gate([self.first], [self.first]), [])
        self.assertEqual(self.gate([], [self.first, self.first]), [])

    def test_prev_changes_do_not_authenticate_log_position(self):
        changed = dict(self.first, prev="c" * 64)
        self.verify(changed)
        self.assertEqual(self.ns["authenticated_event_identity"](self.first),
                         self.ns["authenticated_event_identity"](changed))

    def test_v1_before_first_valid_own_log_v2_remains_despite_later_timestamp(self):
        self.write_log(self.addr, [self.legacy_before, self.first])
        self.assertCountEqual([event["id"] for event in self.rows()],
                              ["tk-before", "tk-test"])

    def test_v1_after_valid_own_log_v2_is_excluded_despite_earlier_timestamp(self):
        self.write_log(self.addr, [self.first, self.legacy_after])
        self.assertEqual([event["id"] for event in self.rows()], ["tk-test"])

    def test_floor_filters_ledger_lines_preserving_physical_indices_and_hashes(self):
        self.write_log(self.addr, [self.legacy_before, self.first, self.legacy_after])
        physical = self.ns["ledger_lines"]()
        self.assertEqual([(event["id"], index) for event, _path, index, _sha in physical],
                         [("tk-before", 0), ("tk-test", 1)])
        raw = (self.ledger / (self.addr + ".jsonl")).read_bytes().splitlines()
        for _event, path, index, line_sha in physical:
            self.assertEqual(Path(path).name, self.addr + ".jsonl")
            self.assertEqual(line_sha, hashlib.sha256(raw[index]).hexdigest())
        self.assertEqual({event["id"] for event in self.rows()},
                         {event["id"] for event, *_ in physical})

    def test_floor_reaches_first_publisher_index_without_backdated_credit(self):
        for event in (self.publish_before, self.publish_v2,
                      self.publish_after, self.other_publish):
            self.verify(event)
        self.write_log(self.addr,
                       [self.publish_before, self.publish_v2, self.publish_after])
        self.write_log(self.other_addr, [self.other_publish])
        physical = self.ns["ledger_lines"]()
        self.assertNotIn(("sy-credit", self.addr),
                         [(event["id"], event["addr"].lower())
                          for event, *_ in physical])
        self.assertCountEqual([event["id"] for event, *_ in physical],
                              ["sy-before", "sy-valid", "sy-credit"])
        publishers = self.ns["first_publisher_index"]()
        self.assertEqual(publishers["sy-credit"],
                         (self.other_addr,
                          self.ns["parse_ts"](self.other_publish["ts"])))
        self.assertEqual(publishers["sy-before"][0], self.addr)
        self.assertEqual(publishers["sy-valid"][0], self.addr)

    def test_invalid_sig2_does_not_establish_floor(self):
        bad = dict(self.first, sig2=self.second["sig2"])
        self.assertFalse(self.ns["verify_entry"](bad, bad["sig"], bad["addr"])[0])
        self.write_log(self.addr, [bad, self.legacy_after])
        self.assertIn("tk-after", [event["id"] for event in self.rows()])

    def test_malformed_signer_values_cannot_crash_or_establish_floor(self):
        for address in (["a"], 7, {}):
            with self.subTest(address=address):
                bad = dict(self.first, addr=address)
                self.assertIsNone(self.ns["authenticated_event_identity"](bad))
                self.write_log(self.addr, [bad, self.legacy_after])
                self.assertIn("tk-after", [event["id"] for event in self.rows()])

    def test_foreign_log_v2_does_not_establish_any_own_log_floor(self):
        self.verify(self.first)
        self.write_log(self.other_addr, [self.first, self.other_legacy])
        self.write_log(self.addr, [self.legacy_after])
        ids = [event["id"] for event in self.rows()]
        self.assertIn("tk-after", ids, "foreign copy must not floor its signer")
        self.assertIn("tk-other", ids, "foreign copy must not floor the log owner")

    def test_gate_accepts_distinct_v2_with_identical_v1_fields(self):
        self.assertEqual(self.gate([self.first], [self.second]), [])
        self.assertEqual(self.gate([], [self.first, self.second]), [])

    def test_gate_refuses_stripped_copy_across_v1_identity(self):
        for alternate in (False, True):
            with self.subTest(alternate_recovery_byte=alternate):
                stripped = self.stripped(alternate)
                self.assert_stripped_replay(self.gate([self.first], [stripped]))
                self.assert_stripped_replay(self.gate([], [self.first, stripped]))

    def test_gate_refuses_stripped_event_before_original_in_received_head(self):
        for alternate in (False, True):
            with self.subTest(alternate_recovery_byte=alternate):
                stripped = self.stripped(alternate)
                stripped["result"] = "sy-forged"
                self.verify(stripped)
                self.assert_stripped_replay(self.gate([], [stripped, self.first]))
                # Distinct strong events can share the legacy identity. Neither
                # genuine v2 event may be rejected while discarding the weak copy.
                self.assert_stripped_replay(
                    self.gate([], [stripped, self.first, self.second]))

    def test_same_signer_supersession_uses_physical_order_not_timestamps(self):
        self.verify(self.view_publish)
        self.verify(self.view_update)
        self.write_log(self.addr, [self.view_publish, self.view_update])
        self.assert_view_state(self.view_old, "superseded")
        self.assert_view_state(self.view_new, "signed")

    def test_collection_member_rows_flag_altered_signed_metadata(self):
        self.write_log(self.addr, [self.view_publish])
        signed = self.ns["_member_line"](self.view_old)
        self.assertIn("metadata signed", signed)
        altered = self.ns["_member_line"](dict(self.view_old, title="tampered"))
        self.assertIn("METADATA ALTERED", altered)
        self.assertRegex(altered, r"T[0-3]\?")

    def test_restoring_earlier_view_clears_supersession(self):
        for event in (self.view_publish, self.view_update, self.view_restore):
            self.verify(event)
        self.write_log(self.addr,
                       [self.view_publish, self.view_update, self.view_restore])
        # The restoration has an older asserted ts, but the last matching
        # physical event is authoritative for the same signer's held log.
        self.assert_view_state(self.view_old, "signed")
        self.assert_view_state(self.view_new, "superseded")

    def test_preferred_own_copy_keeps_its_physical_view_history_position(self):
        foreign = "0x" + "0" * 40
        self.write_log(foreign, [self.view_restore])
        self.write_log(self.addr,
                       [self.view_publish, self.view_update, self.view_restore])
        snapshot = self.ns["_ledger_raw_lines_local"]()
        gate = self.ns["ManifestEditGate"](snapshot, snapshot, lambda _digest: None)
        self.assert_view_state(self.view_old, "signed", gate.head)
        self.assert_view_state(self.view_new, "superseded", gate.head)

    def test_restored_view_can_be_superseded_again(self):
        self.verify(self.view_update_again)
        self.write_log(self.addr, [self.view_publish, self.view_update,
                                  self.view_restore, self.view_update_again])
        self.assert_view_state(self.view_old, "superseded")
        self.assert_view_state(self.view_new, "signed")

    def test_delegate_log_has_no_supersession_order_relative_to_signer(self):
        self.verify(self.delegate_update)
        for entries in ([self.view_publish, self.delegate_update],
                        [self.delegate_update, self.view_publish]):
            with self.subTest(order=[event["addr"] for event in entries]):
                self.assert_view_state(self.view_old, "signed", entries)
        self.write_log(self.addr, [self.view_publish])
        self.write_log(self.other_addr, [self.delegate_update])
        self.assert_view_state(self.view_old, "signed")
        # Exercise the opposite lexical order too: key 2 owns the manifest,
        # and its delegate's key-1 log sorts after the owner's log.
        delegated_manifest = self.signed_manifest(
            "other signer", key=1, authority=[self.addr])
        event = self.event(action="publish", aid="ds-aaaaaaaa", key=1,
                           view=delegated_manifest["publisher_sig"]["statement"]["view"])
        self.verify(event)
        self.write_log(self.other_addr, [event])
        self.write_log(self.addr, [self.view_update_again])
        self.assert_view_state(delegated_manifest, "signed")

    def test_attestation_v2_covers_params_including_empty_comparator(self):
        self.assert_state(self.manifest(self.att_v2, self.params), "valid")

    def test_v2_params_distinguish_python_equal_json_values(self):
        for signed, changed in ((False, 0), (0, False), (1, True), (True, 1),
                                (1, 1.0), (-0.0, 0.0)):
            with self.subTest(signed=repr(signed), changed=repr(changed)):
                params = {"COMPARATOR": "", "VALUE": signed,
                          "nested": {"values": [signed]}}
                attestation = self.attestation(rc="attestation/2", params=params)
                self.assert_state(self.manifest(attestation, params), "valid")
                # Python equality says these are equal despite different JSON
                # and different strings passed to a comparator environment.
                for member in ("VALUE", "nested"):
                    altered = copy.deepcopy(params)
                    if member == "VALUE":
                        altered["VALUE"] = changed
                    else:
                        altered["nested"]["values"][0] = changed
                    self.assertEqual(params, altered)
                    self.assertNotEqual(canonical(params), canonical(altered))
                    self.assert_state(self.manifest(attestation, altered), "stale")

    def test_v2_params_object_key_order_is_not_a_change(self):
        reordered = {key: self.params[key] for key in reversed(self.params)}
        self.assert_state(self.manifest(self.att_v2, reordered), "valid")

    def test_v2_params_nested_nonfinite_display_values_fail_closed(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                params = dict(self.params, nested={"values": [value]})
                self.assert_state(self.manifest(self.att_v2, params), "invalid")

    def test_changed_or_removed_v2_params_are_stale(self):
        variants = [None, {}, dict(self.params, EPSILON="0"),
                    {"EPSILON": "1e-6"},
                    dict(self.params, COMPARATOR="sk-12345678")]
        for params in variants:
            with self.subTest(params=params):
                self.assert_state(self.manifest(self.att_v2, params), "stale")

    def test_tampered_signed_v2_params_are_invalid(self):
        manifest = self.manifest(self.att_v2, self.params)
        # Keep the displayed claim equal to the tampered statement so a stale
        # comparison cannot hide the failed cryptographic verification.
        manifest["verification"]["params"]["EPSILON"] = "0"
        manifest["verification"]["attested_by"]["statement"]["params"]["EPSILON"] = "0"
        self.assert_state(manifest, "invalid")

    def test_v1_attestation_with_params_is_partial(self):
        self.assert_state(self.manifest(self.att_v1, self.params), "partial")

    def test_v1_attestation_without_params_is_valid(self):
        self.assert_state(self.manifest(self.att_v1), "valid")

    def test_unknown_attestation_rc_fails_closed_even_with_real_signature(self):
        for rc in ("attestation/999", None, False):
            with self.subTest(rc=rc):
                attestation = copy.deepcopy(self.att_unknown)
                attestation["statement"]["rc"] = rc
                # Explicit null is distinct from an absent legacy rc. Re-sign
                # each case so rejection cannot come from broken crypto.
                signed = self.sign(canonical(attestation["statement"]))
                attestation.update(addr=signed["address"], sig=signed["signature"])
                message = canonical(attestation["statement"])
                self.assertTrue(self.ns["_verify_message"](
                    message, attestation["sig"], attestation["addr"])[0])
                manifest = self.manifest(attestation, self.params)
                state, detail = self.ns["check_attestation"](manifest)
                self.assertIn(state, ("invalid", "unknown", "unknown-version"), detail)


unittest.main(verbosity=2)
PY
