#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Research Commons Authors
# Signed metadata that cannot be checked must stop before resolving/running code.
# Real CLI and independent EIP-191 fixtures; no network, containers or operator keys.
# Alternate tool: COMMONS=/baseline/bin/commons bash tests/test-view-verification-escapes.sh
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 - "$REPO" "$@" <<'PY'
import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(sys.argv.pop(1))
COMMONS = Path(os.environ.get("COMMONS", str(REPO / "bin/commons"))).resolve()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class VerificationEscapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = tempfile.TemporaryDirectory(prefix="commons-view-verification-")
        cls.addClassCleanup(cls.lab.cleanup)
        cls.root = Path(cls.lab.name)
        cls.env = {k: v for k, v in os.environ.items()
                   if not k.startswith("COMMONS_")}
        roots = [os.environ.get("COMMONS_VIEM_DIR"), str(REPO),
                 str(REPO.parent / "research-commons")]
        cls.viem_root = next((p for p in roots if p and
                              (Path(p) / "node_modules/viem").is_dir()), None)
        if cls.viem_root is None:
            raise RuntimeError("real crypto fixtures require local viem or COMMONS_VIEM_DIR")
        cls.env.update(COMMONS_ROOT=str(cls.root), COMMONS_EXEC="native",
                       COMMONS_AGENT="verification-test", COMMONS_REQUIRE_SIG="0",
                       COMMONS_VIEM_DIR=cls.viem_root, PYTHONDONTWRITEBYTECODE="1")
        cls.art = cls.root / "registry/artifacts"
        cls.art.mkdir(parents=True)
        cls.workflow_sentinel = cls.root / "workflow-executed"
        cls.comparator_sentinel = cls.root / "comparator-executed"
        cls.workflow = cls.store("workflow", canonical({
            "env": {"SENTINEL": str(cls.workflow_sentinel)},
            "steps": ['printf executed > "$SENTINEL"',
                      'printf "expected\\n" > "$OUT_DIR/result.txt"'],
            "outputs": {"result": "result.txt"},
        }).encode(), "workflow.json")
        cls.other_workflow = cls.store("workflow", canonical({
            "env": {"SENTINEL": str(cls.workflow_sentinel)},
            "steps": ['printf executed > "$SENTINEL"',
                      'printf "different\\n" > "$OUT_DIR/result.txt"'],
            "outputs": {"result": "result.txt"},
        }).encode(), "other-workflow.json")
        cls.comparator = cls.store("skill", (
            '#!/bin/sh\nprintf executed > "$SENTINEL"\nexit 0\n'
        ).encode(), "comparator.sh")
        cls.replacement_comparator = cls.store("skill", (
            '#!/bin/sh\nprintf replaced > "$SENTINEL"\nexit 0\n'
        ).encode(), "replacement-comparator.sh")
        cls.manifest = cls.store("dataset", b"expected\n", "result.txt")
        cls.manifest.update(
            verification={"tier": "T0", "params": {"MODE": "original"}},
            provenance={"workflow": {
                "id": cls.workflow["id"],
                "sha256": cls.workflow["content"]["sha256"],
            }, "run": {"exec": {"mode": "native"}}})
        cls.manifest = cls.signed(cls.manifest)
        cls.workflow = cls.signed(cls.workflow)
        cls.other_workflow = cls.signed(cls.other_workflow)
        cls.comparator = cls.signed(cls.comparator)
        # Check crypto independently of every production signature/view helper.
        cls.assert_real_signature(cls.manifest, True)
        cls.assert_real_signature(cls.workflow, True)
        cls.assert_real_signature(cls.other_workflow, True)
        cls.assert_real_signature(cls.comparator, True)

    @classmethod
    def crypto(cls, request):
        script = """
const fs = require('node:fs');
const {createRequire} = require('node:module');
const req = createRequire(process.env.COMMONS_VIEM_DIR + '/package.json');
const {privateKeyToAccount} = req('viem/accounts');
const {recoverMessageAddress} = req('viem');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
  // Public disposable scalar, assembled here; no wallet or key file is read.
  const account = privateKeyToAccount('0x' + (5).toString(16).padStart(64, '0'));
  if (input.signature) {
    const recovered = await recoverMessageAddress({
      message: input.message, signature: input.signature,
    });
    console.log(JSON.stringify({valid: recovered.toLowerCase() ===
                              input.address.toLowerCase()}));
  } else {
    const signature = await account.signMessage({message: input.message});
    console.log(JSON.stringify({address: account.address, signature}));
  }
})().catch(error => { console.error(error); process.exit(1); });
"""
        result = subprocess.run(["node", "-e", script], input=canonical(request),
                                text=True, capture_output=True, env=cls.env,
                                timeout=20, check=True)
        return json.loads(result.stdout)

    @classmethod
    def signed(cls, manifest, version="manifest-view/1"):
        manifest = copy.deepcopy(manifest)
        manifest.pop("publisher_sig", None)
        # These fixtures contain no empty/derived/set-valued fields. Construct
        # the wire view directly, without importing production normalization.
        digest = hashlib.sha256(canonical({
            "rc": version, "manifest": manifest,
        }).encode("ascii")).hexdigest()
        statement = {"rc": "manifest/1", "id": manifest["id"],
                     "sha256": manifest["content"]["sha256"],
                     "view_version": version, "view": digest,
                     "ts": "2026-01-02T00:00:00Z"}
        signed = cls.crypto({"message": canonical(statement)})
        manifest["publisher_sig"] = {
            "addr": signed["address"], "sig": signed["signature"],
            "statement": statement,
        }
        return manifest

    @classmethod
    def assert_real_signature(cls, manifest, expected):
        signature = manifest["publisher_sig"]
        valid = cls.crypto({"message": canonical(signature["statement"]),
                            "signature": signature["sig"],
                            "address": signature["addr"]})["valid"]
        if valid != expected:
            raise AssertionError("independent fixture crypto validity: %s != %s"
                                 % (valid, expected))

    @classmethod
    def store(cls, kind, body, filename):
        digest = hashlib.sha256(body).hexdigest()
        blob = cls.root / "store/sha256" / digest[:2] / digest
        blob.parent.mkdir(parents=True, exist_ok=True)
        blob.write_bytes(body)
        prefix = {"dataset": "ds", "workflow": "wf", "skill": "sk"}[kind]
        return {"schema": "rc.v1", "id": prefix + "-" + digest[:8],
                "type": kind, "title": "Verification fixture",
                "content": {"sha256": digest, "filename": filename,
                            "bytes": len(body)}}

    def write(self, manifest):
        (self.art / (manifest["id"] + ".json")).write_text(
            json.dumps(manifest, sort_keys=True, indent=2) + "\n")

    def setUp(self):
        for path in (self.workflow_sentinel, self.comparator_sentinel):
            path.unlink(missing_ok=True)
        shutil.rmtree(self.root / "registry/ledger", ignore_errors=True)
        for manifest in (self.manifest, self.workflow, self.other_workflow,
                         self.comparator):
            self.write(manifest)

    def verify(self, manifest):
        self.write(manifest)
        return subprocess.run(
            [sys.executable, str(COMMONS), "verify", self.manifest["id"],
             "--exec", "native"], cwd=self.root, env=self.env,
            text=True, capture_output=True, timeout=30)

    def changed_claims(self):
        manifest = copy.deepcopy(self.manifest)
        manifest["verification"] = {
            "tier": "T1", "criteria": self.comparator["id"],
            "params": {"MODE": "changed", "SENTINEL": str(self.comparator_sentinel)},
        }
        manifest["provenance"]["workflow"] = {
            "id": self.other_workflow["id"],
            "sha256": self.other_workflow["content"]["sha256"],
        }
        return manifest

    def assert_stopped(self, result, state, workflow_ran=False):
        output = result.stdout + result.stderr
        # Check side effects first: an exit-3 assertion alone could accidentally
        # pass after a workflow ran and a later unrelated check returned 3.
        self.assertEqual(self.workflow_sentinel.exists(), workflow_ran, output)
        self.assertFalse(self.comparator_sentinel.exists(), output)
        self.assertEqual(result.returncode, 3, output)
        self.assertIn("verification stopped", output.lower())
        self.assertIn("unchecked metadata", output.lower())
        self.assertIn(state, output)
        for forbidden in ("PASS:", "FAIL:", "no such artifact", "Traceback",
                          "METADATA ALTERED", "BAD SIGNATURE"):
            self.assertNotIn(forbidden, output)
        self.assertFalse((self.root / "registry/ledger").exists(), output)

    def test_valid_view_runs_real_host_workflow_normally(self):
        result = self.verify(self.manifest)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("metadata signed", result.stdout)
        self.assertIn("PASS:", result.stdout)
        self.assertTrue(self.workflow_sentinel.exists())
        self.assertFalse(self.comparator_sentinel.exists())

    def test_changed_claims_without_escape_still_fail(self):
        result = self.verify(self.changed_claims())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("METADATA ALTERED", result.stdout)
        self.assertFalse(self.workflow_sentinel.exists())
        self.assertFalse(self.comparator_sentinel.exists())

    def test_changed_claims_unknown_version_never_run_workflow_or_comparator(self):
        manifest = self.changed_claims()
        manifest["publisher_sig"]["statement"]["view_version"] = "manifest-view/999"
        self.assert_real_signature(manifest, False)
        self.assert_stopped(self.verify(manifest), "unknown-view-version")

    def test_changed_claims_nan_never_run_workflow_or_comparator(self):
        manifest = self.changed_claims()
        manifest["future"] = {"value": float("nan")}
        self.assert_real_signature(manifest, True)
        self.assert_stopped(self.verify(manifest), "unnormalisable")

    def test_genuinely_signed_future_version_stops_without_forgery_accusation(self):
        manifest = self.signed(self.manifest, version="manifest-view/999")
        self.assert_real_signature(manifest, True)
        self.assert_stopped(self.verify(manifest), "unknown-view-version")

    def test_unknown_version_stops_before_resolving_missing_workflow(self):
        manifest = self.changed_claims()
        manifest["provenance"]["workflow"]["id"] = "wf-00000000"
        manifest["publisher_sig"]["statement"]["view_version"] = "manifest-view/999"
        self.assert_stopped(self.verify(manifest), "unknown-view-version")

    def test_nan_stops_before_resolving_missing_workflow(self):
        manifest = self.changed_claims()
        manifest["provenance"]["workflow"]["id"] = "wf-00000000"
        manifest["future"] = float("nan")
        self.assert_stopped(self.verify(manifest), "unnormalisable")

    def test_unknown_workflow_view_stops_before_execution(self):
        workflow = self.signed(self.workflow, version="manifest-view/999")
        self.assert_real_signature(workflow, True)
        self.assert_stopped(self.verify(workflow), "unknown-view-version")

    def test_valid_t1_view_runs_real_comparator_normally(self):
        manifest = self.signed(self.changed_claims())
        self.assert_real_signature(manifest, True)
        result = self.verify(manifest)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PASS:", result.stdout)
        self.assertTrue(self.workflow_sentinel.exists())
        self.assertTrue(self.comparator_sentinel.exists())

    def test_unknown_comparator_view_stops_before_comparator_execution(self):
        comparator = self.signed(self.comparator, version="manifest-view/999")
        self.assert_real_signature(comparator, True)
        self.write(comparator)
        self.assert_stopped(self.verify(self.signed(self.changed_claims())),
                            "unknown-view-version", workflow_ran=True)

    def test_nan_comparator_view_stops_before_comparator_execution(self):
        comparator = copy.deepcopy(self.comparator)
        comparator["future"] = float("nan")
        self.write(comparator)
        self.assert_stopped(self.verify(self.signed(self.changed_claims())),
                            "unnormalisable", workflow_ran=True)

    def assert_altered_comparator_stopped(self, comparator):
        self.write(comparator)
        result = self.verify(self.signed(self.changed_claims()))
        output = result.stdout + result.stderr
        self.assertFalse(self.comparator_sentinel.exists(), output)
        self.assertTrue(self.workflow_sentinel.exists(), output)
        self.assertEqual(result.returncode, 1, output)
        self.assertIn("METADATA ALTERED", output)
        self.assertIn("metadata is altered", output)
        self.assertNotIn("PASS:", output)
        self.assertNotIn("Traceback", output)
        self.assertFalse((self.root / "registry/ledger").exists(), output)

    def test_altered_comparator_filename_stops_before_comparator_execution(self):
        comparator = copy.deepcopy(self.comparator)
        comparator["content"]["filename"] = "forged-comparator.sh"
        self.assert_altered_comparator_stopped(comparator)

    def test_altered_comparator_hash_stops_before_comparator_execution(self):
        comparator = copy.deepcopy(self.comparator)
        comparator["content"]["sha256"] = self.replacement_comparator["content"]["sha256"]
        self.assert_altered_comparator_stopped(comparator)

    def test_byte_identical_t1_result_does_not_resolve_unneeded_comparator(self):
        manifest = self.changed_claims()
        manifest["provenance"] = copy.deepcopy(self.manifest["provenance"])
        manifest["verification"]["criteria"] = "sk-00000000"
        result = self.verify(self.signed(manifest))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("byte-identical (comparator not needed)", result.stdout)
        self.assertTrue(self.workflow_sentinel.exists())
        self.assertFalse(self.comparator_sentinel.exists())

    def test_metadata_helper_raises_exit_three_for_both_unchecked_states(self):
        # Exercise the selected tool directly, without mocking its crypto or gate.
        with mock.patch.dict(os.environ, self.env, clear=True):
            namespace = runpy.run_path(str(COMMONS))
            check = namespace.get("check_metadata_before_verify")
            self.assertIsNotNone(check, "selected tool has no metadata verification guard")
            unknown = self.changed_claims()
            unknown["publisher_sig"]["statement"]["view_version"] = "manifest-view/999"
            nonfinite = self.changed_claims()
            nonfinite["future"] = float("nan")
            for manifest in (unknown, nonfinite):
                with self.subTest(manifest=manifest["publisher_sig"]["statement"]["view_version"]):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        with self.assertRaises(SystemExit) as stopped:
                            check(manifest)
                    self.assertEqual(stopped.exception.code, 3)
                    self.assertIn("verification stopped", output.getvalue().lower())


unittest.main(verbosity=2)
PY
