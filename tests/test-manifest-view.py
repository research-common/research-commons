#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Research Commons Authors
"""Run with python3 tests/test-manifest-view.py (crypto checks need local viem)."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))
from manifest_views import (VERSION, canonical_view, publisher_view, view_digest,
                            validate_publisher_signature)

FIXTURE = json.loads((ROOT / "tests/fixtures/manifest-view-v1.json").read_text())
VECTORS = {v["name"]: v for v in FIXTURE["vectors"]}


class NormalizationTests(unittest.TestCase):
    def test_fixed_views_canonical_bytes_and_sha256(self):
        self.assertEqual(VERSION, FIXTURE["version"])
        for vector in FIXTURE["vectors"]:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(publisher_view(vector["manifest"]), vector["view"])
                self.assertEqual(canonical_view(publisher_view(vector["manifest"])),
                                 vector["canonical_view"])
                self.assertEqual(view_digest(vector["manifest"]), vector["digest"])
                # Also check fixture integrity without using the normalizer.
                self.assertEqual(hashlib.sha256(vector["canonical_view"].encode("ascii"))
                                 .hexdigest(), vector["digest"])

    def test_input_nonmutation_and_detached_output(self):
        manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        before = copy.deepcopy(manifest)
        projected = publisher_view(manifest)
        view_digest(manifest)
        self.assertEqual(manifest, before)
        projected["manifest"]["verification"]["params"]["options"]["label"] = "changed"
        projected["manifest"]["provenance"]["inputs"][0]["sha256"] = "changed"
        self.assertEqual(manifest, before)

    def test_absent_empty_equivalence(self):
        self.assertEqual(view_digest(VECTORS["absent"]["manifest"]),
                         VECTORS["empty"]["digest"])
        self.assertNotEqual(VECTORS["opaque-empty-parameter"]["digest"],
                            VECTORS["absent"]["digest"])

    def test_comparator_parameters_are_recursively_opaque(self):
        manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        params = manifest["verification"]["params"]
        self.assertEqual(publisher_view(manifest)["manifest"]["verification"]["params"],
                         params)
        del manifest["verification"]["params"]["delimiter"]
        self.assertNotEqual(view_digest(manifest), VECTORS["signed-rich"]["digest"])

    def test_duplicate_id_provenance_order_changes_digest(self):
        reverse = VECTORS["duplicate-id-inputs-reversed"]
        manifest = copy.deepcopy(reverse["manifest"])
        manifest["provenance"]["inputs"].reverse()
        self.assertNotEqual(view_digest(manifest), reverse["digest"])
        self.assertEqual(publisher_view(manifest)["manifest"]["provenance"]["inputs"],
                         manifest["provenance"]["inputs"])

    def test_set_order_duplicates_and_derived_annotations_do_not_change_digest(self):
        manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        manifest["tags"].reverse()
        manifest["tags"] += manifest["tags"]
        manifest["links"].reverse()
        manifest["links"] += manifest["links"]
        manifest["links"].append({"rel": "accepted", "id": "anything", "extra": "x"})
        manifest["verification"]["attested_by"] = {"anything": "different"}
        manifest["ingest"] = {"anything": "different"}
        manifest["publisher_sig"] = {"anything": "different"}
        self.assertEqual(view_digest(manifest), VECTORS["signed-rich"]["digest"])

    def test_unknown_fields_and_nonderived_links_are_signed(self):
        manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        manifest["future"]["kept"] = False
        self.assertNotEqual(view_digest(manifest), VECTORS["signed-rich"]["digest"])
        manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        manifest["links"].append({"rel": "future-relation", "id": "x"})
        self.assertNotEqual(view_digest(manifest), VECTORS["signed-rich"]["digest"])

    def test_unicode_has_no_normalization_and_nonbmp_uses_surrogates(self):
        vector = VECTORS["unicode-key-order"]
        canonical = canonical_view(publisher_view(vector["manifest"]))
        self.assertIn(r'"\ud83d\ude00":"nonBMP"', canonical)
        self.assertLess(canonical.index(r'"\ue000"'), canonical.index(r'"\ud83d\ude00"'))
        manifest = copy.deepcopy(vector["manifest"])
        manifest["future"]["nfd"] = "é"
        self.assertNotEqual(view_digest(manifest), vector["digest"])

    def test_python_float_spelling(self):
        canonical = canonical_view(publisher_view(VECTORS["signed-rich"]["manifest"]))
        for spelling in ('"negative_zero":-0.0', '"small":1e-07',
                         '"large":1e+20', '"whole":1.0', '"temperature":0.1'):
            self.assertIn(spelling, canonical)

    def test_nonfinite_values_rejected_even_in_nested_opaque_params(self):
        for number in (float("nan"), float("inf"), float("-inf")):
            for location in ("params", "tags", "future"):
                with self.subTest(number=number, location=location):
                    manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
                    if location == "params":
                        manifest["verification"]["params"]["options"]["nested"] = [number]
                    elif location == "tags":
                        manifest["tags"].append(number)
                    else:
                        manifest["future"]["nested"] = {"number": number}
                    with self.assertRaises(ValueError):
                        view_digest(manifest)
                    self.assertEqual(validate_publisher_signature(
                        manifest, self.never_verify)[0], "unnormalisable")

    @staticmethod
    def never_verify(*args):
        raise AssertionError("crypto callback must not be called")

    def test_list_elements_survive_recursive_pruning(self):
        vector = VECTORS["ordered-list-empty-elements"]
        self.assertEqual(publisher_view(vector["manifest"])["manifest"]["future"]["ordered"],
                         [None, "", [], {}, {}, False, 0])

    def test_only_top_level_tags_and_links_are_sets(self):
        manifest = {"future": {"tags": ["b", "a", "b"],
                               "links": [{"rel": "accepted", "id": "x"}]}}
        self.assertEqual(publisher_view(manifest)["manifest"], manifest)

    def test_invalid_normalization_input(self):
        for manifest in (None, [], "", 1):
            with self.subTest(manifest=manifest), self.assertRaises(TypeError):
                publisher_view(manifest)
        with self.assertRaises(TypeError):
            view_digest({"unknown": object()})


class SignatureTests(unittest.TestCase):
    def setUp(self):
        self.manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        self.calls = []

    def good_callback(self, message, sig, addr):
        self.calls.append((message, sig, addr))
        return True, addr.lower()

    def assert_state(self, expected, callback=None):
        state, detail, recovered = validate_publisher_signature(
            self.manifest, callback or self.good_callback)
        self.assertEqual(state, expected, detail)
        self.assertIsInstance(detail, str)
        self.assertTrue(detail)
        return recovered

    def test_valid_callback_receives_fixed_canonical_statement(self):
        addr = self.manifest["publisher_sig"]["addr"]
        self.assertEqual(self.assert_state("valid"), addr.lower())
        self.assertEqual(self.calls, [(VECTORS["signed-rich"]["canonical_statement"],
                                      self.manifest["publisher_sig"]["sig"], addr)])

    def test_legacy_only_when_signature_is_absent(self):
        del self.manifest["publisher_sig"]
        self.assertIsNone(self.assert_state("legacy"))
        self.assertEqual(self.calls, [])
        for malformed in (None, {}, [], "", False):
            with self.subTest(signature=malformed):
                self.manifest["publisher_sig"] = malformed
                self.assertIsNone(self.assert_state("altered"))

    def test_missing_or_invalid_domain_tag(self):
        for value in (None, "", "ledger/2", "manifest/2", 1, True, {}, []):
            with self.subTest(rc=value):
                self.manifest["publisher_sig"]["statement"]["rc"] = value
                self.assert_state("altered")
        del self.manifest["publisher_sig"]["statement"]["rc"]
        self.assert_state("altered")
        self.assertEqual(self.calls, [])

    def test_unknown_version_and_invalid_version_types(self):
        statement = self.manifest["publisher_sig"]["statement"]
        statement["view_version"] = "manifest-view/2"
        self.assert_state("unknown-view-version")
        for value in (None, True, 1, [], {}, ""):
            with self.subTest(version=value):
                statement["view_version"] = value
                self.assert_state("altered")
        del statement["view_version"]
        self.assert_state("altered")
        self.assertEqual(self.calls, [])

    def test_malformed_statement_fields_fail_without_callback(self):
        for field in ("id", "sha256", "view", "ts"):
            for value in (None, True, 17, [], {}, ""):
                with self.subTest(field=field, value=value):
                    self.manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
                    self.manifest["publisher_sig"]["statement"][field] = value
                    self.assert_state("altered")
            self.manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
            del self.manifest["publisher_sig"]["statement"][field]
            self.assert_state("altered")
        for field in ("sha256", "view"):
            for value in ("g" * 64, "a" * 63, "a" * 65, "0x" + "a" * 64):
                with self.subTest(field=field, value=value):
                    self.manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
                    self.manifest["publisher_sig"]["statement"][field] = value
                    self.assert_state("altered")
        self.assertEqual(self.calls, [])

    def test_malformed_signature_container_fields(self):
        for field in ("statement", "addr", "sig"):
            for value in (None, True, 1, "", [], {}, "0xgarbage"):
                with self.subTest(field=field, value=value):
                    self.manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
                    self.manifest["publisher_sig"][field] = value
                    self.assert_state("altered")
            self.manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
            del self.manifest["publisher_sig"][field]
            self.assert_state("altered")
        self.assertEqual(self.calls, [])

    def test_manifest_identity_binding(self):
        for field, value in (("id", "ds-other"), ("id", True), ("content", None),
                             ("content", []), ("content", {}),
                             ("content", {"sha256": "a" * 64}),
                             ("content", {"sha256": True})):
            with self.subTest(field=field, value=value):
                self.manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
                self.manifest[field] = value
                self.assert_state("altered")
        self.assertEqual(self.calls, [])

    def test_digest_mismatch(self):
        self.manifest["verification"]["tier"] = "T0"
        self.assert_state("altered")
        self.assertEqual(self.calls, [])

    def test_callback_must_recover_the_stated_address(self):
        other = "0x" + "a" * 40
        self.assertEqual(self.assert_state("altered", lambda *args: (True, other)), other)
        self.assertIsNone(self.assert_state("altered", lambda *args: (True, None)))
        self.assertIsNone(self.assert_state("altered", lambda *args: (True, {})))
        self.assert_state("altered", lambda *args: (False, args[2]))

    def test_callback_errors_and_malformed_results_fail_closed(self):
        def broken(*args):
            raise ValueError("invalid signature")
        for callback in (broken, lambda *args: None, lambda *args: (True,)):
            self.assertIsNone(self.assert_state("altered", callback))

    def test_nan_in_statement_is_unnormalisable(self):
        self.manifest["publisher_sig"]["statement"]["future"] = [float("nan")]
        self.assert_state("unnormalisable")
        self.assertEqual(self.calls, [])

    def test_non_json_view_and_cyclic_input_are_unnormalisable(self):
        self.manifest["future"] = object()
        self.assert_state("unnormalisable")
        self.manifest["future"] = self.manifest
        self.assert_state("unnormalisable")

    def test_invalid_manifest_type(self):
        self.assertEqual(validate_publisher_signature(None, self.good_callback)[0],
                         "unnormalisable")


class EIP191Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        roots = [os.environ.get("COMMONS_VIEM_DIR"), str(ROOT),
                 str(ROOT.parent / "research-commons"),
                 str(ROOT.parent / "research-commons-manifest-fix")]
        cls.viem_root = next((p for p in roots if p and
                              (Path(p) / "node_modules/viem").is_dir()), None)
        if cls.viem_root is None:
            raise RuntimeError("crypto tests require local viem or COMMONS_VIEM_DIR")

    def verify(self, message, sig, addr):
        env = dict(os.environ, COMMONS_VIEM_DIR=self.viem_root,
                   SIGNATURE=sig, ADDRESS=addr)
        result = subprocess.run(["node", str(ROOT / "lib/verify-message.mjs"), "--stdin"],
                                input=message, text=True, capture_output=True,
                                env=env, timeout=30)
        if result.returncode not in (0, 1):
            raise RuntimeError(result.stderr)
        response = json.loads(result.stdout)
        return response["valid"], response["recovered"]

    def test_fixed_signature_is_valid_and_recovers_known_test_key(self):
        vector = VECTORS["signed-rich"]
        state, detail, recovered = validate_publisher_signature(vector["manifest"], self.verify)
        self.assertEqual(state, "valid", detail)
        self.assertEqual(recovered.lower(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")

    def test_fixed_signature_reproduced_by_known_test_private_key(self):
        script = """
const {createRequire} = require('node:module');
const fs = require('node:fs');
const req = createRequire(process.env.COMMONS_VIEM_DIR + '/package.json');
const {privateKeyToAccount} = req('viem/accounts');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
privateKeyToAccount(input.key).signMessage({message: input.message})
  .then(sig => console.log(sig));
"""
        result = subprocess.run(["node", "-e", script], input=json.dumps({
            "key": "0x" + format(FIXTURE["test_private_key_scalar"], "064x"),
            "message": VECTORS["signed-rich"]["canonical_statement"]}),
            text=True, capture_output=True, check=True, timeout=30,
            env=dict(os.environ, COMMONS_VIEM_DIR=self.viem_root))
        self.assertEqual(result.stdout.strip(),
                         VECTORS["signed-rich"]["manifest"]["publisher_sig"]["sig"])

    def test_statement_tampering_fails_real_crypto_verification(self):
        manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        manifest["publisher_sig"]["statement"]["ts"] = "2026-10-03T09:00:00Z"
        state, _, recovered = validate_publisher_signature(manifest, self.verify)
        self.assertEqual(state, "altered")
        self.assertNotEqual(recovered.lower(), manifest["publisher_sig"]["addr"].lower())

    def test_bad_hex_signature_fails_real_crypto_without_traceback(self):
        manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        manifest["publisher_sig"]["sig"] = "0x" + "00" * 65
        self.assertEqual(validate_publisher_signature(manifest, self.verify)[0], "altered")

    def test_wrong_address_fails_real_crypto(self):
        manifest = copy.deepcopy(VECTORS["signed-rich"]["manifest"])
        manifest["publisher_sig"]["addr"] = "0x" + "aa" * 20
        state, _, recovered = validate_publisher_signature(manifest, self.verify)
        self.assertEqual(state, "altered")
        self.assertEqual(recovered.lower(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf")


if __name__ == "__main__":
    unittest.main(verbosity=2)
