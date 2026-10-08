# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Research Commons Authors
"""Pure manifest-view/1 construction and intrinsic publisher signature checks.

No ledger, peer registry, clock or signing implementation is consulted here.
Authority, stripped signatures and supersession belong to the caller.
"""

import copy
import hashlib
import json
import re

VERSION = "manifest-view/1"


def canonical_view(obj):
    """Serialize a view or statement to the protocol's ASCII canonical JSON.

    This deliberately uses Python's float spelling and code-point key order, not
    RFC 8785. Non-finite numbers anywhere in the signed object are rejected.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False)


def _empty(value):
    return value is None or value == "" or value == [] or value == {}


def _prune(value, path=()):
    # Comparator parameters are opaque, including every nested member. The
    # parent still removes params itself if it is an empty object.
    if path == ("verification", "params"):
        return value
    if isinstance(value, dict):
        result = {}
        for key, member in value.items():
            member = _prune(member, path + (key,))
            if not _empty(member):
                result[key] = member
        return result
    if isinstance(value, list):
        # Never discard list elements, even ones that become empty after pruning.
        return [_prune(member, path + (index,))
                for index, member in enumerate(value)]
    return value


def publisher_view(m):
    """Return a detached publisher projection wrapped in its version domain.

    Unknown fields are included. Only top-level tags and links are set-valued.
    Raises TypeError/ValueError for invalid input or unencodable set members.
    """
    if not isinstance(m, dict):
        raise TypeError("manifest must be an object")
    view = copy.deepcopy(m)
    view.pop("ingest", None)
    view.pop("publisher_sig", None)
    if isinstance(view.get("verification"), dict):
        view["verification"].pop("attested_by", None)
    if isinstance(view.get("links"), list):
        view["links"] = [
            link for link in view["links"]
            if not (isinstance(link, dict)
                    and link.get("rel") in ("fulfills", "accepted"))
        ]
    view = _prune(view)
    for field in ("tags", "links"):
        if isinstance(view.get(field), list):
            members = {canonical_view(member): member for member in view[field]}
            view[field] = [members[key] for key in sorted(members)]
    return {"rc": VERSION, "manifest": view}


def view_digest(m):
    """SHA-256 hex digest of the canonical ASCII publisher view."""
    return hashlib.sha256(canonical_view(publisher_view(m)).encode("ascii")).hexdigest()


def _hex(value, digits):
    return isinstance(value, str) and re.fullmatch(
        r"[0-9a-fA-F]{%d}" % digits, value) is not None


def validate_publisher_signature(m, verify_message):
    """Return (state, detail, recovered_signer) for the file alone.

    States are legacy, valid, altered, unknown-view-version and unnormalisable.
    verify_message(canonical_statement, sig, addr) must return (ok, recovered).
    A present but malformed publisher_sig is altered, never legacy. Missing or
    invalid signer recovery fails closed, even if the callback reports success.
    """
    if not isinstance(m, dict):
        return "unnormalisable", "manifest must be an object", None
    if "publisher_sig" not in m:
        return "legacy", "no publisher signature", None
    signature = m["publisher_sig"]
    if not isinstance(signature, dict):
        return "altered", "publisher_sig must be an object", None
    statement = signature.get("statement")
    if not isinstance(statement, dict):
        return "altered", "publisher statement must be an object", None
    if statement.get("rc") != "manifest/1":
        return "altered", "publisher statement domain must be manifest/1", None
    for field in ("id", "sha256", "view_version", "view", "ts"):
        if not isinstance(statement.get(field), str) or not statement[field]:
            return "altered", "publisher statement %s must be a nonempty string" % field, None
    if not _hex(statement["sha256"], 64) or not _hex(statement["view"], 64):
        return "altered", "publisher statement hashes must be 64 hex digits", None
    addr, sig = signature.get("addr"), signature.get("sig")
    if not (isinstance(addr, str) and addr.startswith("0x") and _hex(addr[2:], 40)):
        return "altered", "publisher address must be a 20-byte hex address", None
    if not (isinstance(sig, str) and sig.startswith("0x") and _hex(sig[2:], 130)):
        return "altered", "publisher signature must be a 65-byte hex signature", None
    if statement["view_version"] != VERSION:
        return "unknown-view-version", "unsupported view version: %s" % statement["view_version"], None
    content = m.get("content")
    if statement["id"] != m.get("id"):
        return "altered", "publisher statement covers a different id", None
    if not isinstance(content, dict) or statement["sha256"] != content.get("sha256"):
        return "altered", "publisher statement covers different content", None
    try:
        digest = view_digest(m)
        message = canonical_view(statement)
    except (TypeError, ValueError, RecursionError, OverflowError) as error:
        return "unnormalisable", "cannot canonicalise publisher view or statement: %s" % error, None
    if digest != statement["view"]:
        return "altered", "publisher view digest does not match the statement", None
    try:
        ok, recovered = verify_message(message, sig, addr)
    except Exception:
        # Injected crypto adapters can reject malformed signatures or be unavailable.
        return "altered", "could not verify publisher signature", None
    if not isinstance(recovered, str):
        recovered = None
    if not ok or recovered is None or recovered.lower() != addr.lower():
        return "altered", "publisher signature does not recover the stated address", recovered
    return "valid", "publisher signature matches the manifest", recovered
