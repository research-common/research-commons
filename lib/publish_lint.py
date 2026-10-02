#!/usr/bin/env python3
"""publish_lint — publish-time secret/PII scan. Prevention beats retraction.

Once an artifact replicates, the bytes are out; a `retract` event is best-effort
recall, not erasure. So the cheap win is refusing to publish the accident in the
first place — fail-closed, like the sync-channel lint.

Findings are (severity, label, line_no, excerpt). severity "block" refuses the
publish; "warn" prints and continues. Excerpts are always redacted: this tool
must never be the thing that writes a key into a log.

Deliberately NOT a general DLP engine. High-signal patterns only, because a lint
that cries wolf gets bypassed, and a bypassed lint protects nothing.
"""
import base64, codecs, csv, io, json, math, os, re, sys

# --- high-confidence credential shapes (block) ---
BLOCK_PATTERNS = [
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY")),
    ("eth private key", re.compile(r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{64}(?![0-9a-fA-F])")),
    ("aws access key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("aws secret key", re.compile(r"(?i)aws.{0,20}(?:secret|private).{0,20}['\"][0-9a-zA-Z/+=]{40}['\"]")),
    ("github token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b")),
    ("openai key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("google api key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe secret", re.compile(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("bearer secret", re.compile(r"(?i)authorization:\s*bearer\s+[A-Za-z0-9._-]{20,}")),
    ("password assignment", re.compile(
        r"(?i)\b(?:password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*"
        r"['\"][^'\"\s]{8,}['\"]")),
    ("bip39 mnemonic", re.compile(
        r"(?i)\b(?:abandon|ability|able|about|above|absent|absorb|abstract)\b"
        r"(?:\s+[a-z]{3,8}\b){11,23}")),
]

# --- personal data (warn: often legitimate in research corpora) ---
WARN_PATTERNS = [
    ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("us ssn", re.compile(r"\b(?!000|666)[0-8]\d{2}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("credit card", re.compile(r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13})\b")),
    ("private ip", re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
    ("bare phone number", re.compile(r"(?<![\d.])\+?1?[\s.-]?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?![\d.])")),
]

# --- binary variant of BLOCK_PATTERNS: leading \b anchor stripped ---
#
# In a packed binary record (e.g. a SQLite row) a credential can sit glued
# directly to the preceding column's bytes with no word-boundary character in
# between (`...api_keysk-proj-...`), so `\bsk-` silently fails to match a
# credential that is right there in plaintext. The *trailing* anchor is left
# alone: only the leading one is dropped, and only for this binary-only copy
# of the pattern list — the text path's anchors (and its false-positive
# behaviour) are unchanged. Measured 0 FP on both test corpora (2026-08-23).
def _strip_leading_word_boundary(rx):
    src = rx.pattern
    if src.startswith(r"\b"):
        return re.compile(src[2:], rx.flags)
    return rx


BLOCK_PATTERNS_BINARY = [(label, _strip_leading_word_boundary(rx)) for label, rx in BLOCK_PATTERNS]

# Contexts where a high-entropy blob is expected and meaningless to flag.
ENTROPY_SKIP = re.compile(
    r"(?i)\b(?:sha256|sha512|sha1|md5|blake|digest|hash|checksum|commit|"
    r"image_digest|content|blob|id|addr|address|signature|sig|prev|txid|"
    r"merkle|root|nonce)\b")
# `# lint: allow` or `// lint: allow` (or `/* lint: allow */`): skill bundles ship
# mixed-language helpers (bash, python, TS/JS), and a marker only bash can spell
# forces TS authors to either mangle a public constant or publish with --allow-secrets
# for the whole archive — the coarser, worse escape hatch.
ALLOW_MARK = re.compile(r"(?i)(?:#|//|/\*)\s*(?:secret-lint|lint):\s*allow")

# --- eth-key vs. tx/block hash: context exemption (issue #9) ---
#
# A raw 32-byte hex value is information-theoretically indistinguishable between a
# private key and a hash — a tx hash, block hash, log topic, storage slot, keccak id,
# merkle root. On-chain datasets are full of the latter (every row of a payment
# ledger has a `txHash`), and the bare-shape "eth private key" pattern above cannot
# tell them apart, so a real 83 MB on-chain NDJSON produced 443,939 BLOCK findings —
# forcing `--allow-secrets`, the blanket bypass this lint exists to avoid.
#
# The fix is CONTEXT, not a weaker shape: suppress the "eth private key" finding only
# when the match is the value of a JSON key / CSV column header from a conservative
# built-in allowlist of hash-shaped field names, and NEVER suppress when the same
# field name also contains a key-danger token — so `{"txHash": "0x…"}` is exempt but
# `{"privateKeyHash": "0x…"}` and `{"txHash": "0x…", "privateKey": "0x…"}` (the
# privateKey occurrence) still block. Ambiguous or unrecognised field names are NOT
# exempted (err toward blocking): `id`, `content`, `value`, `data` are deliberately
# left out of the allowlist.
#
# Known residual risk, stated honestly rather than left implicit: a real secret
# stored under a hash-named key — `{"txHash": "<some private key>"}` — is
# indistinguishable from a genuine hash under this or any purely structural check,
# and will be waved through. This is why suppression is never silent: every
# suppressed match is counted and reported in a single summary WARN, so the
# suppression is auditable rather than invisible, and an operator who actually put a
# key under `txHash` still has one more chance to notice before the bytes replicate.
ETH_KEY_LABEL = "eth private key"
HEX64_BARE = re.compile(r"^0x[0-9a-fA-F]{64}$")


def _norm_field(name):
    return re.sub(r"[^a-z0-9]", "", (name or "").lower())


# Conservative: only names that are structurally hash-shaped on real on-chain/db
# exports. Generic names (`id`, `content`, `value`, `data`, `key`) are deliberately
# excluded — an unrecognised field name blocks, same as before this change.
HASH_FIELD_NAMES_NORM = frozenset(_norm_field(n) for n in (
    "hash", "txHash", "transactionHash", "blockHash", "parentHash",
    "topics", "topic", "root", "stateRoot", "receiptsRoot", "mixHash",
    "sha3Uncles", "txid", "tx_id", "tx_hash", "block_hash",
    "transaction_hash", "commitment", "nullifier", "digest",
    "sha256", "sha1", "sha512", "keccak", "keccak256",
    "merkleRoot", "merkle_root", "checksum",
))

# Any of these appearing anywhere in the normalised field name keeps the match
# blocking, even if the name also looks hash-shaped — e.g. "privateKeyHash" or a
# generic "key" contain "key" and never get exempted. Deliberately broad: a false
# negative here is a leaked key, a false positive is one more `# lint: allow`.
DANGER_FIELD_TOKENS = ("private", "priv", "secret", "mnemonic", "seed", "signerkey", "pk", "key")


def _is_hash_field(name):
    n = _norm_field(name)
    if not n:
        return False
    if any(tok in n for tok in DANGER_FIELD_TOKENS):
        return False
    return n in HASH_FIELD_NAMES_NORM


def _json_hash_occurrences(doc):
    """(value, key) for every bare-64-hex string leaf in `doc`, depth-first, in the
    order json.loads would have read them off the original text (dict insertion
    order is preserved since Python 3.7, matching source order for a single decoded
    line). A list inherits its own key so `"topics": ["0x…", "0x…"]` resolves each
    element back to the `topics` field."""
    out = []

    def walk(node, key):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, k)
        elif isinstance(node, list):
            for item in node:
                walk(item, key)
        elif isinstance(node, str):
            s = node.strip()
            if HEX64_BARE.match(s):
                out.append((s, key))

    walk(doc, None)
    return out


def _csv_hash_occurrences(line, header):
    """Same shape as `_json_hash_occurrences` but for one CSV data row: (value,
    column name) for each cell that is a bare 64-hex value, left to right."""
    try:
        cells = next(csv.reader(io.StringIO(line)))
    except (csv.Error, StopIteration):
        return None
    out = []
    for i, cell in enumerate(cells):
        s = cell.strip()
        if HEX64_BARE.match(s):
            out.append((s, header[i] if i < len(header) else None))
    return out


def _detect_csv_header(text):
    """First non-blank line, if it looks like a delimited header row rather than
    JSON or prose. Mirrors the same convention `forbidden_key_findings` already
    uses for CSV: the first line is the header, or nothing is CSV-shaped."""
    first = next((l for l in text.splitlines() if l.strip()), "")
    if not first or first.lstrip()[:1] in ("{", "["):
        return None
    try:
        cells = next(csv.reader(io.StringIO(first)))
    except (csv.Error, StopIteration):
        return None
    return cells if len(cells) > 1 else None


def _eth_key_match(line, rx, csv_header):
    """Apply hash-field context suppression to the "eth private key" pattern for
    one line. Returns (first_unsafe_match_text_or_None, suppressed_count).

    Structural context (JSON object/array on the line, or a CSV row under a known
    header) is resolved once per line and matched to the raw-text regex hits by
    position, left to right — both walks visit the line in the same order. If the
    line isn't structurally parseable, or the structural walk doesn't find exactly
    the same set of hex values the regex found (anything unexpected: a hex value
    outside a string literal, multi-line JSON, a parse edge case), this falls back
    to the original behaviour and blocks — suppression only ever fires when the
    context is unambiguous.
    """
    matches = list(rx.finditer(line))
    if not matches:
        return None, 0
    context = None
    stripped = line.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            doc = json.loads(line)
        except ValueError:
            context = None
        else:
            context = _json_hash_occurrences(doc)
    elif csv_header is not None:
        context = _csv_hash_occurrences(line, csv_header)
    if context is not None and len(context) == len(matches):
        suppressed = 0
        for (val, key), m in zip(context, matches):
            if val == m.group(0) and _is_hash_field(key):
                suppressed += 1
                continue
            return m.group(0), suppressed
        return None, suppressed
    return matches[0].group(0), 0


def shannon(s):
    if not s: return 0.0
    counts = {}
    for ch in s: counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def redact(s, keep=4):
    s = s.strip()
    if len(s) <= keep * 2: return "*" * len(s)
    return "%s\u2026%s (%d chars)" % (s[:keep], s[-keep:], len(s))


def entropy_findings(line, lineno):
    """Long, high-entropy, non-hash tokens — the shape of an unknown credential."""
    out = []
    if ENTROPY_SKIP.search(line): return out
    for tok in re.findall(r"[A-Za-z0-9+/=_-]{32,}", line):
        if re.fullmatch(r"[0-9a-fA-F]+", tok):  # plain hex: almost always a hash
            continue
        h = shannon(tok)
        if h >= 4.2:
            out.append(("warn", "high-entropy token (entropy %.1f)" % h, lineno, redact(tok)))
    return out


# --- streaming line machinery ---
#
# `scan_file` used to read its whole cap into memory, decode it, and `splitlines()` it:
# peak RSS was ~3.4x the scanned bytes, which is fine at 8 MiB and not at 100 MiB. The
# scan now streams: bounded binary chunks -> an incremental UTF-8 decoder (so a multibyte
# character split across two chunks is never corrupted, and `errors="replace"` yields
# exactly what a whole-buffer decode would) -> `_LineSplitter`, which yields the same
# lines `str.splitlines()` would, one at a time. Memory is bounded by one chunk plus the
# longest line kept whole (LONG_LINE_CHARS), independent of file size.
#
# For every input whose lines are all <= LONG_LINE_CHARS, findings (labels, severities,
# line numbers, order, the max_findings cut-off) are identical to the old whole-buffer
# scan. Longer lines (minified JSON, a single-line dump) are the one deliberate
# difference: they are scanned in overlapping windows (LONG_LINE_OVERLAP chars of
# overlap, far longer than any pattern needs), and on those lines the `lint: allow`
# marker and the hash-field exemption are NOT applied. Both need the whole line, and
# the conservative direction for a secret scanner is to keep blocking. A summary warn
# says when that happened.
CHUNK_BYTES = 1 << 20
LONG_LINE_CHARS = 1 << 20
LONG_LINE_OVERLAP = 4096
LONG_LINE_LABEL = "very long line"
# Exactly the separators str.splitlines() treats as line boundaries (plus "\r\n" as one).
_LINE_TERMS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"


def _strip_term(line):
    if line.endswith("\r\n"):
        return line[:-2]
    if line and line[-1] in _LINE_TERMS:
        return line[:-1]
    return line


class _LineSplitter:
    """Incremental `str.splitlines()`. `feed()` yields (lineno, text, windowed).

    A trailing "\r" is held back until the next chunk shows whether it is half of
    "\r\n" (one boundary) or a lone "\r" (also one boundary). splitlines() makes the
    same distinction on the whole string, so line numbering is identical.
    """

    def __init__(self):
        self.carry = ""
        self.lineno = 0
        self.windowing = False

    def feed(self, s, final=False):
        buf = self.carry + s
        self.carry = ""
        if not buf:
            return
        parts = buf.splitlines(True)
        last = parts[-1]
        incomplete = last[-1] not in _LINE_TERMS or last.endswith("\r") and not last.endswith("\r\n")
        if incomplete and not final:
            self.carry = parts.pop()
        for part in parts:
            yield from self._complete(_strip_term(part))
        while len(self.carry) > LONG_LINE_CHARS:
            if not self.windowing:
                self.windowing = True
                self.lineno += 1
            yield (self.lineno, self.carry[:LONG_LINE_CHARS], True)
            self.carry = self.carry[LONG_LINE_CHARS - LONG_LINE_OVERLAP:]

    def _complete(self, text):
        if self.windowing:
            # Tail of a line already being windowed (it starts with the overlap).
            self.windowing = False
            yield from self._windows(text)
            return
        self.lineno += 1
        if len(text) > LONG_LINE_CHARS:
            # Decide by line length alone, never by where chunk boundaries fell.
            yield from self._windows(text)
        else:
            yield (self.lineno, text, False)

    def _windows(self, text):
        step = LONG_LINE_CHARS - LONG_LINE_OVERLAP
        pos = 0
        while True:
            yield (self.lineno, text[pos:pos + LONG_LINE_CHARS], True)
            if pos + LONG_LINE_CHARS >= len(text):
                return
            pos += step


def _scan_lines(pieces, block_patterns, text_mode, max_findings):
    """Per-line scan shared by the text and binary paths (see scan_text for semantics)."""
    findings = []
    suppressed = 0
    csv_header = None
    # A CSV data row only has a header if the file itself is CSV-shaped: the first
    # non-blank line, resolved once (same rule as _detect_csv_header on the whole text).
    header_pending = text_mode and block_patterns is BLOCK_PATTERNS
    windowed_lines = set()
    seen = set()  # (lineno, label, excerpt): de-duplicates matches repeated in window overlaps
    for lineno, line, windowed in pieces:
        if header_pending and line.strip():
            header_pending = False
            if not windowed:
                csv_header = _detect_csv_header(line)
        if windowed:
            windowed_lines.add(lineno)
            new = []
            for label, rx in block_patterns:
                m = rx.search(line)
                if m: new.append(("block", label, lineno, redact(m.group(0))))
            if text_mode:
                for label, rx in WARN_PATTERNS:
                    m = rx.search(line)
                    if m: new.append(("warn", label, lineno, redact(m.group(0))))
                new.extend(entropy_findings(line, lineno))
            for f in new:
                # One finding per (line, label), as for an ordinary line; windows overlap.
                if (lineno, f[1]) not in seen:
                    seen.add((lineno, f[1]))
                    findings.append(f)
        else:
            if ALLOW_MARK.search(line):
                continue
            for label, rx in block_patterns:
                if text_mode and label == ETH_KEY_LABEL:
                    m, sup = _eth_key_match(line, rx, csv_header)
                    suppressed += sup
                    if m: findings.append(("block", label, lineno, redact(m)))
                    continue
                m = rx.search(line)
                if m: findings.append(("block", label, lineno, redact(m.group(0))))
            if text_mode:
                for label, rx in WARN_PATTERNS:
                    m = rx.search(line)
                    if m: findings.append(("warn", label, lineno, redact(m.group(0))))
                findings.extend(entropy_findings(line, lineno))
        if len(findings) >= max_findings:
            findings.append(("warn", "scan truncated", lineno, "too many findings"))
            break
    if suppressed:
        # Never silent: an operator who genuinely put a key under a hash-named
        # field (the residual risk documented above `_eth_key_match`) still gets
        # one visible line naming the count, not a quiet all-clear.
        findings.append(("warn",
                         "%d 32-byte hex value(s) under hash-named fields not "
                         "treated as keys" % suppressed, 0,
                         "txHash/blockHash/topics/etc. — see README"))
    if windowed_lines:
        findings.append(("warn", LONG_LINE_LABEL, 0,
                         "%d line(s) longer than %s scanned in overlapping windows; "
                         "`lint: allow` markers and the hash-field exemption were not "
                         "applied to them" % (len(windowed_lines), _mib(LONG_LINE_CHARS))))
    return findings


def _text_pieces(text):
    return _LineSplitter().feed(text, final=True)


def scan_text(text, max_findings=40, block_patterns=None):
    block_patterns = BLOCK_PATTERNS if block_patterns is None else block_patterns
    return _scan_lines(_text_pieces(text), block_patterns, True, max_findings)


TRUNCATED_LABEL = "scan incomplete"
# GitHub hard-blocks any single file over 100 MiB on push ("GitHub blocks files larger
# than 100 MiB", docs.github.com, "About large files on GitHub", checked 2026-09-29).
# Hubs federate over git, so nothing bigger can travel through a GitHub-hosted hub
# anyway. The scan cap matches it: everything that can federate is scanned in full.
# Cost at the cap: ~354 ms/MiB on all-printable text, so ~35 s for 100 MiB, in bounded memory.
GITHUB_FILE_LIMIT = 100 << 20
DEFAULT_MAX_BYTES = GITHUB_FILE_LIMIT

# --- archive detection (issue #20) ---
#
# The scan reads raw bytes only: a secret sitting inside a compressed member of a
# zip/tar/gzip is invisible to the block/warn patterns above until that member is
# decompressed, and the binary path (see `scan_file`) runs its patterns over the
# *compressed* bytes, which is close to useless — compression destroys the plaintext
# shapes those patterns look for. Before this fix `scan_file` printed nothing to flag
# that, so a publisher who had not read the README had no runtime signal at all.
# Enumerating archive members is the planned real fix (not yet built, per the issue);
# this is the cheap half: recognise the container by its leading magic bytes — file
# extensions are an easy thing to get wrong or omit — and say out loud that the
# interior went unscanned, using the same PARTIAL verdict the over-cap case already
# uses, so a publisher sees one consistent signal for "this scan covered less than
# the whole file" rather than two different silences.
ARCHIVE_LABEL = "archive members not scanned"


def _detect_archive_magic(head):
    """Archive family from the file's leading bytes, or None. `head` must be at least
    262 bytes for the tar check (ustar magic lives at offset 257); shorter heads just
    skip that check, which is fine — a tar too short to carry that magic is also too
    short to carry a member worth flagging."""
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "zip"
    if head[:3] == b"BZh":
        return "bzip2"
    if head[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    return None


def default_max_bytes():
    """The scan cap. COMMONS_LINT_MAX_BYTES can only LOWER it (tests use it to cross
    the cap cheaply); a value at or above the default, or unparsable, is ignored, so
    an environment variable can never widen the unscanned tail."""
    raw = os.environ.get("COMMONS_LINT_MAX_BYTES", "")
    try:
        v = int(raw)
    except ValueError:
        return DEFAULT_MAX_BYTES
    return v if 0 < v < DEFAULT_MAX_BYTES else DEFAULT_MAX_BYTES


def _mib(n):
    return "%.1f MiB" % (n / float(1 << 20))


def scan_file(path, max_bytes=None):
    if max_bytes is None:
        max_bytes = default_max_bytes()
    try:
        with open(path, "rb") as f:
            # Sniff at least 8 KiB for NUL (the binary test), whatever the chunk size.
            first = f.read(min(max(CHUNK_BYTES, 8192), max_bytes))
            binary = b"\0" in first[:8192]
            archive_kind = _detect_archive_magic(first)

            def chunks():
                total = len(first)
                yield first
                while total < max_bytes:
                    b = f.read(min(CHUNK_BYTES, max_bytes - total))
                    if not b:
                        return
                    total += len(b)
                    yield b

            def pieces():
                dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
                split = _LineSplitter()
                for b in chunks():
                    yield from split.feed(dec.decode(b))
                yield from split.feed(dec.decode(b"", final=True), final=True)

            if binary:
                # Binary: WARN_PATTERNS/entropy are noise on binary bytes (delimiters,
                # base64-shaped protobuf fields, etc.), but a block-pattern credential
                # sitting verbatim in plaintext bytes is real and must not be waved
                # through. Use the binary-only pattern set (leading \b stripped);
                # warn/entropy scanning stays skipped for binary content.
                findings = _scan_lines(pieces(), BLOCK_PATTERNS_BINARY, False, 40)
            else:
                findings = _scan_lines(pieces(), BLOCK_PATTERNS, True, 40)
            # One byte past the cap tells us whether anything went unscanned, even if
            # the scan above stopped early at max_findings.
            f.seek(max_bytes)
            truncated = bool(f.read(1))
        size = os.path.getsize(path) if truncated else None
    except OSError as e:
        return [("warn", "unreadable file", 0, str(e))]
    if truncated:
        # A partial scan that reports "clean" is worse than no scan: it is a
        # false all-clear. Every truncation must be said out loud.
        note = ("only the first %s of %s was checked; the remaining %s "
                "was NOT scanned for secrets" % (
                    _mib(max_bytes), _mib(size), _mib(size - max_bytes)))
        if size > GITHUB_FILE_LIMIT:
            note += " (GitHub also rejects files over 100 MiB: partition it)"
        findings.append(("warn", TRUNCATED_LABEL, 0, note))
    if archive_kind:
        # The scan above ran over compressed bytes (binary path, if NUL showed up in
        # the sniff window) or found nothing to do (text path): either way the member
        # content was never examined. Marked PARTIAL like the over-cap case (see
        # `is_partial`) so the two "this scan covered less than the whole file" signals
        # look the same at the call site, instead of one being silent.
        findings.append(("warn", ARCHIVE_LABEL, 0,
                         "%s archive detected (%s); its members were NOT scanned for "
                         "secrets — check them yourself before publishing, or wait for "
                         "member-aware scanning (planned, not yet built)"
                         % (archive_kind, os.path.basename(path))))
    return findings


def is_partial(findings):
    return any(f[1] in (TRUNCATED_LABEL, ARCHIVE_LABEL) for f in findings)


def _scan_binary_text(text, max_findings=40):
    return _scan_lines(_text_pieces(text), BLOCK_PATTERNS_BINARY, False, max_findings)


# --- topic-scoped forbidden field names (block) ---
#
# A different question from BLOCK_PATTERNS, not a bigger version of it. Those look for
# credential *shapes*, which are recognisable anywhere and so can be a tool default.
# These are identifiers whose danger depends entirely on the topic: `account_id`
# deanonymises a provider's earnings history in a hub about provider economics, and is a
# harmless join key in a hub about anything else. `account_id: 81234` carries no signal
# a general lint could act on, which is exactly why the list has to come from a
# collection's own declared policy and never from a default here.
#
# Reported at the same severity as a credential, because the consequence is the same:
# blobs are immutable and replicate, and `retract` is best-effort recall, not erasure.
ARCHIVE_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".zip")


def _json_key_names(node, out, depth=0):
    """Collect keys up to the nesting limit; return whether coverage is complete."""
    if not isinstance(node, (dict, list)):
        return True
    if depth > 64:        # cycles are impossible in decoded JSON; depth bombs are not
        return False
    complete = True
    if isinstance(node, dict):
        for k, v in node.items():
            out.append(k)
            if not _json_key_names(v, out, depth + 1):
                complete = False
    else:
        for v in node:
            if not _json_key_names(v, out, depth + 1):
                complete = False
    return complete


def forbidden_key_findings(path, forbidden):
    """Findings for a collection's declared forbidden FIELD NAMES.

    Covers JSON object keys through depth 64, JSONL (per line), and CSV header cells —
    measurement datasets are routinely CSV, so a JSON-keys-only check would miss the
    same leak in the format most likely to carry it.

    Names are matched whole and case-insensitively; substrings are deliberately not
    matched, because `id` would then flag `machine_id`, `model_id` and every other
    legitimate column. **A denylist is only a floor**: a contributor who exports `acct`
    instead of `account_id` passes cleanly, and only a closed-property member schema
    catches that. Anything this cannot parse is reported as *not covered* rather than
    passed silently, so the output never implies more coverage than it has.
    """
    wanted = {k.strip().lower() for k in (forbidden or [])
              if isinstance(k, str) and k.strip()}
    if not wanted:
        return []
    name = os.path.basename(path)
    if path.lower().endswith(ARCHIVE_SUFFIXES):
        # The secret lint scans archive bytes with the binary pattern set, which finds credential shapes but cannot see structure.
        return [("warn", "archive interior not scanned for forbidden keys", 0, name)]
    try:
        with open(path, "rb") as f:
            # This is a leak gate: a prefix cannot establish coverage of a dataset.
            # The hub's temporary-file path uses this same complete scan.
            raw = f.read()
    except OSError as e:
        return [("warn", "unreadable file", 0, str(e))]
    if b"\0" in raw[:8192]:
        return [("warn", "binary content not scanned for forbidden keys", 0, name)]
    text = raw.decode("utf-8-sig", errors="replace")

    hits = {}        # lowered name -> (lineno, name as written, where)

    def note(key, lineno, where):
        k = (key or "").strip()
        if k.lower() in wanted and k.lower() not in hits:
            hits[k.lower()] = (lineno, k, where)

    covered = None
    warnings = []
    first = next((l for l in text.splitlines() if l.strip()), "")
    json_shaped = first.lstrip().startswith(("{", "["))
    try:                                             # 1. one JSON document
        doc = json.loads(text)
        covered = "JSON"
        keys = []
        if not _json_key_names(doc, keys):
            warnings.append(("warn", "nesting beyond 64 levels not covered by the "
                             "forbidden-key check", 0, name))
        for k in keys:
            note(k, 0, "JSON object key")
    except (ValueError, RecursionError):
        pass
    if covered is None:                              # 2. JSONL, one object per line
        rows = [(i, l) for i, l in enumerate(text.splitlines(), 1) if l.strip()]
        docs, bad_lines = [], 0
        for i, line in rows:
            try:
                docs.append((i, json.loads(line)))
            except (ValueError, RecursionError):
                bad_lines += 1
        if docs:
            covered = "JSONL"
            for i, doc in docs:
                keys = []
                if not _json_key_names(doc, keys):
                    warnings.append(("warn", "nesting beyond 64 levels not covered by the "
                                     "forbidden-key check", i, name))
                for k in keys:
                    note(k, i, "JSONL object key")
        if bad_lines and (docs or json_shaped):
            warnings.append(("warn", "%d line(s) not covered by the forbidden-key "
                             "check: invalid JSON/JSONL" % bad_lines, 0, name))
    if covered is None and not json_shaped:           # 3. CSV header row
        try:
            cells = next(csv.reader(io.StringIO(first)))
        except (csv.Error, StopIteration):
            cells = []
        # One cell is any line of prose; treat a delimited row as a header, and say
        # nothing is covered otherwise rather than pretending a sentence was a schema.
        if len(cells) > 1:
            covered = "CSV header"
            for cell in cells:
                note(cell, 1, "CSV header cell")

    # A whole-file JSON document has no line to blame from the parse, but the operator has
    # to find the field to remove it, so resolve each hit to where the name is written.
    if covered == "JSON" and hits:
        lines = text.splitlines()
        for k, (lineno, written, where) in list(hits.items()):
            if lineno:
                continue
            needle = '"%s"' % written
            at = next((i for i, l in enumerate(lines, 1) if needle in l), 0)
            hits[k] = (at, written, where)

    out = [("block", "forbidden key %r (%s)" % (written, where), lineno, written)
           for lineno, written, where in sorted(hits.values(), key=lambda h: (h[0], h[1]))]
    if covered is None:
        out.append(("warn", "not JSON/JSONL/CSV — forbidden-key check does not cover "
                            "this content", 0, name))
    out.extend(warnings)
    return out


def main(argv):
    if len(argv) < 2:
        sys.exit("usage: publish_lint.py <file> [...]")
    total_block = 0
    partial = 0
    for path in argv[1:]:
        findings = scan_file(path)
        partial += is_partial(findings)
        for sev, label, lineno, excerpt in findings:
            print("%-5s %s:%s  %s  [%s]" % (sev.upper(), os.path.basename(path),
                                            lineno or "?", label, excerpt))
            if sev == "block": total_block += 1
    verdict = "clean" if total_block == 0 else "%d blocking finding(s)" % total_block
    if partial:
        verdict += " (PARTIAL: %d file(s) only partly scanned)" % partial
    print("secret-lint: %s" % verdict)
    return 1 if total_block else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
