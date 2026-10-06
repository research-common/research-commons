#!/usr/bin/env bash
# Receiver-side anchor trust: metadata is not Bitcoin verification, and an anchor
# event can checkpoint only its signer's own log. All identities/roots are disposable.
set -euo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"
LAB="$(mktemp -d -t commons-anchor-trust-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT

python3 - "$COMMONS" "$LAB" <<'PY'
import hashlib, importlib.machinery, importlib.util, json, os, secrets, sys
from pathlib import Path
code, lab = sys.argv[1], Path(sys.argv[2])
os.environ['COMMONS_ROOT'] = str(lab / 'unit')
loader = importlib.machinery.SourceFileLoader('anchor_test', code)
spec = importlib.util.spec_from_loader(loader.name, loader)
c = importlib.util.module_from_spec(spec)
loader.exec_module(c)
root = Path(c.ROOT)
Path(c.ANCHOR_DIR).mkdir(parents=True)
keys = {}
for name in ('alice', 'bob'):
    key = lab / (name + '.key')
    key.write_text('0x' + secrets.token_hex(32))
    key.chmod(0o600)
    keys[name] = str(key)

def append(who, action, aid, digest, ts, **extra):
    os.environ['COMMONS_SIGNING_KEY'] = keys[who]
    e = {'schema': c.SCHEMA, 'action': action, 'agent': who,
         'id': aid, 'sha256': digest, 'ts': ts}
    e.update(extra)
    addr, sig, sig2 = c.sign_entry(e, dual=True)
    e.update(addr=addr, sig=sig, sig2=sig2)
    c.ledger_commit(e)
    return e

def log(e): return e['addr'].lower() + '.jsonl'
def head(e): return c.ledger_head(str(Path(c.LEDGER_DIR) / log(e)))
def merkle(heads):
    layer = [hashlib.sha256((k + ':' + v).encode()).hexdigest()
             for k, v in sorted(heads.items())]
    while len(layer) > 1:
        layer = [hashlib.sha256((layer[i] + (layer[i+1] if i+1 < len(layer)
                 else layer[i])).encode()).hexdigest() for i in range(0, len(layer), 2)]
    return layer[0]
def checkpoint(name, heads, created='2001-01-01T00:00:00Z', **extra):
    rec = {'schema': c.SCHEMA, 'created': created, 'heads': heads,
           'root': merkle(heads), 'anchored': 'confirmed', 'bitcoin_blocks': [1]}
    rec.update(extra)
    p = Path(c.ANCHOR_DIR) / (name + '.json')
    p.write_text(json.dumps(rec))
    return p, rec

def clear():
    for p in Path(c.ANCHOR_DIR).glob('*.json'): p.unlink()
    c._ANCHOR_CACHE['key'] = None

def check(label, condition):
    assert condition, label
    print('  ok  ' + label)

digest = hashlib.sha256(b'same independently published bytes').hexdigest()
aid = 'ds-' + digest[:8]
a = append('alice', 'publish', aid, digest, '2026-01-01T00:00:00Z')
ah = head(a)
ap, ar = checkpoint('anchor-alice', {log(a): ah}, created='2026-01-01T00:00:01Z', anchored='none')
aa = append('alice', 'anchor', 'anchor-alice', ar['root'], '2026-01-01T00:00:01Z')
b = append('bob', 'publish', aid, digest, '2026-01-01T00:00:02Z')
bh = head(b)
check('honest first publisher is Alice', c.first_publisher(aid)[0] == a['addr'].lower())

bp, br = checkpoint('anchor-forged', {log(b): bh}, verified_locally=True,
                    confirmed_at='2001-01-01T00:00:00Z', ots_proof='missing.root.ots')
check('proofless confirmed JSON cannot seize first publisher', c.first_publisher(aid)[0] == a['addr'].lower())
check('forged JSON cannot smear the honest publisher', not c.backdating_flags())
check('unsigned anchor cannot bound a signed publisher', bh not in c.anchor_bounds())

ba = append('bob', 'anchor', 'anchor-forged', br['root'], '2026-01-01T00:00:03Z')
check('signed checkpoint is still only local', c.anchor_bounds()[bh][1] == 'local')
check('JSON created/confirmed_at cannot replace signed checkpoint time', c.anchor_bounds()[bh][0] == c.parse_ts(ba['ts']))
check('verified_locally=true in replicated JSON confers no trust', all(q == 'local' for _, q in c.anchor_bounds().values()))
check('signed later checkpoint cannot win with earlier JSON metadata', c.first_publisher(aid)[0] == a['addr'].lower())
check('local bound display discloses self-declared time', 'self-declared' in c.fmt_bound(*c.anchor_bounds()[bh]))

# An operator can record all heads, but its signature cannot checkpoint other keys.
clear()
p, rec = checkpoint('anchor-cross-log', {log(a): head(aa), log(b): head(ba)})
append('bob', 'anchor', 'anchor-cross-log', rec['root'], '2026-01-01T00:00:04Z')
check('signed anchor scopes coverage to its own signer log', ah not in c.anchor_bounds() and bh in c.anchor_bounds())

# An unsigned metadata edit must not widen a signed commitment.
rec['heads'][log(a)] = ah
p.write_text(json.dumps(rec))
check('root mismatch contributes no bound', not c.anchor_bounds())
clear()
p, rec = checkpoint('anchor-wrong-id', {log(a): ah})
check('matching root alone without the signed anchor id is insufficient', not c.anchor_bounds())

# A valid anchor event moved into someone else's log is not authorization.
clear()
p, rec = checkpoint('anchor-misplaced', {log(a): ah})
e = append('alice', 'anchor', 'anchor-misplaced', rec['root'], '2026-01-01T00:00:05Z')
alog = Path(c.LEDGER_DIR) / log(a)
lines = alog.read_text().splitlines()
last = lines.pop()
alog.write_text('\n'.join(lines) + '\n')
with (Path(c.LEDGER_DIR) / log(b)).open('a') as f: f.write(last + '\n')
check('signed event must reside in signer-named log', not c.anchor_bounds())

# A forged signature on an otherwise matching event contributes nothing.
clear()
p, rec = checkpoint('anchor-invalid-sig', {log(a): ah})
e = append('alice', 'anchor', 'anchor-invalid-sig', rec['root'], '2026-01-01T00:00:06Z')
lines = alog.read_text().splitlines()
x = json.loads(lines[-1]); x['sha256'] = '0' * 64
lines[-1] = json.dumps(x)
alog.write_text('\n'.join(lines) + '\n')
rec['root'] = '0' * 64
p.write_text(json.dumps(rec))
check('invalid commitment cannot contribute coverage', not c.anchor_bounds())
# Keep a valid root but put a tampered signature on its matching event.
x['sha256'] = merkle(rec['heads']); x['sig'] = '0x' + '0' * 130
lines[-1] = json.dumps(x); alog.write_text('\n'.join(lines) + '\n')
rec['root'] = x['sha256']; p.write_text(json.dumps(rec))
check('invalid anchor signature cannot contribute coverage', not c.anchor_bounds())

# Future heads are not checkpoints of the prefix preceding the signed anchor.
clear()
future = append('alice', 'publish', 'ds-future01', digest, '2026-01-01T00:00:07Z')
fh = head(future)
p, rec = checkpoint('anchor-future', {log(a): fh})
anchor = append('alice', 'anchor', 'anchor-future', rec['root'], '2026-01-01T00:00:06Z')
lines = alog.read_text().splitlines(); lines[-2], lines[-1] = lines[-1], lines[-2]
alog.write_text('\n'.join(lines) + '\n')
check('head appearing after anchor event is not authorized', not c.anchor_bounds())

clear()
for i, rec in enumerate(([], {}, {'heads': []}, {'heads': {'../foreign.jsonl': ah}, 'root': ah},
                         {'heads': {log(a): 123}, 'root': ah})):
    (Path(c.ANCHOR_DIR) / ('malformed-%d.json' % i)).write_text(json.dumps(rec))
(Path(c.ANCHOR_DIR) / 'malformed-json.json').write_text('{')
check('malformed anchor input is ignored without a crash', not c.anchor_bounds())

# Unsigned operational coverage does not become signed first-publisher evidence.
clear()
u = Path(c.LEDGER_DIR) / 'local-unsigned.jsonl'
u.write_text(json.dumps({'action': 'publish', 'id': 'ds-unsigned', 'ts': '2026-01-01T00:00:00Z'}) + '\n')
uh = c.ledger_head(str(u))
p, rec = checkpoint('anchor-unsigned', {'local-unsigned.jsonl': uh})
check('valid unsigned checkpoint preserves unsigned-log drift coverage', c.anchor_bounds()[uh][1] == 'local')
with u.open('a') as f: f.write(json.dumps(a) + '\n')
sh = c.ledger_head(str(u)); rec['heads']['local-unsigned.jsonl'] = sh
rec['root'] = merkle(rec['heads']); p.write_text(json.dumps(rec))
check('unsigned checkpoint cannot authenticate a signed event in unsigned log', sh not in c.anchor_bounds())

# A forged checkpoint must not upgrade a backdated derivation commit into
# independence evidence against a publisher with an authenticated checkpoint.
clear()
ap.write_text(json.dumps(ar))
tid, salt = 'tk-commit-forge', 'test-salt'
commitment = hashlib.sha256((digest + salt).encode()).hexdigest()
commit = append('bob', 'derivation-commit', tid, commitment,
                '2025-01-01T00:00:00Z', commitment=commitment)
ch = head(commit)
checkpoint('anchor-forged-commit', {log(b): ch})
commits = c.derivation_commits(tid)
check('forged anchor cannot bound a derivation commit',
      commits[b['addr'].lower()][0][2:] == (c.UNANCHORED, 'none'))
load_manifest = c.load_manifest
c.load_manifest = lambda *args, **kwargs: {'content': {'sha256': digest}}
verdict, _ = c.derivation_evidence(tid, aid, b['addr'], {'salt': salt},
                                   commits, c.first_publisher(aid))
c.load_manifest = load_manifest
check('forged anchor cannot grant commit-reveal quorum credit', verdict == 'reference')

# An unsigned line naming a key it cannot prove it holds gets no bound from an
# unsigned checkpoint, so it cannot become commit-reveal evidence for that key.
clear()
ap.write_text(json.dumps(ar))
tid2 = 'tk-unsigned-addr'
commitment2 = hashlib.sha256((digest + salt).encode()).hexdigest()
with u.open('a') as f:
    f.write(json.dumps({'schema': c.SCHEMA, 'action': 'derivation-commit', 'agent': 'bob',
                        'id': tid2, 'sha256': commitment2, 'commitment': commitment2,
                        'addr': b['addr'], 'ts': '2025-01-01T00:00:00Z'}) + '\n')
uh2 = c.ledger_head(str(u))
checkpoint('anchor-unsigned-addr', {'local-unsigned.jsonl': uh2}, anchored='none')
check('unsigned checkpoint does not bound an unsigned line claiming an addr',
      uh2 not in c.anchor_bounds())
c.load_manifest = lambda *args, **kwargs: {'content': {'sha256': digest}}
verdict, _ = c.derivation_evidence(tid2, aid, b['addr'], {'salt': salt},
                                   c.derivation_commits(tid2), c.first_publisher(aid))
c.load_manifest = load_manifest
check('unsigned addr-claiming commit cannot earn commit-reveal', verdict != 'commit-reveal')
check('unsigned addr-less lines keep drift coverage', uh in c.anchor_bounds())

# A signed anchor event dated BEFORE a line it covers contradicts its own hash
# chain: it is ignored, so a copier cannot pull its later publish ahead with it.
clear()
ap.write_text(json.dumps(ar))
c._FIRSTPUB_CACHE['key'] = None
p, rec = checkpoint('anchor-backdated-event', {log(b): c.ledger_head(str(Path(c.LEDGER_DIR) / log(b)))})
bad = append('bob', 'anchor', 'anchor-backdated-event', rec['root'], '2001-01-01T00:00:00Z')
c._ANCHOR_CACHE['key'] = None; c._FIRSTPUB_CACHE['key'] = None
check('signed anchor event older than a covered line contributes no bound', bh not in c.anchor_bounds())
check('incoherent backdated anchor event cannot seize first publisher',
      c.first_publisher(aid)[0] == a['addr'].lower())
check('incoherent backdated anchor event cannot flag the honest publisher', not c.backdating_flags())

# The quality-order helper is also used across competing publishers, not just when
# choosing multiple anchors for one line. No metadata currently produces bitcoin.
check('Bitcoin evidence sorts before a backdated local checkpoint',
      c.bound_order((100, 'bitcoin')) < c.bound_order((1, 'local')))
check('local sorts before unanchored', c.bound_order((100, 'local')) < c.bound_order((c.UNANCHORED, 'none')))
clear()
bounds = {ah: (100, 'bitcoin'), bh: (1, 'local')}
c.anchor_bounds = lambda: bounds
c._FIRSTPUB_CACHE['key'] = None
check('first-publisher ordering uses quality before timestamp', c.first_publisher(aid)[0] == a['addr'].lower())
check('publication evidence also prefers quality before timestamp', c.publish_ordering_evidence(aid)[1] == (100, 'bitcoin'))
print('anchor trust unit cases: ALL GREEN')
PY

# End-to-end: a proofless fabricated anchor can still be transported as data in this
# read-side fix, but it must have no priority effect before/after hub CI and pull.
export COMMONS_ROOT="$LAB/lead"
"$COMMONS" hub init "$COMMONS_ROOT" >/dev/null
export COMMONS_SIGNING_KEY="$LAB/alice.key" COMMONS_AGENT=alice
A=$("$COMMONS" peer whoami 2>/dev/null | head -1)
B=$(COMMONS_SIGNING_KEY="$LAB/bob.key" "$COMMONS" peer whoami 2>/dev/null | head -1)
printf 'x,y\n1,2\n' > "$LAB/d.csv"
AID=$("$COMMONS" publish dataset "$LAB/d.csv" probe --license CC0-1.0 --obtainability open 2>/dev/null)
"$COMMONS" anchor --local-only >/dev/null
for who in "$A" "$B"; do "$COMMONS" peer add "$who" --agent-id test --trust full >/dev/null; done
export A AID
assert_publisher() {
  python3 - "$COMMONS" <<'PY'
import os, runpy, sys
c = runpy.run_path(sys.argv[1])
assert c['first_publisher'](os.environ['AID'])[0] == os.environ['A'].lower()
assert not c['backdating_flags']()
PY
}
gx() { git -c user.email=test@example.invalid -c user.name=test "$@"; }
cd "$COMMONS_ROOT"
gx add registry store .commons-hub .gitignore README.md .github
gx commit -qm base
BASE=$(git rev-parse HEAD)
git clone -q "$COMMONS_ROOT" "$LAB/contributor"
# Publish in a clean hub so content dedup doesn't suppress the second creation claim.
mkdir -p "$LAB/scratch/registry"
COMMONS_ROOT="$LAB/scratch" COMMONS_SIGNING_KEY="$LAB/bob.key" COMMONS_AGENT=bob \
  "$COMMONS" publish dataset "$LAB/d.csv" probe --license CC0-1.0 --obtainability open >/dev/null 2>&1
BL="$(echo "$B" | tr 'A-Z' 'a-z').jsonl"
cp "$LAB/scratch/registry/ledger/$BL" "$LAB/contributor/registry/ledger/$BL"
python3 - "$LAB/contributor" "$BL" <<'PY'
import hashlib, json, sys
from pathlib import Path
root, name = Path(sys.argv[1]), sys.argv[2]
last = (root / 'registry/ledger' / name).read_bytes().splitlines()[-1]
heads = {name: hashlib.sha256(last).hexdigest()}
digest = hashlib.sha256((name + ':' + heads[name]).encode()).hexdigest()
rec = {'schema': 'rc.v1', 'created': '2001-01-01T00:00:00Z', 'root': digest,
       'heads': heads, 'leaves': [digest], 'anchored': 'confirmed', 'bitcoin_blocks': [1]}
(root / 'registry/anchors/anchor-20010101T000000Z.json').write_text(json.dumps(rec))
PY
cd "$LAB/contributor"
gx add registry/anchors registry/ledger
gx commit -qm 'contributor checkpoint'
for who in "$A" "$B"; do COMMONS_ROOT="$PWD" "$COMMONS" peer add "$who" --agent-id test --trust full >/dev/null; done
COMMONS_ROOT="$PWD" assert_publisher
COMMONS_ROOT="$PWD" "$COMMONS" hub check --base "$BASE" > "$LAB/check.out" 2>&1
cd "$COMMONS_ROOT"
git remote add contributor "$LAB/contributor"
"$COMMONS" pull contributor --branch main > "$LAB/pull.out" 2>&1
assert_publisher
printf '  ok  forged anchor cannot seize priority or smear origin after hub check/pull\n'
printf 'test-anchor-trust: ALL GREEN\n'
