package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/wire"
)

// External signing (identity profile §8): --prepare writes a package and appends nothing; --complete recomputes
// the PAE and id, verifies the signature, re-runs every check and commits only when the signer's log has not moved.
// The device is simulated in-test: the key file is loaded by the test, never by the command that prepares.

// extHome is a store whose root key file is kept apart: commands run without --key; the test signs.
type extHome struct {
	t      *testing.T
	store  string
	dir    string
	key    wire.Key // the "device"
	keyF   string   // its file, for direct-signing comparisons only
	signer string
}

func newExtHome(t *testing.T, alg string) *extHome {
	t.Helper()
	keys := t.TempDir()
	f, s := newKeyFile(t, keys, alg)
	lk, prob := loadKey(f, "test")
	if prob != nil {
		t.Fatal(prob)
	}
	return &extHome{t: t, store: drillStore(t), dir: t.TempDir(), key: lk.Key, keyF: f, signer: s}
}

// run runs a command against the store with no key named.
func (h *extHome) run(args ...string) result { return runIn(h.store, nil, append(args, "--json")...) }

func (h *extHome) runStdin(in string, args ...string) result {
	var o, e bytes.Buffer
	code := Main(append(args, "--json"), &Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" },
		Getwd: func() (string, error) { return h.store, nil }, Build: Build{Version: "test", Commit: "0000000"}, Stdin: strings.NewReader(in)})
	return result{code, o.String(), e.String()}
}

func (h *extHome) path(name string) string { return filepath.Join(h.dir, name) }

// prepare runs cmd with --prepare into a new file and returns the package path and the parsed package.
func (h *extHome) prepare(name string, cmd ...string) (string, *canon.Object) {
	h.t.Helper()
	p := h.path(name)
	r := h.run(append(cmd, "--prepare", p, "--signer", h.signer)...)
	if r.code != ExitOK {
		h.t.Fatalf("%v --prepare: %d\n%s%s", cmd, r.code, r.stdout, r.stderr)
	}
	return p, readPkg(h.t, p)
}

func readPkg(t *testing.T, p string) *canon.Object {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(bytes.TrimSuffix(b, []byte("\n")))
	if err != nil {
		t.Fatalf("package is not strict JSON: %v", err)
	}
	return v.(*canon.Object)
}

func paeOf(t *testing.T, pkg *canon.Object) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(string(pkg.Members["pae"].(canon.String)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// sign is the device: it signs the package's PAE bytes and writes the signature file.
func (h *extHome) sign(name string, pkg *canon.Object) string {
	h.t.Helper()
	p := h.path(name)
	os.WriteFile(p, []byte(h.key.Sign(paeOf(h.t, pkg))+"\n"), 0o644)
	return p
}

func (h *extHome) complete(cmd []string, pkgPath, sigPath string) result {
	return h.run(append(cmd, "--complete", pkgPath, "--signature", sigPath)...)
}

func writePkg(t *testing.T, p string, pkg *canon.Object) {
	t.Helper()
	os.Remove(p)
	if err := os.WriteFile(p, append(canon.Encode(pkg), '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func clonePkg(pkg *canon.Object) *canon.Object {
	v, _ := canon.Parse(canon.Encode(pkg))
	return v.(*canon.Object)
}

// TestExternalSigningEndToEnd: an identity's root key lives on a "device"; the store never sees its file. The
// inception, a grant and a cut are prepared, signed in-test over the PAE bytes, and completed; each committed line
// is byte-identical to what direct signing with the key file writes at the same --ts on a twin store. A delegate's
// act (publish --as) goes the same way. Both algorithms.
func TestExternalSigningEndToEnd(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			ts := []string{"--ts", "2026-11-14T00:00:00Z"}
			root := newExtHome(t, alg)
			twin := &idHome{t: t, store: drillStore(t), key: root.keyF, signer: root.signer}

			// inception
			before := storeBytes(t, root.store)
			newCmd := append([]string{"identity", "new"}, ts...)
			pp, pkg := root.prepare("new.pkg", newCmd...)
			if storeBytes(t, root.store) != before {
				t.Fatal("--prepare wrote to the store")
			}
			if pkg.Members["format"] != canon.String(SigningPackageFormat) || pkg.Members["log_head"] != canon.String("genesis") {
				t.Fatalf("package: %s", canon.Encode(pkg))
			}
			pae := paeOf(t, pkg)
			if wire.ID(pae) != string(pkg.Members["statement"].(canon.String)) {
				t.Fatal("package id is not sha256 of its pae")
			}
			r := root.complete([]string{"identity", "new"}, pp, root.sign("new.sig", pkg))
			if r.code != ExitOK {
				t.Fatalf("complete: %d %s%s", r.code, r.stdout, r.stderr)
			}
			ident := string(jsonOf(t, r).Members["identity"].(canon.String))
			if ident != string(pkg.Members["statement"].(canon.String)) {
				t.Fatalf("committed id %s != prepared %s", ident, pkg.Members["statement"])
			}
			direct := twin.ok(newCmd...)
			if direct.Members["identity"] != canon.String(ident) {
				t.Fatalf("direct signing gives %s", direct.Members["identity"])
			}
			if a, b := lineOf(t, root.store, ident), lineOf(t, twin.store, ident); a == "" || a != b {
				t.Fatalf("external line differs from the directly signed one:\n%s\n%s", a, b)
			}

			// a worker and its first line, held by both stores
			worker := newIDHome(t, alg)
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "worker first line"), "--licence", "CC0-1.0"))
			if r := runIn(root.store, nil, "pull", worker.store, "--json"); r.code != ExitOK {
				t.Fatal(r.stdout)
			}
			twin.pullFrom(worker)

			// grant
			grantCmd := append([]string{"identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d, "--permissions", anyContentPerm}, ts...)
			gp, gpkg := root.prepare("grant.pkg", grantCmd...)
			lh, _ := gpkg.Members["log_head"].(*canon.Object)
			if lh == nil || lh.Members["statement"] != canon.String(ident) || lh.Members["seq"] != canon.Int(0) {
				t.Fatalf("grant log_head: %s", canon.Encode(gpkg.Members["log_head"]))
			}
			gsig := root.sign("grant.sig", gpkg)
			if alg == wire.AlgEIP191 {
				// a device may return v∈{0,1} and high s: a valid encoding (wire note §4); the line stores the canonical one
				gsig = root.path("grant-alt.sig")
				os.WriteFile(gsig, []byte(nonCanonicalEIP191(t, root.key.Sign(paeOf(t, gpkg)))), 0o644)
			}
			r = root.complete([]string{"identity", "grant"}, gp, gsig)
			if r.code != ExitOK {
				t.Fatalf("grant complete: %d %s", r.code, r.stdout)
			}
			grant := string(jsonOf(t, r).Members["grant"].(canon.String))
			if g := twin.ok(grantCmd...); g.Members["grant"] != canon.String(grant) || lineOf(t, root.store, grant) != lineOf(t, twin.store, grant) {
				t.Fatalf("grant differs from direct signing: %s", canon.Encode(g))
			}

			// a delegate's act, prepared on the worker's store with the worker key held apart
			worker.pullFrom(&idHome{store: root.store})
			wext := &extHome{t: t, store: worker.store, dir: t.TempDir(), signer: worker.signer}
			wk, _ := loadKey(worker.key, "test")
			wext.key = wk.Key
			c1 := worker.file("c1", "an act for the identity, signed on a device")
			actCmd := append([]string{"publish", "--kind", "authored", "--content", c1, "--licence", "CC0-1.0", "--as", ident, "--grant", grant, "--no-holds"}, ts...)
			ap, apkg := wext.prepare("act.pkg", actCmd...)
			r = wext.run("publish", "--complete", ap, "--signature", wext.sign("act.sig", apkg), "--content", c1)
			if r.code != ExitOK {
				t.Fatalf("act complete: %d %s", r.code, r.stdout)
			}
			act := firstID(t, jsonOf(t, r))
			if !strings.Contains(r.stdout, `"state":"eligible"`) || act != string(apkg.Members["statement"].(canon.String)) {
				t.Fatalf("act: %s", r.stdout)
			}

			// cut, from a signature on standard input
			root.pullFrom(worker.store)
			cutCmd := append([]string{"identity", "cut", "--identity", ident, "--grant", grant, "--last-good", act, "--reason", "superseded"}, ts...)
			cp, cpkg := root.prepare("cut.pkg", cutCmd...)
			if !strings.Contains(string(canon.Encode(cpkg.Members["summary"])), "cannot be undone") {
				t.Fatal("cut summary does not say it cannot be undone")
			}
			r = root.runStdin(root.key.Sign(paeOf(t, cpkg)), "identity", "cut", "--complete", cp, "--signature", "-")
			if r.code != ExitOK || !strings.Contains(r.stdout, "keeps counting") {
				t.Fatalf("cut complete: %d %s", r.code, r.stdout)
			}
			cutID := firstID(t, jsonOf(t, r))
			twin.pullFrom(worker)
			if c := twin.ok(cutCmd...); firstID(t, c) != cutID || lineOf(t, root.store, cutID) != lineOf(t, twin.store, cutID) {
				t.Fatalf("cut differs from direct signing")
			}
		})
	}
}

func (h *extHome) pullFrom(store string) {
	h.t.Helper()
	if r := runIn(h.store, nil, "pull", store, "--json"); r.code != ExitOK {
		h.t.Fatalf("pull: %s", r.stdout)
	}
}

// lineOf is the stored line of id in the store, "" when none.
func lineOf(t *testing.T, store, id string) string {
	t.Helper()
	var found string
	filepath.WalkDir(filepath.Join(store, "statements"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, l := range bytes.Split(b, []byte("\n")) {
			if st, err := wire.ReadStored(l); err == nil && st.ID == id {
				found = string(l)
			}
		}
		return nil
	})
	return found
}

// TestExternalSigningAborts: every refusal of --complete leaves the store byte-identical, both algorithms: a bad
// signature, the wrong key, a moved log head, a mutated envelope, a package member that disagrees with the
// envelope (pae, statement, alg, signer, log_head, summary), a malformed package, a malformed signature encoding,
// lost eligibility, and the option conflicts of --prepare.
func TestExternalSigningAborts(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			ts := []string{"--ts", "2026-11-14T00:00:00Z"}
			root := newExtHome(t, alg)
			pp, pkg := root.prepare("new.pkg", append([]string{"identity", "new"}, ts...)...)
			if r := root.complete([]string{"identity", "new"}, pp, root.sign("new.sig", pkg)); r.code != ExitOK {
				t.Fatalf("inception: %s", r.stdout)
			}
			ident := string(pkg.Members["statement"].(canon.String))
			worker := newIDHome(t, alg)
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "w"), "--licence", "CC0-1.0"))
			root.pullFrom(worker.store)
			grantCmd := []string{"identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d, "--permissions", anyContentPerm}
			gp, gpkg := root.prepare("grant.pkg", append(grantCmd, ts...)...)
			good := root.sign("grant.sig", gpkg)
			other := newExtHome(t, alg)
			wrongKey := filepath.Join(root.dir, "wrong.sig")
			os.WriteFile(wrongKey, []byte(other.key.Sign(paeOf(t, gpkg))), 0o644)
			flip := func(s string) string {
				b := []byte(s)
				i := len(b) - 3
				if b[i] == '0' {
					b[i] = '1'
				} else {
					b[i] = '0'
				}
				return string(b)
			}
			badSig := filepath.Join(root.dir, "bad.sig")
			goodS, _ := os.ReadFile(good)
			os.WriteFile(badSig, []byte(flip(strings.TrimSpace(string(goodS)))), 0o644)
			upper := filepath.Join(root.dir, "upper.sig")
			os.WriteFile(upper, []byte(strings.ToUpper(strings.TrimSpace(string(goodS)))), 0o644)
			b64 := filepath.Join(root.dir, "b64.sig")
			raw, _ := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(goodS)), "0x"))
			os.WriteFile(b64, []byte(base64.StdEncoding.EncodeToString(raw)), 0o644)
			// a package whose derived members disagree with its envelope, each named
			mutated := func(name string, f func(p *canon.Object)) string {
				p := clonePkg(gpkg)
				f(p)
				path := root.path(name)
				writePkg(t, path, p)
				return path
			}
			envOf := func(p *canon.Object) *canon.Object { return p.Members["envelope"].(*canon.Object) }
			cases := []struct {
				name, pkg, sig string
				code           int
				want           string
			}{
				{"bad signature", gp, badSig, ExitDidNotStart, "signature-does-not-verify"},
				{"wrong key", gp, wrongKey, ExitDidNotStart, "signature-does-not-verify"},
				{"upper-case hex", gp, upper, ExitDidNotStart, "malformed-signature"},
				{"base64 signature", gp, b64, ExitDidNotStart, "malformed-signature"},
				{"mutated envelope (body)", mutated("m-body.pkg", func(p *canon.Object) {
					envOf(p).Members["body"].(*canon.Object).Members["permissions"] = canon.Array{}
				}), good, ExitDidNotStart, "malformed-package"},
				{"mutated envelope (ts), pae left", mutated("m-ts.pkg", func(p *canon.Object) {
					envOf(p).Members["ts"] = canon.String("2026-11-14T00:00:01Z")
				}), good, ExitDidNotStart, "package member pae"},
				{"envelope re-derived (ts, pae, statement, summary consistent)", mutated("m-rederived.pkg", func(p *canon.Object) {
					env := envOf(p)
					env.Members["ts"] = canon.String("2026-11-14T00:00:01Z")
					st, err := wire.CheckUnsigned(env)
					if err != nil {
						t.Fatal(err)
					}
					p.Members["pae"] = canon.String(base64.StdEncoding.EncodeToString(st.SignedString))
					p.Members["statement"] = canon.String(st.ID)
					p.Members["summary"] = summaryOf(st)
				}), good, ExitDidNotStart, "signature-does-not-verify"},
				{"pae field", mutated("m-pae.pkg", func(p *canon.Object) {
					p.Members["pae"] = canon.String(base64.StdEncoding.EncodeToString(append(paeOf(t, gpkg), ' ')))
				}), good, ExitDidNotStart, "package member pae"},
				{"pae not base64", mutated("m-pae64.pkg", func(p *canon.Object) { p.Members["pae"] = canon.String("!!") }), good, ExitDidNotStart, "package member pae"},
				{"statement field", mutated("m-id.pkg", func(p *canon.Object) { p.Members["statement"] = canon.String(d) }), good, ExitDidNotStart, "package member statement"},
				{"alg field", mutated("m-alg.pkg", func(p *canon.Object) { p.Members["alg"] = canon.String("x") }), good, ExitDidNotStart, "package member alg"},
				{"signer field", mutated("m-signer.pkg", func(p *canon.Object) { p.Members["signer"] = canon.String(worker.signer) }), good, ExitDidNotStart, "package member signer"},
				{"log_head field", mutated("m-head.pkg", func(p *canon.Object) { p.Members["log_head"] = canon.String("genesis") }), good, ExitDidNotStart, "package member log_head"},
				{"summary field", mutated("m-sum.pkg", func(p *canon.Object) {
					p.Members["summary"].(*canon.Object).Members["delegate"] = canon.String(root.signer)
				}), good, ExitDidNotStart, "package member summary"},
				{"unknown member", mutated("m-extra.pkg", func(p *canon.Object) { p.Keys = append(p.Keys, "x"); p.Members["x"] = canon.Null{} }), good, ExitDidNotStart, "malformed-package"},
				{"wrong format", mutated("m-fmt.pkg", func(p *canon.Object) { p.Members["format"] = canon.String("rc-key/0") }), good, ExitDidNotStart, "malformed-package"},
			}
			notJSON := root.path("garbage.pkg")
			os.WriteFile(notJSON, []byte("{not json"), 0o644)
			cases = append(cases, struct {
				name, pkg, sig string
				code           int
				want           string
			}{"not JSON", notJSON, good, ExitDidNotStart, "malformed-file"})
			before := storeBytes(t, root.store)
			for _, c := range cases {
				r := root.complete([]string{"identity", "grant"}, c.pkg, c.sig)
				if r.code != c.code || !strings.Contains(r.stdout, c.want) {
					t.Fatalf("%s: %d %s", c.name, r.code, r.stdout)
				}
				if storeBytes(t, root.store) != before {
					t.Fatalf("%s: the store changed", c.name)
				}
			}
			// the wrong command for the package
			if r := root.complete([]string{"identity", "cut"}, gp, good); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "not for this command") {
				t.Fatalf("cut --complete of a grant package: %d %s", r.code, r.stdout)
			}
			// options --complete takes from the package, and --prepare conflicts
			for _, bad := range [][]string{
				{"identity", "grant", "--complete", gp, "--signature", good, "--identity", ident},
				{"identity", "grant", "--complete", gp, "--signature", good, "--ts", "2026-11-14T00:00:00Z"},
				{"identity", "grant", "--complete", gp},
				{"identity", "grant", "--prepare", root.path("x.pkg"), "--complete", gp},
				{"identity", "new", "--prepare", root.path("x.pkg")},
				{"identity", "new", "--prepare", root.path("x.pkg"), "--signer", root.signer, "--key", root.keyF},
				{"identity", "new", "--prepare", root.path("x.pkg"), "--signer", root.signer, "--dry-run"},
				{"identity", "new", "--signer", root.signer},
				{"identity", "new", "--signature", good},
				{"identity", "new", "--prepare", gp, "--signer", root.signer}, // never overwritten
				{"publish", "--kind", "describes", "--about", ident, "--prepare", root.path("x.pkg"), "--signer", root.signer},
			} {
				if r := root.run(bad...); r.code != ExitDidNotStart {
					t.Fatalf("%v: %d %s", bad, r.code, r.stdout)
				}
			}
			if _, err := os.Stat(root.path("x.pkg")); err == nil {
				t.Fatal("a refused --prepare wrote a package")
			}
			if b, _ := os.ReadFile(gp); !bytes.Equal(b, append(canon.Encode(gpkg), '\n')) {
				t.Fatal("an existing package was overwritten")
			}
			if storeBytes(t, root.store) != before {
				t.Fatal("a refused option changed the store")
			}

			// stale prepare: the root's log moves (a second grant, signed directly) after the package was prepared
			worker2 := newIDHome(t, alg)
			d2 := firstID(t, worker2.ok("publish", "--kind", "authored", "--content", worker2.file("c0", "w2"), "--licence", "CC0-1.0"))
			root.pullFrom(worker2.store)
			if r := runIn(root.store, nil, append([]string{"identity", "grant", "--identity", ident, "--delegate", worker2.signer, "--delegate-inception", d2,
				"--permissions", anyContentPerm, "--key", root.keyF, "--json"}, ts...)...); r.code != ExitOK {
				t.Fatalf("direct grant: %s", r.stdout)
			}
			before = storeBytes(t, root.store)
			r := root.complete([]string{"identity", "grant"}, gp, good)
			if r.code != ExitWrong || !strings.Contains(r.stdout, "stale-prepare") || !strings.Contains(r.stdout, "your log moved since the package was prepared") {
				t.Fatalf("stale prepare: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, root.store) != before {
				t.Fatal("a stale completion changed the store")
			}
			conformance.Partial(t, "C-id-40", "the external-signing package (profile §8, prepare/complete) is exercised through the commands: a root key kept off the store signs the inception, a grant and a cut and a delegate key signs an act over the exact PAE bytes, each committed line equal to direct signing; every abort (bad signature, wrong key, moved head, mutated envelope, mismatched derived member, malformed package or signature, lost eligibility) appends nothing; a compromised operational host and hardware or connector signing are not drilled")
		})
	}
}

// TestExternalSigningEligibilityLost: a cut prepared, then the identity's grant becomes something the cut cannot
// name any more... the simplest honest loss: an act prepared under a grant, then the grant is cut before completion;
// --complete runs the identity evaluator over the signed act and refuses it (nothing appended). And an EIP-191
// signature in the high-s / v∈{0,1} encoding is accepted only in the canonical encoding (others exit 2).
func TestExternalSigningEligibilityLost(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			ts := []string{"--ts", "2026-11-14T00:00:00Z"}
			root := newIDHome(t, alg)
			ident := string(root.ok(append([]string{"identity", "new"}, ts...)...).Members["identity"].(canon.String))
			worker := newIDHome(t, alg)
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "w"), "--licence", "CC0-1.0"))
			root.pullFrom(worker)
			grant := string(root.ok(append([]string{"identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d, "--permissions", anyContentPerm}, ts...)...).Members["grant"].(canon.String))
			worker.pullFrom(root)
			wext := &extHome{t: t, store: worker.store, dir: t.TempDir(), signer: worker.signer}
			wk, _ := loadKey(worker.key, "test")
			wext.key = wk.Key
			c1 := worker.file("c1", "an act prepared before the cut")
			ap, apkg := wext.prepare("act.pkg", append([]string{"publish", "--kind", "authored", "--content", c1, "--licence", "CC0-1.0", "--as", ident, "--grant", grant, "--no-holds"}, ts...)...)
			sigF := wext.sign("act.sig", apkg)
			// the root cuts the grant keeping nothing; the worker's store receives the cut
			root.ok(append([]string{"identity", "cut", "--identity", ident, "--grant", grant, "--last-good", "none", "--reason", "superseded"}, ts...)...)
			worker.pullFrom(root)
			before := storeBytes(t, worker.store)
			r := wext.run("publish", "--complete", ap, "--signature", sigF, "--content", c1)
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "act-not-eligible") {
				t.Fatalf("completion after the cut: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, worker.store) != before {
				t.Fatal("a refused completion changed the store")
			}
			if alg != wire.AlgEIP191 {
				return
			}
			// EIP-191: v∈{0,1} is a valid encoding of the same signature (wire note §4): it passes the signature
			// check and reaches the same eligibility refusal; v out of range does not verify (exit 2)
			raw, _ := hex.DecodeString(strings.TrimPrefix(wext.key.Sign(paeOf(t, apkg)), "0x"))
			v01 := append([]byte{}, raw...)
			v01[64] -= 27
			if _, _, err := sig.RecoverEIP191(paeOf(t, apkg), v01); err != nil {
				t.Fatal(err)
			}
			alt := wext.path("v01.sig")
			os.WriteFile(alt, []byte("0x"+hex.EncodeToString(v01)), 0o644)
			r = wext.run("publish", "--complete", ap, "--signature", alt, "--content", c1)
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "act-not-eligible") {
				t.Fatalf("v∈{0,1}: %d %s", r.code, r.stdout)
			}
			v01[64] = 5
			os.WriteFile(alt, []byte("0x"+hex.EncodeToString(v01)), 0o644)
			r = wext.run("publish", "--complete", ap, "--signature", alt, "--content", c1)
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "signature-does-not-verify") {
				t.Fatalf("v=5: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, worker.store) != before {
				t.Fatal("a refused completion changed the store")
			}
		})
	}
}

// TestPrepareCompleteDigest: the printed pae_sha256 is sha256 of the package's PAE bytes, i.e. the proposed id.
func TestPrepareCompleteDigest(t *testing.T) {
	root := newExtHome(t, wire.AlgEd25519)
	p := root.path("new.pkg")
	r := root.run("identity", "new", "--prepare", p, "--signer", root.signer, "--ts", "2026-11-14T00:00:00Z")
	if r.code != ExitOK {
		t.Fatal(r.stdout)
	}
	o := jsonOf(t, r)
	pkg := readPkg(t, p)
	h := sha256.Sum256(paeOf(t, pkg))
	if o.Members["pae_sha256"] != canon.String(hex.EncodeToString(h[:])) || o.Members["pae_sha256"] != pkg.Members["statement"] || o.Members["committed"] != canon.Bool(false) {
		t.Fatalf("%s", r.stdout)
	}
}

// nonCanonicalEIP191 re-encodes a canonical r‖s‖v signature as high s with v∈{0,1}: the same signature.
func nonCanonicalEIP191(t *testing.T, canonical string) string {
	t.Helper()
	raw, _ := hex.DecodeString(strings.TrimPrefix(canonical, "0x"))
	var s secp256k1.ModNScalar
	s.SetByteSlice(raw[32:64])
	s.Negate()
	out := append([]byte{}, raw...)
	s.PutBytesUnchecked(out[32:64])
	out[64] = (55 - raw[64]) - 27
	if c, ok := sig.Canonical(out); !ok || "0x"+hex.EncodeToString(c) != canonical {
		t.Fatal("the re-encoding is not the same signature")
	}
	return "0x" + hex.EncodeToString(out)
}

// TestSignExternalRebuiltEnvelope: the innermost completion check on its own. At the prepared head, a statement
// rebuilt from the package's inputs that differs in any envelope member (here ts, then body) is refused
// stale-prepare naming the member, before any signature is attached; the prepared one is signed and reads valid.
func TestSignExternalRebuiltEnvelope(t *testing.T) {
	k := testKey("rebuilt")
	d, _ := wire.IdentityDraft(wire.Draft{Kind: "identity_inception", Body: objOf("profile", canon.String(wire.FixedRootProfile))}, nil, nil)
	prep := &externalKey{signer: k.Signer(), alg: k.Alg()}
	sts, err := signExternal(prep, head{}, "2026-11-14T00:00:00Z", []wire.Draft{d})
	if err != nil || sts[0].line != nil {
		t.Fatalf("prepare: %v", err)
	}
	env := envelopeOf(sts[0].st).(*canon.Object)
	done := &externalKey{signer: k.Signer(), alg: k.Alg(), sig: k.Sign(sts[0].st.SignedString), env: env}
	if _, err := signExternal(done, head{}, "2026-11-14T00:00:01Z", []wire.Draft{d}); err == nil {
		t.Fatal("a rebuilt ts was not refused")
	} else if p, ok := err.(*Problem); !ok || p.Slug != "stale-prepare" || p.Scope != "envelope member ts" {
		t.Fatalf("a rebuilt ts: %v", err)
	}
	d2, _ := wire.IdentityDraft(wire.Draft{Kind: "identity_inception", Body: objOf("profile", canon.String("fixed-root-v2"))}, nil, nil)
	if _, err := signExternal(done, head{}, "2026-11-14T00:00:00Z", []wire.Draft{d2}); err == nil || !isProblem(err, "stale-prepare", "envelope member body") {
		t.Fatalf("a rebuilt body was not refused: %v", err)
	}
	if _, err := signExternal(done, head{seq: 1, prev: sts[0].st.ID}, "2026-11-14T00:00:00Z", []wire.Draft{d}); err == nil || !isProblem(err, "stale-prepare", "this key's log") {
		t.Fatalf("a moved head was not refused: %v", err)
	}
	got, err := signExternal(done, head{}, "2026-11-14T00:00:00Z", []wire.Draft{d})
	if err != nil || got[0].st.ID != sts[0].st.ID || !got[0].st.Verified {
		t.Fatalf("the prepared statement: %v", err)
	}
	if _, err := signExternal(done, head{}, "2026-11-14T00:00:00Z", []wire.Draft{d, d}); err == nil {
		t.Fatal("two statements in one package")
	}
}

func isProblem(err error, slug, scope string) bool {
	p, ok := err.(*Problem)
	return ok && p.Slug == slug && p.Scope == scope
}
