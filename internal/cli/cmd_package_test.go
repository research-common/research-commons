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

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// The signing side of the external-signing package (identity profile §8): package show and key sign run on a
// "signing machine" that holds the binary and the key file and no store. Here that machine is a working directory
// with no store above it and $COMMONS_STORE naming a directory that does not exist.

// signingMachine runs store-less commands from a directory holding no store.
type signingMachine struct {
	t   *testing.T
	dir string
	env map[string]string
}

func newSigningMachine(t *testing.T) *signingMachine {
	d := t.TempDir()
	return &signingMachine{t: t, dir: d, env: map[string]string{StoreEnv: filepath.Join(d, "no-such-store")}}
}

func (m *signingMachine) run(args ...string) result { return runIn(m.dir, m.env, args...) }

// runStdinIn runs args in wd with standard input in (for --signature -).
func runStdinIn(wd, in string, args ...string) result {
	var o, e bytes.Buffer
	code := Main(args, &Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" },
		Getwd: func() (string, error) { return wd, nil }, Build: Build{Version: "test", Commit: "0000000"}, Stdin: strings.NewReader(in)})
	return result{code, o.String(), e.String()}
}

// TestPackageShowKeySignEndToEnd: a package prepared on a store that never sees the root key file is checked with
// package show and signed with key sign on a machine with no store, then completed; the committed line is
// byte-identical to direct signing at the same --ts on a twin store. The inception's signature travels as a file,
// the grant's on standard output into --complete --signature -. Both algorithms.
func TestPackageShowKeySignEndToEnd(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			ts := []string{"--ts", "2026-11-14T00:00:00Z"}
			root := newExtHome(t, alg) // store A: commands run with no key named; the key file lives apart
			twin := &idHome{t: t, store: drillStore(t), key: root.keyF, signer: root.signer}
			dev := newSigningMachine(t)

			// inception: prepare on A, carry the package to the signing machine
			newCmd := append([]string{"identity", "new"}, ts...)
			pp, pkg := root.prepare("new.pkg", newCmd...)
			prepOut := jsonOf(t, root.run(append(newCmd[:2:2], "--prepare", root.path("again.pkg"), "--signer", root.signer, "--ts", ts[1])...))
			show := dev.run("package", "show", pp, "--json")
			if show.code != ExitOK {
				t.Fatalf("package show: %d %s%s", show.code, show.stdout, show.stderr)
			}
			so := jsonOf(t, show)
			h := sha256.Sum256(paeOf(t, pkg))
			for k, want := range map[string]canon.Value{
				"pae_sha256": canon.String(hex.EncodeToString(h[:])), "pae_bytes": canon.Int(int64(len(paeOf(t, pkg)))),
				"signer": canon.String(root.signer), "alg": canon.String(alg), "statement": pkg.Members["statement"],
				"log_head_check": canon.String(logHeadUnchecked),
			} {
				if !bytes.Equal(canon.Encode(so.Members[k]), canon.Encode(want)) {
					t.Fatalf("package show %s = %s, want %s", k, canon.Encode(so.Members[k]), canon.Encode(want))
				}
			}
			if so.Members["pae_sha256"] != prepOut.Members["pae_sha256"] {
				t.Fatal("package show's pae_sha256 is not the one --prepare printed")
			}
			if !bytes.Equal(canon.Encode(so.Members["summary"]), canon.Encode(pkg.Members["summary"])) {
				t.Fatal("package show's summary is not the package's")
			}
			if hs := dev.run("package", "show", pp); hs.code != ExitOK || !strings.Contains(hs.stdout, logHeadUnchecked) || !strings.Contains(hs.stdout, "fixed-root identity") {
				t.Fatalf("package show (human): %d %s", hs.code, hs.stdout)
			}
			// a dry run signs nothing, writes nothing
			dryOut := filepath.Join(dev.dir, "dry.sig")
			if r := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--out", dryOut, "--dry-run", "--json"); r.code != ExitOK ||
				jsonOf(t, r).Members["signed"] != canon.Bool(false) || jsonOf(t, r).Members["pae_sha256"] != so.Members["pae_sha256"] {
				t.Fatalf("dry run: %d %s", r.code, r.stdout)
			}
			if _, err := os.Stat(dryOut); err == nil {
				t.Fatal("a dry run wrote the signature")
			}
			// sign into a file; the summary is printed (standard error) before the signature is written
			sigF := filepath.Join(dev.dir, "new.sig")
			r := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--out", sigF)
			if r.code != ExitOK || !strings.Contains(r.stderr, "fixed-root identity") || !strings.Contains(r.stderr, string(so.Members["pae_sha256"].(canon.String))) {
				t.Fatalf("key sign: %d %s%s", r.code, r.stdout, r.stderr)
			}
			sb, _ := os.ReadFile(sigF)
			if string(sb) != root.key.Sign(paeOf(t, pkg))+"\n" {
				t.Fatalf("the signature file is not the statement encoding, newline-terminated: %q", sb)
			}
			r = root.complete([]string{"identity", "new"}, pp, sigF)
			if r.code != ExitOK {
				t.Fatalf("complete: %d %s", r.code, r.stdout)
			}
			ident := string(jsonOf(t, r).Members["identity"].(canon.String))
			if twin.ok(newCmd...).Members["identity"] != canon.String(ident) || lineOf(t, root.store, ident) == "" || lineOf(t, root.store, ident) != lineOf(t, twin.store, ident) {
				t.Fatal("the line signed by key sign is not the directly signed one")
			}

			// grant: key sign writes the signature line on standard output, --complete reads it on standard input
			worker := newIDHome(t, alg)
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "w"), "--licence", "CC0-1.0"))
			root.pullFrom(worker.store)
			twin.pullFrom(worker)
			grantCmd := append([]string{"identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d, "--permissions", anyContentPerm}, ts...)
			gp, gpkg := root.prepare("grant.pkg", grantCmd...)
			if r := dev.run("package", "show", gp, "--json"); r.code != ExitOK || !strings.Contains(r.stdout, worker.signer) {
				t.Fatalf("package show grant: %d %s", r.code, r.stdout)
			}
			r = dev.run("key", "sign", "--package", gp, "--key", root.keyF)
			if r.code != ExitOK || r.stdout != root.key.Sign(paeOf(t, gpkg))+"\n" || !strings.Contains(r.stderr, "--complete") {
				t.Fatalf("key sign to stdout: %d %q %s", r.code, r.stdout, r.stderr)
			}
			c := runStdinIn(root.store, r.stdout, "identity", "grant", "--complete", gp, "--signature", "-", "--json")
			if c.code != ExitOK {
				t.Fatalf("grant complete: %d %s", c.code, c.stdout)
			}
			grant := string(jsonOf(t, c).Members["grant"].(canon.String))
			if g := twin.ok(grantCmd...); g.Members["grant"] != canon.String(grant) || lineOf(t, root.store, grant) != lineOf(t, twin.store, grant) {
				t.Fatal("the grant signed by key sign is not the directly signed one")
			}
			conformance.Partial(t, "C-id-40", "the signing side of the external-signing package runs store-less: package show recomputes every derived member and key sign signs the recomputed PAE with a key file on a machine with no store, each committed line equal to direct signing; the compromised-host drill is TestIdentityCompromisedHostDrill, hardware signing the Ledger tests and the manual drill (§8)")
		})
	}
}

// TestPackageShowKeySignRefusals: a package whose derived member differs from its envelope (pae, statement, alg,
// signer, log_head, summary, or an envelope member changed under them) makes package show exit 1 naming the member
// and key sign refuse with nothing written; a malformed package exits 2; the wrong key, an existing --out, --store
// and --json with --out - are refused before anything is signed. Both algorithms.
func TestPackageShowKeySignRefusals(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root := newExtHome(t, alg)
			pp, pkg := root.prepare("new.pkg", "identity", "new", "--ts", "2026-11-14T00:00:00Z")
			dev := newSigningMachine(t)
			other := newExtHome(t, alg)
			mutated := func(name string, f func(p *canon.Object)) string {
				p := clonePkg(pkg)
				f(p)
				path := filepath.Join(dev.dir, name)
				writePkg(t, path, p)
				return path
			}
			envOf := func(p *canon.Object) *canon.Object { return p.Members["envelope"].(*canon.Object) }
			cases := []struct {
				name, pkg string
				member    string // the member named in scope
				also      []string
			}{
				{"pae", mutated("m-pae.pkg", func(p *canon.Object) {
					p.Members["pae"] = canon.String(base64.StdEncoding.EncodeToString(append(paeOf(t, pkg), ' ')))
				}), "pae", nil},
				{"statement", mutated("m-id.pkg", func(p *canon.Object) { p.Members["statement"] = canon.String(strings.Repeat("ab", 32)) }), "statement", nil},
				{"alg", mutated("m-alg.pkg", func(p *canon.Object) { p.Members["alg"] = canon.String("x") }), "alg", nil},
				{"signer", mutated("m-signer.pkg", func(p *canon.Object) { p.Members["signer"] = canon.String(other.signer) }), "signer", nil},
				{"log_head", mutated("m-head.pkg", func(p *canon.Object) {
					p.Members["log_head"] = objOf("seq", canon.Int(0), "statement", canon.String(strings.Repeat("cd", 32)))
				}), "log_head", nil},
				{"summary", mutated("m-sum.pkg", func(p *canon.Object) {
					p.Members["summary"].(*canon.Object).Members["root"] = canon.String(other.signer)
				}), "summary", nil},
				// the envelope is the source: changed under the derived members, every one it moves is named
				{"envelope ts", mutated("m-ts.pkg", func(p *canon.Object) { envOf(p).Members["ts"] = canon.String("2026-11-14T00:00:01Z") }),
					"pae", []string{"statement", "summary"}},
			}
			for _, c := range cases {
				r := dev.run("package", "show", c.pkg, "--json")
				if r.code != ExitWrong || !strings.Contains(r.stdout, `"scope":"package member `+c.member+`"`) || !strings.Contains(r.stdout, "package-mismatch") {
					t.Fatalf("package show %s: %d %s", c.name, r.code, r.stdout)
				}
				for _, m := range c.also {
					if !strings.Contains(r.stdout, m) {
						t.Fatalf("package show %s does not list %s: %s", c.name, m, r.stdout)
					}
				}
				out := filepath.Join(dev.dir, "sig-"+strings.ReplaceAll(c.name, " ", "-"))
				r = dev.run("key", "sign", "--package", c.pkg, "--key", root.keyF, "--out", out, "--json")
				if r.code != ExitWrong || !strings.Contains(r.stdout, `"scope":"package member `+c.member+`"`) {
					t.Fatalf("key sign %s: %d %s", c.name, r.code, r.stdout)
				}
				if _, err := os.Stat(out); err == nil {
					t.Fatalf("key sign %s wrote a signature", c.name)
				}
				if r := dev.run("key", "sign", "--package", c.pkg, "--key", root.keyF); r.code != ExitWrong || r.stdout != "" {
					t.Fatalf("key sign %s to stdout: %d %q", c.name, r.code, r.stdout)
				}
			}
			// malformed or unreadable: exit 2 on both
			garbage := filepath.Join(dev.dir, "garbage.pkg")
			os.WriteFile(garbage, []byte("{not json"), 0o644)
			for _, p := range []string{garbage, filepath.Join(dev.dir, "absent.pkg"), root.keyF,
				mutated("m-fmt.pkg", func(p *canon.Object) { p.Members["format"] = canon.String("rc-key/0") }),
				mutated("m-extra.pkg", func(p *canon.Object) { p.Keys = append(p.Keys, "x"); p.Members["x"] = canon.Null{} }),
				mutated("m-body.pkg", func(p *canon.Object) { envOf(p).Members["body"] = canon.Array{} }),
			} {
				if r := dev.run("package", "show", p, "--json"); r.code != ExitDidNotStart {
					t.Fatalf("package show %s: %d %s", p, r.code, r.stdout)
				}
				out := filepath.Join(dev.dir, "malformed.sig")
				if r := dev.run("key", "sign", "--package", p, "--key", root.keyF, "--out", out, "--json"); r.code != ExitDidNotStart {
					t.Fatalf("key sign %s: %d %s", p, r.code, r.stdout)
				}
				if _, err := os.Stat(out); err == nil {
					t.Fatal("key sign of a malformed package wrote a signature")
				}
			}
			// the wrong key (same alg, then the other alg): refused, nothing written
			otherAlg := wire.AlgEIP191
			if alg == otherAlg {
				otherAlg = wire.AlgEd25519
			}
			wrongAlg, _ := newKeyFile(t, t.TempDir(), otherAlg)
			for _, k := range []string{other.keyF, wrongAlg} {
				out := filepath.Join(dev.dir, "wrong.sig")
				r := dev.run("key", "sign", "--package", pp, "--key", k, "--out", out, "--json")
				if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "key-not-signer") {
					t.Fatalf("wrong key: %d %s", r.code, r.stdout)
				}
				if _, err := os.Stat(out); err == nil {
					t.Fatal("a wrong key wrote a signature")
				}
				if r := dev.run("key", "sign", "--package", pp, "--key", k); r.stdout != "" {
					t.Fatalf("a wrong key printed a signature: %q", r.stdout)
				}
			}
			// an existing --out is never overwritten, and is refused before the key is read (here: the wrong key)
			exists := filepath.Join(dev.dir, "exists.sig")
			os.WriteFile(exists, []byte("keep\n"), 0o644)
			r := dev.run("key", "sign", "--package", pp, "--key", other.keyF, "--out", exists, "--json")
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "signature-file-exists") {
				t.Fatalf("existing --out: %d %s", r.code, r.stdout)
			}
			if b, _ := os.ReadFile(exists); string(b) != "keep\n" {
				t.Fatal("an existing --out was overwritten")
			}
			// store-less: --store is refused; key sign needs --package and a key; --json and --out - both want stdout
			for _, bad := range [][]string{
				{"package", "show", pp, "--store", root.store},
				{"key", "sign", "--package", pp, "--key", root.keyF, "--store", root.store},
				{"key", "sign", "--key", root.keyF},
				{"key", "sign", "--package", pp},
				{"key", "sign", "--package", pp, "--key", root.keyF, "--json"},
				{"key", "sign", "--package", pp, "--key", root.keyF, "--out", "-", "--json"},
			} {
				if bad[len(bad)-1] != "--json" {
					bad = append(bad, "--json")
				}
				if r := dev.run(bad...); r.code != ExitDidNotStart || !strings.Contains(r.stdout, `"exit":2`) {
					t.Fatalf("%v: %d %s", bad, r.code, r.stdout)
				}
			}
			ents, _ := os.ReadDir(dev.dir)
			for _, e := range ents {
				if strings.HasSuffix(e.Name(), ".sig") && e.Name() != "exists.sig" {
					t.Fatalf("a refused key sign left %s", e.Name())
				}
			}
			// the package itself is never changed by either command
			if b, _ := os.ReadFile(pp); !bytes.Equal(b, append(canon.Encode(pkg), '\n')) {
				t.Fatal("the package was changed")
			}
		})
	}
}

// TestRetiredPackageFormat: a package of the retired format rc-signing-package/0 (its summary carried prose) is
// refused by package show, key sign and --complete, exit 2, naming the retired format and the next step (prepare
// it again); nothing is signed, written or appended. The same package with the current tag is accepted, so the
// refusal is the format check's. Both algorithms.
func TestRetiredPackageFormat(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root := newExtHome(t, alg)
			_, pkg := root.prepare("new.pkg", "identity", "new", "--ts", "2026-11-14T00:00:00Z")
			dev := newSigningMachine(t)
			old := clonePkg(pkg)
			old.Members["format"] = canon.String("rc-signing-package/0")
			sum := old.Members["summary"].(*canon.Object)
			sum.Members["action"] = canon.String("create a fixed-root identity")
			sum.Keys = append(sum.Keys, "custody")
			sum.Members["custody"] = canon.String("this key becomes the identity's only administrator; fixed-root-v1 has no recovery if it is lost or stolen")
			oldP := filepath.Join(dev.dir, "old.pkg")
			writePkg(t, oldP, old)
			refused := func(what string, r result) {
				t.Helper()
				if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "retired-package-format") || !strings.Contains(r.stdout, "rc-signing-package/0") ||
					!strings.Contains(r.stdout, "re-prepare it") {
					t.Fatalf("%s: %d %s", what, r.code, r.stdout)
				}
			}
			refused("package show", dev.run("package", "show", oldP, "--json"))
			out := filepath.Join(dev.dir, "old.sig")
			refused("key sign", dev.run("key", "sign", "--package", oldP, "--key", root.keyF, "--out", out, "--json"))
			if _, err := os.Stat(out); err == nil {
				t.Fatal("key sign of a retired package wrote a signature")
			}
			before := storeBytes(t, root.store)
			sig := root.path("old.sig")
			os.WriteFile(sig, []byte(root.key.Sign(paeOf(t, pkg))), 0o644)
			refused("--complete", root.complete([]string{"identity", "new"}, oldP, sig))
			if storeBytes(t, root.store) != before {
				t.Fatal("--complete of a retired package appended")
			}
			// the current tag over the same envelope is read (and its prose summary named as the mismatch)
			cur := clonePkg(old)
			cur.Members["format"] = canon.String(SigningPackageFormat)
			curP := filepath.Join(dev.dir, "cur.pkg")
			writePkg(t, curP, cur)
			if r := dev.run("package", "show", curP, "--json"); r.code != ExitWrong || !strings.Contains(r.stdout, `"scope":"package member summary"`) {
				t.Fatalf("current tag, prose summary: %d %s", r.code, r.stdout)
			}
		})
	}
}

// TestKeySignRefusesUnpreparedMembers: an envelope carrying a member --prepare never writes (an unknown member a
// reader ignores, or a merges list), with every derived member re-derived so the package is otherwise consistent,
// is refused by package show, key sign and --complete alike, exit 2 naming the member: key sign signs only the
// PAE of an envelope the tool would prepare (identity profile §8). Nothing is signed, written or appended. Both
// algorithms.
func TestKeySignRefusesUnpreparedMembers(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root := newExtHome(t, alg)
			_, pkg := root.prepare("new.pkg", "identity", "new", "--ts", "2026-11-14T00:00:00Z")
			dev := newSigningMachine(t)
			for _, c := range []struct {
				member string
				value  canon.Value
			}{
				{"x_note", canon.String("inert to every reader")},
				{"zz", canon.Null{}},
			} {
				p := clonePkg(pkg)
				env := p.Members["envelope"].(*canon.Object)
				env.Keys = append(env.Keys, c.member)
				env.Members[c.member] = c.value
				st, err := wire.CheckUnsigned(env)
				if err != nil || st.Status != wire.Valid {
					t.Fatalf("%s: the reader no longer holds the envelope valid (%v), so this case tests nothing", c.member, err)
				}
				p.Members["pae"] = canon.String(base64.StdEncoding.EncodeToString(st.SignedString))
				p.Members["statement"] = canon.String(st.ID)
				p.Members["summary"] = summaryOf(st)
				path := filepath.Join(dev.dir, c.member+".pkg")
				writePkg(t, path, p)
				refused := func(what string, r result) {
					t.Helper()
					if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "malformed-package") || !strings.Contains(r.stdout, "envelope member "+c.member) {
						t.Fatalf("%s %s: %d %s", what, c.member, r.code, r.stdout)
					}
				}
				refused("package show", dev.run("package", "show", path, "--json"))
				out := filepath.Join(dev.dir, c.member+".sig")
				refused("key sign", dev.run("key", "sign", "--package", path, "--key", root.keyF, "--out", out, "--json"))
				if _, err := os.Stat(out); err == nil {
					t.Fatalf("key sign of %s wrote a signature", c.member)
				}
				before := storeBytes(t, root.store)
				sig := filepath.Join(dev.dir, c.member+"-direct.sig")
				os.WriteFile(sig, []byte(root.key.Sign(st.SignedString)), 0o644)
				refused("--complete", root.complete([]string{"identity", "new"}, path, sig))
				if storeBytes(t, root.store) != before {
					t.Fatalf("--complete of %s appended", c.member)
				}
			}
		})
	}
}
