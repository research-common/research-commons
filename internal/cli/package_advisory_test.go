package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// preparedAt prepares an inception package whose envelope ts is ts.
func preparedAt(t *testing.T, alg, ts string) (*extHome, string, *canon.Object) {
	t.Helper()
	root := newExtHome(t, alg)
	pp, pkg := root.prepare("new.pkg", "identity", "new", "--ts", ts)
	return root, pp, pkg
}

// TestPackageFutureSkewAdvisory: a package whose envelope ts is more than 300 s ahead of this machine's clock gets
// an advisory from package show and key sign (human line and --json `advisories`); the exit is unchanged and key
// sign still signs. At exactly the bound, and behind it, there is none. The advisory is not a check: the store's
// refusal at --complete is unchanged.
func TestPackageFutureSkewAdvisory(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			// --prepare uses the preparing machine's clock, here set so the ts is accepted there (the store's bound)
			prep := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
			withClock(t, prep)
			root, pp, pkg := preparedAt(t, alg, "2026-11-14T12:04:00Z")
			dev := newSigningMachine(t)
			advisory := "the store refuses this at --complete (writer's future-skew bound, 300 s); re-prepare with a current --ts"

			// the signing machine's clock is behind: ts is 400 s ahead of it
			withClock(t, prep.Add(-160*time.Second))
			r := dev.run("package", "show", pp, "--json")
			if r.code != ExitOK {
				t.Fatalf("package show: %d %s", r.code, r.stdout)
			}
			adv, _ := jsonOf(t, r).Members["advisories"].(canon.Array)
			if len(adv) != 1 || !strings.Contains(string(adv[0].(canon.String)), advisory) || !strings.Contains(string(adv[0].(canon.String)), "400 s ahead") {
				t.Fatalf("package show --json advisories: %s", r.stdout)
			}
			if hr := dev.run("package", "show", pp); hr.code != ExitOK || !strings.Contains(hr.stdout, advisory) {
				t.Fatalf("package show (human): %d %s", hr.code, hr.stdout)
			}
			// key sign: the advisory is on the summary (standard error), the signature is still written
			out := filepath.Join(dev.dir, "new.sig")
			ks := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--out", out)
			if ks.code != ExitOK || !strings.Contains(ks.stderr, advisory) {
				t.Fatalf("key sign: %d %s%s", ks.code, ks.stdout, ks.stderr)
			}
			if sb, _ := os.ReadFile(out); string(sb) != root.key.Sign(paeOf(t, pkg))+"\n" {
				t.Fatalf("key sign did not sign over the advisory: %q", sb)
			}
			out2 := filepath.Join(dev.dir, "new2.sig")
			kj := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--out", out2, "--json")
			if a, _ := jsonOf(t, kj).Members["advisories"].(canon.Array); kj.code != ExitOK || len(a) != 1 {
				t.Fatalf("key sign --json advisories: %d %s", kj.code, kj.stdout)
			}
			// --dry-run says it too
			if kd := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--dry-run", "--json"); kd.code != ExitOK || !strings.Contains(kd.stdout, `"advisories"`) {
				t.Fatalf("key sign --dry-run: %d %s", kd.code, kd.stdout)
			}

			// exactly at the bound (ts = now + 300 s), inside it, and behind the clock: no advisory, no member
			for _, now := range []time.Time{
				time.Date(2026, 11, 14, 11, 59, 0, 0, time.UTC), // ts is exactly 300 s ahead
				time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC),  // 240 s
				time.Date(2026, 11, 14, 13, 0, 0, 0, time.UTC),  // behind the clock
			} {
				withClock(t, now)
				r := dev.run("package", "show", pp, "--json")
				if _, has := jsonOf(t, r).Members["advisories"]; r.code != ExitOK || has || strings.Contains(r.stdout, "advisor") {
					t.Fatalf("clock %s: unexpected advisory: %d %s", now, r.code, r.stdout)
				}
				if hr := dev.run("package", "show", pp); strings.Contains(hr.stdout, "future-skew") {
					t.Fatalf("clock %s: human advisory: %s", now, hr.stdout)
				}
			}
			// one second past the bound: advisory
			withClock(t, time.Date(2026, 11, 14, 11, 58, 59, 0, time.UTC))
			if r := dev.run("package", "show", pp, "--json"); !strings.Contains(r.stdout, `"advisories"`) || r.code != ExitOK {
				t.Fatalf("301 s ahead: %d %s", r.code, r.stdout)
			}
			// the advisory does not touch the store's check: --complete is the same call as before
			withClock(t, prep)
			if c := root.complete([]string{"identity", "new"}, pp, root.sign("c.sig", pkg)); c.code != ExitOK {
				t.Fatalf("complete: %d %s", c.code, c.stdout)
			}
		})
	}
}

// TestPackageShowPaeOut: --pae-out writes the decoded pae member's exact bytes, no newline, to a new file; it
// refuses an existing file (left untouched) and writes nothing when any check fails (a mutated member, a malformed
// package); package show without it writes nothing.
func TestPackageShowPaeOut(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root := newExtHome(t, alg)
			pp, pkg := root.prepare("new.pkg", "identity", "new", "--ts", "2026-11-14T00:00:00Z")
			dev := newSigningMachine(t)

			out := filepath.Join(dev.dir, "new.pae")
			r := dev.run("package", "show", pp, "--pae-out", out, "--json")
			if r.code != ExitOK {
				t.Fatalf("package show --pae-out: %d %s", r.code, r.stdout)
			}
			got, err := os.ReadFile(out)
			if err != nil || !bytes.Equal(got, paeOf(t, pkg)) {
				t.Fatalf("the file is not the exact PAE bytes: %v %q", err, got)
			}
			if jsonOf(t, r).Members["pae_written"] != canon.String(out) {
				t.Fatalf("pae_written: %s", r.stdout)
			}
			// the bytes are what key sign signs: the signature over the file verifies as the package's
			sigF := filepath.Join(dev.dir, "new.sig")
			if k := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--out", sigF); k.code != ExitOK {
				t.Fatal(k.stderr)
			}
			if sb, _ := os.ReadFile(sigF); string(sb) != root.key.Sign(got)+"\n" {
				t.Fatal("a signature over the --pae-out bytes is not the one key sign makes")
			}
			// an existing file is never overwritten, even by a good package
			if r := dev.run("package", "show", pp, "--pae-out", out, "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "pae-file-exists") {
				t.Fatalf("existing --pae-out: %d %s", r.code, r.stdout)
			}
			if b, _ := os.ReadFile(out); !bytes.Equal(b, got) {
				t.Fatal("an existing --pae-out file was changed")
			}
			// no --pae-out: nothing written beside the package
			before, _ := os.ReadDir(dev.dir)
			dev.run("package", "show", pp, "--json")
			if after, _ := os.ReadDir(dev.dir); len(after) != len(before) {
				t.Fatal("package show wrote a file without --pae-out")
			}
			// every check failing writes nothing: exit 1 (member mismatch) and exit 2 (malformed)
			bad := clonePkg(pkg)
			bad.Members["statement"] = canon.String(strings.Repeat("ab", 32))
			mm := filepath.Join(dev.dir, "mismatch.pkg")
			writePkg(t, mm, bad)
			garbage := filepath.Join(dev.dir, "garbage.pkg")
			os.WriteFile(garbage, []byte("{not json"), 0o644)
			for name, c := range map[string]struct {
				pkg  string
				code int
			}{"mismatch": {mm, ExitWrong}, "malformed": {garbage, ExitDidNotStart}, "absent": {filepath.Join(dev.dir, "absent.pkg"), ExitDidNotStart}} {
				o := filepath.Join(dev.dir, name+".pae")
				if r := dev.run("package", "show", c.pkg, "--pae-out", o, "--json"); r.code != c.code {
					t.Fatalf("%s: %d %s", name, r.code, r.stdout)
				}
				if _, err := os.Stat(o); err == nil {
					t.Fatalf("%s: a failed check wrote the PAE", name)
				}
			}
			// an unwritable directory: refused, named, nothing left behind
			if r := dev.run("package", "show", pp, "--pae-out", filepath.Join(dev.dir, "no-such-dir", "x.pae"), "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "unwritable-file") {
				t.Fatalf("unwritable: %d %s", r.code, r.stdout)
			}
		})
	}
}
