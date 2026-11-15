package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// TestPackageExpectPAESha256: --expect-pae-sha256 compares the sha256 of the recomputed PAE bytes with a digest
// carried by another channel. A match prints "pae sha256: matches expected" and changes nothing else; a different
// digest is exit 1 naming both digests and --pae-out then writes nothing; a malformed digest is exit 2. key sign
// takes the same flag and signs nothing on a mismatch.
func TestPackageExpectPAESha256(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root := newExtHome(t, alg)
			pp, pkg := root.prepare("new.pkg", "identity", "new", "--ts", "2026-11-14T00:00:00Z")
			dev := newSigningMachine(t)
			sum := sha256.Sum256(paeOf(t, pkg))
			good := hex.EncodeToString(sum[:])
			other := strings.Repeat("0", 64)

			// match
			out := filepath.Join(dev.dir, "ok.pae")
			r := dev.run("package", "show", pp, "--expect-pae-sha256", good, "--pae-out", out)
			if r.code != ExitOK || !strings.Contains(r.stdout, "pae sha256: matches expected") {
				t.Fatalf("match: %d %s", r.code, r.stdout)
			}
			if _, err := os.Stat(out); err != nil {
				t.Fatal("a match with --pae-out wrote no file")
			}
			if j := dev.run("package", "show", pp, "--expect-pae-sha256", good, "--json"); j.code != ExitOK || jsonOf(t, j).Members["pae_check"] != canon.String("pae sha256: matches expected") {
				t.Fatalf("match --json: %d %s", j.code, j.stdout)
			}
			if plain := dev.run("package", "show", pp); strings.Contains(plain.stdout, "matches expected") {
				t.Fatal("the match line appears without the flag")
			}

			// mismatch: exit 1, both digests named, nothing written
			bad := filepath.Join(dev.dir, "bad.pae")
			r = dev.run("package", "show", pp, "--expect-pae-sha256", other, "--pae-out", bad, "--json")
			if r.code != ExitWrong || !strings.Contains(r.stdout, good) || !strings.Contains(r.stdout, other) || !strings.Contains(r.stdout, "pae-digest-mismatch") {
				t.Fatalf("mismatch: %d %s", r.code, r.stdout)
			}
			if _, err := os.Stat(bad); err == nil {
				t.Fatal("--pae-out wrote a file although the digest differed")
			}
			if hr := dev.run("package", "show", pp, "--expect-pae-sha256", other); hr.code != ExitWrong {
				t.Fatalf("mismatch human: %d", hr.code)
			}

			// bad hex: exit 2, no file
			for name, v := range map[string]string{"short": good[:63], "upper": strings.ToUpper(good), "nonhex": strings.Repeat("g", 64), "empty": "", "prefixed": "0x" + good[2:]} {
				pf := filepath.Join(dev.dir, "hex-"+name+".pae")
				r := dev.run("package", "show", pp, "--expect-pae-sha256="+v, "--pae-out", pf, "--json")
				if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "bad-pae-digest") {
					t.Fatalf("%s: %d %s", name, r.code, r.stdout)
				}
				if _, err := os.Stat(pf); err == nil {
					t.Fatalf("%s: a file was written", name)
				}
			}

			// key sign shares the flag: mismatch signs and writes nothing, a match signs
			sigF := filepath.Join(dev.dir, "n.sig")
			if k := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--out", sigF, "--expect-pae-sha256", other); k.code != ExitWrong {
				t.Fatalf("key sign mismatch: %d %s", k.code, k.stderr)
			}
			if _, err := os.Stat(sigF); err == nil {
				t.Fatal("key sign wrote a signature although the digest differed")
			}
			if k := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--out", sigF, "--expect-pae-sha256", good); k.code != ExitOK {
				t.Fatalf("key sign match: %d %s", k.code, k.stderr)
			}
			if k := dev.run("key", "sign", "--package", pp, "--key", root.keyF, "--out", filepath.Join(dev.dir, "x.sig"), "--expect-pae-sha256", "zz"); k.code != ExitDidNotStart {
				t.Fatalf("key sign bad hex: %d", k.code)
			}
		})
	}
}
