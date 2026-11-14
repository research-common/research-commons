package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

const observedPerm = `[{"kind":"observed","targets":{"any_content":true},"amend":false}]`

// TestExternalSigningObserved: an `observed` capture, an act for an identity, goes through the external-signing
// round trip as an `authored` does. Without --no-holds the writer would add a holds beside it, a second statement
// to sign, and --prepare refuses (no package, store unchanged); with --no-holds the package carries the one
// observed statement, key sign signs it on a machine that holds no store, and --complete appends exactly that line
// (read as eligible under the grant). Both algorithms.
func TestExternalSigningObserved(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			ts := []string{"--ts", "2026-11-14T00:00:00Z"}
			root := newIDHome(t, alg)
			ident := string(root.ok(append([]string{"identity", "new"}, ts...)...).Members["identity"].(canon.String))
			worker := newIDHome(t, alg)
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "w"), "--licence", "CC0-1.0"))
			root.pullFrom(worker)
			grant := string(root.ok(append([]string{"identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d,
				"--permissions", observedPerm}, ts...)...).Members["grant"].(canon.String))
			worker.pullFrom(root)
			wext := &extHome{t: t, store: worker.store, dir: t.TempDir(), signer: worker.signer}
			wk, _ := loadKey(worker.key, "test")
			wext.key = wk.Key

			data := "a capture, signed on a device"
			content := worker.file("capture.bin", data)
			draft := worker.file("observed.json", `{"kind":"observed","body":{"content":{"digest":"`+dig(data)+`","size":`+itoa(len(data))+`},"class":"source",`+
				`"referent":{"endpoint":"https://api.example/x","parameters":{},"response_digest":"`+dig(data)+`"},"capture":{"at":"2026-01-02T00:00:00Z","evidence":"self-asserted"}}}`)
			act := append([]string{"publish", "--draft", draft, "--content", content, "--as", ident, "--grant", grant}, ts...)

			// without --no-holds: refused at --prepare, nothing written anywhere
			before := storeBytes(t, wext.store)
			refused := wext.path("refused.pkg")
			r := wext.run(append(act[:len(act):len(act)], "--prepare", refused, "--signer", wext.signer)...)
			if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "an external-signing package carries one statement") || !strings.Contains(r.stdout, "writes a holds beside it") || !strings.Contains(r.stdout, "--no-holds") {
				t.Fatalf("observed --prepare without --no-holds: %d %s", r.code, r.stdout)
			}
			if _, err := os.Stat(refused); err == nil {
				t.Fatal("a refused --prepare wrote a package")
			}
			if storeBytes(t, wext.store) != before {
				t.Fatal("a refused --prepare changed the store")
			}

			// with --no-holds: prepare, sign on the store-less machine, complete
			pp, pkg := wext.prepare("obs.pkg", append(act[:len(act):len(act)], "--no-holds")...)
			if storeBytes(t, wext.store) != before {
				t.Fatal("--prepare wrote to the store")
			}
			if k := pkg.Members["envelope"].(*canon.Object).Members["kind"]; k != canon.String("observed") {
				t.Fatalf("package kind = %v", k)
			}
			dev := newSigningMachine(t)
			keyFile := worker.key
			sigF := filepath.Join(dev.dir, "obs.sig")
			if r := dev.run("key", "sign", "--package", pp, "--key", keyFile, "--out", sigF, "--json"); r.code != ExitOK {
				t.Fatalf("key sign: %d %s", r.code, r.stdout)
			}
			r = wext.run("publish", "--complete", pp, "--signature", sigF, "--content", content)
			if r.code != ExitOK {
				t.Fatalf("--complete: %d %s", r.code, r.stdout)
			}
			ss := statementsOf(jsonOf(t, r))
			if len(ss) != 1 || ss[0].Members["kind"] != canon.String("observed") || ss[0].Members["statement"] != pkg.Members["statement"] {
				t.Fatalf("--complete appended %d statements, want the one observed statement %s: %s", len(ss), canon.Encode(pkg.Members["statement"]), r.stdout)
			}
			if !strings.Contains(r.stdout, `"state":"eligible"`) {
				t.Fatalf("the act is not read as eligible: %s", r.stdout)
			}
			if lineOf(t, wext.store, string(pkg.Members["statement"].(canon.String))) == "" {
				t.Fatal("the observed line is not in the store")
			}
		})
	}
}
