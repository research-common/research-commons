package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// idHome is one machine of the identity drill: a store and a key file, driven through the command line only.
type idHome struct {
	t      *testing.T
	store  string
	key    string
	signer string
}

func newIDHome(t *testing.T, alg string) *idHome {
	t.Helper()
	keys := t.TempDir()
	k, s := newKeyFile(t, keys, alg)
	return &idHome{t: t, store: drillStore(t), key: k, signer: s}
}

func (h *idHome) run(args ...string) result {
	return runIn(h.store, nil, append(args, "--key", h.key, "--json")...)
}

func (h *idHome) ok(args ...string) *canon.Object {
	h.t.Helper()
	r := h.run(args...)
	if r.code != ExitOK {
		h.t.Fatalf("%v: %d\n%s%s", args, r.code, r.stdout, r.stderr)
	}
	return jsonOf(h.t, r)
}

func (h *idHome) read(args ...string) result { return runIn(h.store, nil, append(args, "--json")...) }

func (h *idHome) pullFrom(o *idHome) {
	h.t.Helper()
	if r := h.read("pull", o.store); r.code != ExitOK {
		h.t.Fatalf("pull: %d\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func (h *idHome) file(name, data string) string {
	p := filepath.Join(filepath.Dir(h.key), name)
	os.WriteFile(p, []byte(data), 0o644)
	return p
}

func firstID(t *testing.T, o *canon.Object) string {
	t.Helper()
	sts, _ := o.Members["statements"].(canon.Array)
	if len(sts) == 0 {
		t.Fatalf("no statements: %s", canon.Encode(o))
	}
	return string(sts[0].(*canon.Object).Members["statement"].(canon.String))
}

func storeBytes(t *testing.T, dir string) string {
	t.Helper()
	var b bytes.Buffer
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !strings.Contains(p, string(filepath.Separator)+"locks") {
			x, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(dir, p)
			b.WriteString(rel + "\x00")
			b.Write(x)
			b.WriteString("\x00")
		}
		return nil
	})
	return b.String()
}

const anyContentPerm = `[{"kind":"authored","targets":{"any_content":true},"amend":false}]`

// TestIdentityCommands: identity new / grant / cut through the command line, each read back by the production
// reader as a valid rc/2 line; every refusal named leaves the store byte-identical.
func TestIdentityCommands(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root := newIDHome(t, alg)
			// dry run: prints the exact statement, writes nothing
			before := storeBytes(t, root.store)
			dry := root.ok("identity", "new", "--dry-run", "--ts", "2026-11-13T00:00:00Z")
			if !strings.Contains(string(canon.Encode(dry)), `"profile":"fixed-root-v1"`) || dry.Members["committed"] != canon.Bool(false) {
				t.Fatalf("dry run: %s", canon.Encode(dry))
			}
			if storeBytes(t, root.store) != before {
				t.Fatal("dry run wrote")
			}
			o := root.ok("identity", "new", "--ts", "2026-11-13T00:00:00Z")
			ident := string(o.Members["identity"].(canon.String))
			if ident != firstID(t, dry) {
				t.Fatalf("dry-run id %s != signed id %s", firstID(t, dry), ident)
			}
			if !strings.Contains(string(o.Members["custody"].(canon.String)), "no recovery") {
				t.Fatal("no custody warning")
			}
			sh := jsonOf(t, root.read("show", ident))
			if sh.Members["status"] != canon.String("valid") || sh.Members["kind"] != canon.String("identity_inception") {
				t.Fatalf("inception reads %s", canon.Encode(sh))
			}
			// the root key is no longer fresh
			before = storeBytes(t, root.store)
			if r := root.run("identity", "new"); r.code != ExitWrong || !strings.Contains(r.stdout, "root-key-not-fresh") {
				t.Fatalf("second inception: %d %s", r.code, r.stdout)
			}
			// worker machine
			worker := newIDHome(t, alg)
			c := worker.file("c0", "worker first line")
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", c, "--licence", "CC0-1.0"))
			root.pullFrom(worker)
			before = storeBytes(t, root.store)
			for _, bad := range []struct {
				args []string
				code int
				slug string
			}{
				{[]string{"--delegate", root.signer, "--delegate-inception", d, "--permissions", anyContentPerm}, ExitDidNotStart, "self-grant"},
				{[]string{"--delegate", worker.signer, "--delegate-inception", d, "--permissions", `[]`}, ExitDidNotStart, "malformed-argument"},
				{[]string{"--delegate", worker.signer, "--delegate-inception", d, "--permissions", `[{"kind":"genesis","targets":{"any_content":true}}]`}, ExitDidNotStart, "refused"},
				{[]string{"--delegate", worker.signer, "--delegate-inception", ident, "--permissions", anyContentPerm}, ExitWrong, "delegate-inception-mismatch"},
			} {
				r := root.run(append([]string{"identity", "grant", "--identity", ident}, bad.args...)...)
				if r.code != bad.code || !strings.Contains(r.stdout, bad.slug) {
					t.Fatalf("%v: %d %s", bad.args, r.code, r.stdout)
				}
			}
			if r := worker.run("identity", "grant", "--identity", ident, "--delegate", root.signer, "--delegate-inception", d, "--permissions", anyContentPerm); r.code != ExitCouldNot {
				t.Fatalf("grant from a store without the identity: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, root.store) != before {
				t.Fatal("a refused grant wrote")
			}
			// permissions: duplicates removed, sorted
			dup := `[{"kind":"authored","targets":{"any_content":true},"amend":false},{"kind":"holds","targets":{"any_content":true}},{"amend":false,"kind":"authored","targets":{"any_content":true}}]`
			g := root.ok("identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", d, "--permissions", dup)
			if ps := g.Members["permissions"].(canon.Array); len(ps) != 2 {
				t.Fatalf("permissions not deduplicated: %s", canon.Encode(g.Members["permissions"]))
			}
			grant := string(g.Members["grant"].(canon.String))
			gs := jsonOf(t, root.read("show", grant))
			if gs.Members["status"] != canon.String("valid") {
				t.Fatalf("grant reads %s", canon.Encode(gs))
			}
			// a non-root key cannot grant
			worker.pullFrom(root)
			if r := worker.run("identity", "grant", "--identity", ident, "--delegate", root.signer, "--delegate-inception", ident, "--permissions", anyContentPerm); r.code != ExitWrong || !strings.Contains(r.stdout, "not-identity-root") {
				t.Fatalf("worker grant: %d %s", r.code, r.stdout)
			}
			// cut: --last-good is mandatory
			before = storeBytes(t, root.store)
			if r := root.run("identity", "cut", "--identity", ident, "--grant", grant, "--reason", "key_compromise"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "last-good") {
				t.Fatalf("cut without --last-good: %d %s", r.code, r.stdout)
			}
			if r := root.run("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", d, "--reason", "key_compromise", "--dry-run"); r.code != ExitOK || !strings.Contains(r.stdout, "cannot be undone") {
				t.Fatalf("cut dry run: %d %s", r.code, r.stdout)
			}
			if r := root.run("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", ident, "--reason", "key_compromise"); r.code != ExitWrong || !strings.Contains(r.stdout, "last-good-other-key") {
				t.Fatalf("cut at a root line: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, root.store) != before {
				t.Fatal("a refused or dry-run cut wrote")
			}
			cut := root.ok("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", "none", "--reason", "superseded")
			if cs := jsonOf(t, root.read("show", firstID(t, cut))); cs.Members["status"] != canon.String("valid") || cs.Members["kind"] != canon.String("identity_cut") {
				t.Fatalf("cut reads %s", canon.Encode(cs))
			}
		})
	}
}
