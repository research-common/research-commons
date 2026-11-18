package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// TestIdentityControlledCollectionFlow: the whole path a team uses for a collection its identity controls. A worker
// key (a bare key, not the root) signs a genesis whose only controller is {identity: I}; the root grants the worker
// `edition` on that resource; the worker publishes an edition acting for I. The edition counts and becomes current,
// and its member is listed. Without the grant, or under a grant that does not name the resource, the edition is
// refused with nothing appended.
func TestIdentityControlledCollectionFlow(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root := newIDHome(t, alg)
			ident := string(root.ok("identity", "new").Members["identity"].(canon.String))
			worker := newIDHome(t, alg)
			worker.pullFrom(root)
			c := worker.file("c0", "worker first line")
			first := worker.ok("publish", "--kind", "authored", "--content", c, "--licence", "CC0-1.0")
			inception := firstID(t, first)
			digest := ""
			for _, d := range first.Members["did"].(canon.Array) {
				if s := string(d.(canon.String)); strings.HasPrefix(s, "install blob ") {
					digest = strings.TrimPrefix(s, "install blob ")
				}
			}
			if digest == "" {
				t.Fatalf("no blob installed: %s", canon.Encode(first))
			}

			// the worker signs the genesis: its only controller is the identity
			g := firstID(t, worker.ok("publish", "--draft", worker.file("g.json",
				`{"kind":"genesis","body":{"type":"collection","name":"team","controllers":[{"identity":"`+ident+`"}],"rule":{"any_one":true}}}`)))
			edition := worker.file("e.json", `{"kind":"edition","body":{"resource":"`+g+`","predecessors":["`+g+`"],`+
				`"contents":{"members":[{"content":"`+digest+`","role":"dataset"}],"selection":"curated"}}}`)

			// a grant for another resource does not reach this one
			root.pullFrom(worker)
			other := root.ok("identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", inception,
				"--permissions", `[{"kind":"edition","targets":{"resources":["`+strings.Repeat("a", 64)+`"]}}]`)
			worker.pullFrom(root)
			before := storeBytes(t, worker.store)
			if r := worker.run("publish", "--draft", edition, "--as", ident, "--grant", firstID(t, other)); r.code == ExitOK {
				t.Fatalf("an edition under a grant for another resource was accepted: %s", r.stdout)
			}
			if storeBytes(t, worker.store) != before {
				t.Fatal("a refused edition changed the store")
			}

			// the grant names this resource: the edition counts and is current
			gr := firstID(t, root.ok("identity", "grant", "--identity", ident, "--delegate", worker.signer, "--delegate-inception", inception,
				"--permissions", `[{"kind":"edition","targets":{"resources":["`+g+`"]}}]`))
			worker.pullFrom(root)
			o := worker.ok("publish", "--draft", edition, "--as", ident, "--grant", gr)
			if a, _ := o.Members["actor"].(*canon.Object); a == nil || a.Members["state"] != canon.String("eligible") {
				t.Fatalf("actor not eligible: %s", canon.Encode(o))
			}
			sh := worker.read("show", g)
			if sh.code != ExitOK {
				t.Fatalf("show: %d %s", sh.code, sh.stdout)
			}
			out := sh.stdout
			for _, want := range []string{`"controllers":["identity:` + ident + `"]`, `"member":"` + digest + `"`} {
				if !strings.Contains(out, want) {
					t.Fatalf("show lacks %s: %s", want, out)
				}
			}
			if i := strings.Index(out, `"current":"`); i < 0 || strings.HasPrefix(out[i+len(`"current":"`):], g) {
				t.Fatalf("no current edition beyond the genesis: %s", out)
			}

			// a reader holding the root's and the worker's logs reads the same thing
			reader := newIDHome(t, alg)
			reader.pullFrom(worker)
			if r := reader.read("show", g); r.code != ExitOK || !strings.Contains(r.stdout, digest) {
				t.Fatalf("reader: %d %s", r.code, r.stdout)
			}
		})
	}
}
