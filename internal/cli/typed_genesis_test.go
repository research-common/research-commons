package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// TestPublishTypedGenesis: a bare key signs a collection genesis whose controllers are typed subjects (identity
// profile §2.1): rc/2, the body marker {}, no actor, read back valid. `show` resolves the identity controller and
// `list` lists the resource. A genesis of key controllers only stays rc/1. Refusals (a rule no controllers satisfy,
// an unsorted typed list, an edition naming typed controllers from a bare key) leave the store byte-identical.
func TestPublishTypedGenesis(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			h := newIDHome(t, alg) // h.key is a bare key: it is not the identity's root and holds no grant
			ident := string(h.ok("identity", "new").Members["identity"].(canon.String))
			genesis := func(ctrl, rule string) string {
				return h.file("g.json", `{"kind":"genesis","body":{"type":"collection","name":"readings","controllers":`+ctrl+`,"rule":`+rule+`}}`)
			}
			line := func(id string) string {
				lines, _ := mustStore(t, h.store).Statements()
				return string(lines[id])
			}

			// refused, nothing signed
			before := storeBytes(t, h.store)
			for name, d := range map[string]string{
				"unsatisfiable": genesis(`[{"identity":"`+ident+`"},{"key":"`+h.signer+`"}]`, `{"k_of_n":{"k":3}}`),
				"unsorted":      genesis(`[{"key":"`+h.signer+`"},{"identity":"`+ident+`"}]`, `{"any_one":true}`),
				"two members":   genesis(`[{"identity":"`+ident+`","key":"`+h.signer+`"}]`, `{"any_one":true}`),
				"not an id":     genesis(`[{"identity":"nope"}]`, `{"any_one":true}`),
			} {
				if r := h.run("publish", "--draft", d); r.code != ExitDidNotStart || !strings.Contains(r.stdout, `"committed":false`) {
					t.Fatalf("%s: %d %s", name, r.code, r.stdout)
				}
				if storeBytes(t, h.store) != before {
					t.Fatalf("%s: a refused genesis changed the store", name)
				}
			}

			// signed: mixed {identity} + {key}
			o := h.ok("publish", "--draft", genesis(`[{"identity":"`+ident+`"},{"key":"`+h.signer+`"}]`, `{"k_of_n":{"k":2}}`))
			gid := firstID(t, o)
			l := line(gid)
			for _, want := range []string{`"rc":"rc/2"`, `"crit":["x_identity_v1"]`, `"x_identity_v1":{}`} {
				if !strings.Contains(l, want) {
					t.Fatalf("typed genesis lacks %s: %s", want, l)
				}
			}
			if strings.Contains(l, "x_actor_v1") {
				t.Fatalf("a genesis carries no actor: %s", l)
			}
			sh := jsonOf(t, h.read("show", gid))
			if sh.Members["counted"] != canon.String("counted") {
				t.Fatalf("show genesis: %s", canon.Encode(sh))
			}
			if !strings.Contains(string(canon.Encode(sh)), ident) {
				t.Fatalf("show does not name the identity controller: %s", canon.Encode(sh))
			}
			ls := h.read("list")
			if ls.code != ExitOK || !strings.Contains(ls.stdout, gid) {
				t.Fatalf("list: %d %s", ls.code, ls.stdout)
			}

			// key-only controllers: rc/1, as before
			g2 := firstID(t, h.ok("publish", "--draft", h.file("g2.json", `{"kind":"genesis","body":{"type":"collection","name":"plain","controllers":["`+h.signer+`"],"rule":{"any_one":true}}}`)))
			if l := line(g2); !strings.Contains(l, `"rc":"rc/1"`) || strings.Contains(l, "x_identity_v1") || strings.Contains(l, `"crit"`) {
				t.Fatalf("key-only genesis is not plain rc/1: %s", l)
			}

			// an edition naming typed controllers from a bare key is still refused (identity profile §2.3)
			before = storeBytes(t, h.store)
			ed := h.file("e.json", `{"kind":"edition","body":{"resource":"`+g2+`","predecessors":["`+g2+`"],"contents":{"members":[],"controllers":[{"identity":"`+ident+`"}],"rule":{"any_one":true}}}}`)
			if r := h.run("publish", "--draft", ed); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "controllers[0] is not a key") {
				t.Fatalf("typed edition from a bare key: %d %s", r.code, r.stdout)
			}
			if storeBytes(t, h.store) != before {
				t.Fatal("a refused edition changed the store")
			}
		})
	}
}

// TestDraftMarkerOnRC1Refused: a draft the writer signs rc/1 (an edition of an rc/1 resource, a key-only genesis, a
// describes) whose body carries x_identity_v1 is refused, exit 2, nothing signed and the store byte-identical, with
// next naming --as/--grant and the identity-controlled genesis. Before, it was signed rc/1 with the marker as a
// plain body member. The writer's own marker-only form (an identity-controlled genesis) is unchanged: rc/2, {}.
func TestDraftMarkerOnRC1Refused(t *testing.T) {
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			h := newIDHome(t, alg)
			ident := string(h.ok("identity", "new").Members["identity"].(canon.String))
			g := firstID(t, h.ok("publish", "--draft", h.file("g.json", `{"kind":"genesis","body":{"type":"collection","name":"plain","controllers":["`+h.signer+`"],"rule":{"any_one":true}}}`)))
			before := storeBytes(t, h.store)
			for name, d := range map[string]string{
				"edition of an rc/1 resource":   `{"kind":"edition","body":{"resource":"` + g + `","predecessors":["` + g + `"],"contents":{"members":[],"selection":"curated"},"x_identity_v1":{}}}`,
				"edition, a marker with fields": `{"kind":"edition","body":{"resource":"` + g + `","predecessors":["` + g + `"],"contents":{"members":[],"selection":"curated"},"x_identity_v1":{"task_roles":{}}}}`,
				"key-only genesis":              `{"kind":"genesis","body":{"type":"collection","name":"other","controllers":["` + h.signer + `"],"rule":{"any_one":true},"x_identity_v1":{}}}`,
				"describes":                     `{"kind":"describes","body":{"about":{"statement":"` + g + `"},"note":"n","x_identity_v1":{}}}`,
			} {
				r := h.run("publish", "--draft", h.file("d.json", d))
				if r.code != ExitDidNotStart || !strings.Contains(r.stdout, "the draft body carries x_identity_v1") ||
					!strings.Contains(r.stdout, "--as <identity> --grant <grant>") || !strings.Contains(r.stdout, `"committed":false`) {
					t.Fatalf("%s: %d %s", name, r.code, r.stdout)
				}
				if storeBytes(t, h.store) != before {
					t.Fatalf("%s: a refused draft changed the store", name)
				}
			}
			// the writer's own marker-only form is unaffected
			o := h.ok("publish", "--draft", h.file("t.json", `{"kind":"genesis","body":{"type":"collection","name":"typed","controllers":[{"identity":"`+ident+`"},{"key":"`+h.signer+`"}],"rule":{"any_one":true}}}`))
			lines, _ := mustStore(t, h.store).Statements()
			if l := string(lines[firstID(t, o)]); !strings.Contains(l, `"rc":"rc/2"`) || !strings.Contains(l, `"x_identity_v1":{}`) {
				t.Fatalf("typed genesis: %s", l)
			}
		})
	}
}
