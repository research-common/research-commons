package identity_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// Only this adapter may construct model facts in production code: the model trusts its caller's authentication.
func TestOnlyAdapterImportsModel(t *testing.T) {
	root, err := conformance.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	const model = "github.com/research-common/research-commons/internal/identitymodel"
	fset := token.NewFileSet()
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		if strings.HasSuffix(dir, "internal/identity") || strings.HasSuffix(dir, "internal/identitymodel") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == model {
				t.Errorf("%s imports the identity model directly; use internal/identity", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Mutation is never better than omission: for every sampled single-byte mutation of a victim line, every other
// statement's result is no more permissive than when the victim is simply withheld (a corrupted cut is an unseen
// cut, the documented evidence-relative limit; it must not be worse than that), and the mutated bytes never read
// Valid under the victim's id.
func TestByteMutationsNeverCreateAuthority(t *testing.T) {
	w := base(t)
	w.sign(stmt{name: "C1", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "A1")})
	targets := []string{"I", "G1", "G2", "C1", "A1", "A2", "B2"}
	alphabet := []byte("0123456789abcdef\"{}:,x")
	mutations := 0
	for _, victim := range targets {
		omitted := w.admit(without(w.order, victim)...)
		baseline := map[string]identitymodel.Status{}
		for _, n := range w.order {
			baseline[n] = omitted.Evaluate(w.ids[n]).Status
		}
		line := w.lines[victim]
		for i := 0; i < len(line); i += 3 {
			for _, c := range alphabet[:4+i%len(alphabet)%8] {
				if line[i] == c {
					continue
				}
				m := append([]byte(nil), line...)
				m[i] = c
				lines := [][]byte{m}
				for _, n := range w.order {
					if n != victim {
						lines = append(lines, w.lines[n])
					}
				}
				s, err := identity.Admit(lines)
				if err != nil {
					t.Fatalf("admit: %v", err)
				}
				mutations++
				for _, n := range w.order {
					if n == victim {
						continue
					}
					if got := s.Evaluate(w.ids[n]).Status; got == identitymodel.Eligible && baseline[n] != identitymodel.Eligible {
						t.Fatalf("mutating %s byte %d to %q made %s eligible (withholding it does not)", victim, i, c, n)
					}
				}
				if st, ok := s.Status(w.ids[victim]); ok && st == wire.Valid {
					t.Fatalf("mutated %s byte %d still reads Valid under the original id", victim, i)
				}
			}
		}
	}
	if mutations < 1000 {
		t.Fatalf("only %d mutations", mutations)
	}
}

// The unchanged reader stack (keylog + resolve) on the full slice, including rc/2 resource/task kinds and
// authenticated-invalid controls: retained unverified, never evaluated, no panic in any view.
func TestUnchangedReaderStackOnCandidateBytes(t *testing.T) {
	w := base(t)
	w.sign(stmt{name: "Cbad", by: "R", parent: "G2", kind: "identity_cut", body: obj("identity", "zz", "grant", 7, "last_good", "x", "reason", "BAD")})
	w.sign(stmt{name: "Gen", by: "K1", parent: "A2", kind: "genesis", body: obj("type", "collection", "name", "n",
		"controllers", canon.Array{obj("identity", w.ids["I"])}, "rule", obj("k_of_n", 1)), actor: [2]string{"I", "G1"}})
	w.sign(stmt{name: "Ed", by: "K1", parent: "Gen", kind: "edition", body: obj("resource", w.ids["Gen"], "predecessors", []string{w.ids["Gen"]},
		"contents", obj("controllers", canon.Array{obj("key", 5)})), actor: [2]string{"I", "G1"}})
	w.sign(stmt{name: "Obs", by: "K2", parent: "B2", kind: "observed", body: obj("class", canon.Array{}, "content", 3), actor: [2]string{"I", "G2"}})
	w.sign(stmt{name: "Tail1", by: "K1", rc: "rc/1", parent: "Ed", kind: "authored", body: authoredBody(13)})
	w.sign(stmt{name: "Tail2", by: "K2", rc: "rc/1", parent: "Obs", kind: "authored", body: authoredBody(14)})
	store := keylog.NewStore()
	signerOf := func(n string) string {
		for _, by := range []string{"R", "K1", "K2", "S"} {
			if strings.Contains(string(w.lines[n]), `"signer":"`+w.signer(by)+`"`) {
				return w.signer(by)
			}
		}
		t.Fatalf("no signer for %s", n)
		return ""
	}
	for _, n := range w.order {
		if _, err := store.Log(signerOf(n)).Add(w.lines[n]); err != nil {
			t.Fatalf("legacy add %s: %v", n, err)
		}
	}
	r := resolve.New(store)
	for _, n := range w.order {
		p, ok := r.Statement(w.ids[n])
		if !ok {
			continue // unvouched rc/2 lines stay retained, not placed
		}
		if p.St.RC == "rc/2" && (p.St.Verified || p.Evaluable || p.Counts()) {
			t.Fatalf("legacy reader evaluated rc/2 %s: %+v", n, p)
		}
	}
	// Exercise every public view on every referenced id; any panic fails the test.
	for _, n := range w.order {
		id := w.ids[n]
		r.Resource(id)
		r.Observation(id)
	}
	for b := byte(0); b < 16; b++ {
		r.Artifact(digest(b))
		r.Observations(digest(b))
		r.Verify(digest(b))
	}
	s := w.admit()
	w.expect(s, "Gen", identitymodel.Denied, "invalid_actor_binding") // genesis is raw-key only in the profile
	w.expect(s, "Ed", identitymodel.Unknown, "unsupported_evidence")
	w.expect(s, "Obs", identitymodel.Denied, "invalid_actor_binding")
	w.expect(s, "A1", identitymodel.Unknown, "unsupported_root_event")
}

// Over the admission cap the whole snapshot is refused: no partial evidence set can produce a pass. Unverified
// future-major lines are cheap distinct statements, so the cap is reached without signing 100k lines.
func TestAdmitCapRefusesWholeSnapshot(t *testing.T) {
	signer := key("cap", false).Signer()
	lines := make([][]byte, 0, identity.MaxAdmitLines+1)
	for i := 0; i <= identity.MaxAdmitLines; i++ {
		lines = append(lines, canon.Encode(obj("rc", "rc/9", "kind", "x", "signer", signer, "seq", 0, "prev", nil,
			"n", i, "sig", "00")))
	}
	if _, err := identity.Admit(lines[:identity.MaxAdmitLines]); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	if s, err := identity.Admit(lines); err == nil || s != nil {
		t.Fatalf("over the cap admitted a snapshot")
	}
}
