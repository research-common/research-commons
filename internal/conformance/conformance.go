// Package conformance ties the Go tests to docs/CONFORMANCE.md and to the wire-format vectors.
//
// Every case id in CONFORMANCE.md and in the profile notes (ProfileNotes) is a subtest of TestConformanceCases. A case passes there only when at
// least one test elsewhere in the module declares it with Covers(t, "<id>"), meaning that test checks the
// case's whole required outcome. A test that checks only the layers built so far declares
// Partial(t, "<id>", "<what is still unchecked>"); the case stays skipped and the report names both. Every
// other case is pending (skipped), so the list of what is not built yet is always one `go test -v` away. A
// call naming an id the document does not contain fails the build, so a renamed or mistyped case cannot pass
// silently. An id defined in two documents fails too.
//
// The coverage scan is static (go/parser over every _test.go file), so it sees a Covers call whether or not
// that test ran in this invocation. Run the whole module (`go test ./...`) to run the tests themselves.
package conformance

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// Covers records that the calling test checks the named conformance cases. It does nothing at run time
// beyond a log line; the harness finds the call statically.
func Covers(t testing.TB, ids ...string) {
	t.Helper()
	for _, id := range ids {
		t.Logf("conformance: %s", id)
	}
}

// Partial records that the calling test checks part of one conformance case. remaining says what the case
// requires that no test checks yet (usually a layer not built: the log, pull, a surface).
func Partial(t testing.TB, id, remaining string) {
	t.Helper()
	t.Logf("conformance (partial): %s; remaining: %s", id, remaining)
}

// caseRow matches a table row that defines a case: "| C-core-12 | ..." or "| P-03 | ...".
var caseRow = regexp.MustCompile(`(?m)^\| ((?:C-(?:core|exec|exch|btc)-[0-9]+[a-z]?)|(?:P-[0-9]+)) \|`)

// ProfileNotes are the design notes, besides CONFORMANCE.md, whose tables define conformance cases: a profile's
// supplementary regressions stay in its own note. Paths are relative to the repository root.
var ProfileNotes = []string{"docs/DESIGN-notes-bitcoin-time.md"}

// Doc is one document the case ids are read from.
type Doc struct {
	Name  string
	Bytes []byte
}

// CaseIDs returns every case id defined in one document, in document order, and an error if any id is
// defined twice.
func CaseIDs(doc []byte) ([]string, error) {
	ids, _, err := CaseIDsAcross(Doc{Name: "document", Bytes: doc})
	return ids, err
}

// CaseIDsAcross returns every case id defined in docs, in order (document by document), with the document
// that defines each. An id defined twice, in one document or in two, is an error: every case has exactly one
// home. A note that wants to restate a case defined elsewhere writes the id in backticks, which the row
// pattern does not match.
func CaseIDsAcross(docs ...Doc) ([]string, map[string]string, error) {
	var ids []string
	home := map[string]string{}
	for _, d := range docs {
		for _, m := range caseRow.FindAllSubmatch(d.Bytes, -1) {
			id := string(m[1])
			if prev, ok := home[id]; ok {
				if prev == d.Name {
					return nil, nil, errors.New("case defined twice: " + id + " in " + d.Name)
				}
				return nil, nil, errors.New("case defined twice: " + id + " in " + prev + " and " + d.Name)
			}
			home[id] = d.Name
			ids = append(ids, id)
		}
	}
	return ids, home, nil
}

// LoadCaseIDs reads docs/CONFORMANCE.md and every ProfileNotes file under root and returns their case ids.
func LoadCaseIDs(root string) ([]string, map[string]string, error) {
	var docs []Doc
	for _, rel := range append([]string{"docs/CONFORMANCE.md"}, ProfileNotes...) {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			return nil, nil, err
		}
		docs = append(docs, Doc{Name: rel, Bytes: b})
	}
	return CaseIDsAcross(docs...)
}

// Profile returns the scope a case belongs to: core, exec, exch, btc or property.
func Profile(id string) string {
	if id[0] == 'P' {
		return "property"
	}
	return regexp.MustCompile(`^C-([a-z]+)-`).FindStringSubmatch(id)[1]
}

// RepoRoot walks up from the working directory to the directory holding go.mod.
func RepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found above " + dir)
		}
		dir = parent
	}
}

// SortedKeys is a small helper for deterministic reporting.
func SortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
