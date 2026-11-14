package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUnmetSelectionIsAnAnswer: a reader-policy authorship-declaration selection that is not met is an answer in
// the closed vocabulary on every read surface (verify exit 3 naming it, show and explain exit 0), never an internal
// error. The pin names a statement that is not held, over a plain blob: no identity is involved.
func TestUnmetSelectionIsAnAnswer(t *testing.T) {
	w := fixture(t)
	d := dig("sole")
	f := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(f, []byte(`{"version":"reader-policy-v1","selections":[{"statement":"`+strings.Repeat("a", 64)+
		`","subject":{"content":"`+d+`","role":"authorship-declaration"}}],"trust":[]}`), 0o644)
	for _, c := range []struct {
		cmd  string
		exit int
	}{{"verify", 3}, {"explain", 0}, {"show", 0}} {
		r := w.run(c.cmd, d, "--policy", f, "--json")
		if strings.Contains(r.stdout+r.stderr, "internal-error") || r.code != c.exit {
			t.Fatalf("%s: exit %d (want %d)\n%s%s", c.cmd, r.code, c.exit, r.stdout, r.stderr)
		}
		toks := map[string]string{}
		collect(jsonOf(t, r), "", toks)
		for p, v := range toks {
			if !IsToken(v) {
				t.Errorf("%s: %s = %q is not in the closed vocabulary", c.cmd, p, v)
			}
		}
		if c.cmd == "verify" && !strings.Contains(r.stdout, "not met: statement not held") {
			t.Errorf("verify does not name the unmet selection:\n%s", r.stdout)
		}
	}
}
