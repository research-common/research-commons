package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The --json help objects are the stable surface of help: the text layout may change, these bytes may not.
// testdata/help/json-*.golden were captured before the text renderer was added.
func TestHelpJSONGolden(t *testing.T) {
	dir := t.TempDir()
	cases := map[string][]string{
		"json-top.golden":     {"help", "--json"},
		"json-publish.golden": {"help", "publish", "--json"},
		"json-exits.golden":   {"help", "exits", "--json"},
		"json-outputs.golden": {"help", "outputs", "--json"},
	}
	// every command, in registry order, so no command's help object can drift
	var all strings.Builder
	for _, c := range Commands() {
		r := runIn(dir, nil, append([]string{"help"}, append(strings.Fields(c.Name), "--json")...)...)
		if r.code != 0 {
			t.Fatalf("help %s --json: exit %d", c.Name, r.code)
		}
		all.WriteString(r.stdout)
	}
	for name, args := range cases {
		r := runIn(dir, nil, args...)
		if r.code != 0 {
			t.Fatalf("%v: exit %d", args, r.code)
		}
		checkGolden(t, name, r.stdout)
	}
	checkGolden(t, "json-all-commands.golden", all.String())
}

// checkGolden compares got with testdata/help/<name>; RC_UPDATE_DOCS=1 rewrites the file.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("testdata", "help", name)
	if os.Getenv("RC_UPDATE_DOCS") == "1" {
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s differs from the golden; if the change is intended run RC_UPDATE_DOCS=1 go test -run %s ./internal/cli", name, t.Name())
	}
}
