package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

func helpText(t *testing.T, cols string, args ...string) string {
	t.Helper()
	var env map[string]string
	if cols != "" {
		env = map[string]string{"COLUMNS": cols}
	}
	r := runIn(t.TempDir(), env, args...)
	if r.code != 0 || r.stderr != "" {
		t.Fatalf("%v: exit %d, stderr %q", args, r.code, r.stderr)
	}
	return r.stdout
}

// The text pages are pinned at COLUMNS=80 (RC_UPDATE_DOCS=1 rewrites them).
func TestHelpTextGolden(t *testing.T) {
	for name, args := range map[string][]string{
		"text-top.golden":     {"help"},
		"text-publish.golden": {"help", "publish"},
		"text-verify.golden":  {"help", "verify"},
		"text-exits.golden":   {"help", "exits"},
	} {
		checkGolden(t, name, helpText(t, "80", args...))
	}
}

func TestTermWidth(t *testing.T) {
	for in, want := range map[string]int{"": 80, "abc": 80, "0": 80, "-5": 80, "40": 60, "60": 60, "100": 100, "120": 120, "500": 120, " 90 ": 90} {
		if got := termWidth(&Env{Getenv: func(string) string { return in }}); got != want {
			t.Errorf("COLUMNS=%q: width %d, want %d", in, got, want)
		}
	}
	if termWidth(&Env{}) != 80 {
		t.Error("nil Getenv")
	}
}

// Every page fits the width it was rendered for, at every width, and ends with a newline.
func TestHelpTextFitsWidth(t *testing.T) {
	pages := [][]string{{"help"}, {"help", "exits"}, {"help", "outputs"}}
	for _, c := range Commands() {
		pages = append(pages, append([]string{"help"}, strings.Fields(c.Name)...))
	}
	for _, cols := range []string{"60", "80", "120"} {
		w := map[string]int{"60": 60, "80": 80, "120": 120}[cols]
		for _, p := range pages {
			out := helpText(t, cols, p...)
			if !strings.HasSuffix(out, "\n") || strings.HasSuffix(out, "\n\n") {
				t.Errorf("%v: bad ending", p)
			}
			for _, l := range strings.Split(out, "\n") {
				if runeLen(l) > w && strings.Count(strings.TrimSpace(l), " ") > 0 {
					t.Errorf("%v at %d: line of %d columns: %q", p, w, runeLen(l), l)
				}
			}
		}
	}
}

// The paragraph split only breaks between sentences: nothing is reworded, and the JSON description is the
// unsplit Help.
func TestHelpParasKeepEveryWord(t *testing.T) {
	for _, c := range Commands() {
		if got := strings.Join(helpParas(c.Help), " "); got != c.Help {
			t.Errorf("%s: paragraphs differ from Help", c.Name)
		}
		for _, p := range helpParas(c.Help) {
			if p == "" || strings.Contains(p, "\n") {
				t.Errorf("%s: empty or multi-line paragraph %q", c.Name, p)
			}
		}
	}
}

// Every registered command is in exactly one group of the top page, and every group member is registered.
func TestHelpCommandGroups(t *testing.T) {
	seen := map[string]int{}
	for _, g := range commandGroups {
		for _, n := range g.Names {
			seen[n]++
			if commandByName(n) == nil {
				t.Errorf("group %s names %q, which is not registered", g.Title, n)
			}
		}
	}
	for _, c := range Commands() {
		if seen[c.Name] != 1 {
			t.Errorf("command %q is in %d groups", c.Name, seen[c.Name])
		}
	}
	top := helpText(t, "80", "help")
	for _, c := range Commands() {
		if !strings.Contains(top, "  "+c.Name+" ") {
			t.Errorf("command %q is not on the top page", c.Name)
		}
	}
}

// A command with option groups has every one of its options in exactly one group.
func TestHelpOptionGroups(t *testing.T) {
	for name, gs := range optionGroups {
		c := commandByName(name)
		if c == nil {
			t.Fatalf("option groups for unregistered command %q", name)
		}
		seen := map[string]int{}
		for _, g := range gs {
			for _, n := range g.Names {
				seen[n]++
			}
		}
		for _, f := range c.Flags {
			if seen[f.Name] != 1 {
				t.Errorf("%s --%s is in %d option groups", name, f.Name, seen[f.Name])
			}
		}
		for n := range seen {
			if !slices.ContainsFunc(c.Flags, func(f Flag) bool { return f.Name == n }) {
				t.Errorf("%s: group names --%s, which the command lacks", name, n)
			}
		}
	}
	for _, n := range []string{"publish", "run"} {
		if len(optionGroups[n]) == 0 {
			t.Errorf("%s has no option groups", n)
		}
	}
}

// Options show their value placeholder; a command with many options prints the short usage line.
func TestHelpUsageAndPlaceholders(t *testing.T) {
	pub := helpText(t, "80", "help", "publish")
	if !strings.Contains(pub, "\n  commons publish [options] [--json]\n") {
		t.Errorf("publish: not the short usage line:\n%s", pub[:200])
	}
	if !strings.Contains(pub, "  --key <file>") || !strings.Contains(pub, "  --dry-run ") {
		t.Error("publish: options lack placeholders")
	}
	ver := helpText(t, "100", "help", "verify")
	if !strings.Contains(ver, "commons verify [--rerun] [--exec-policy <file>] [--policy <file>] <digest|id> [--json]") {
		t.Errorf("verify: usage line not whole:\n%s", ver)
	}
	// the options of a long usage line are all still named in the listing
	for _, c := range Commands() {
		out := helpText(t, "80", append([]string{"help"}, strings.Fields(c.Name)...)...)
		for _, f := range c.Flags {
			if !strings.Contains(out, "--"+f.Name) {
				t.Errorf("%s: --%s missing from its help", c.Name, f.Name)
			}
		}
	}
}

// Every example parses and runs against a throwaway store. The ones that name a digest get a real one.
func TestHelpExamplesRun(t *testing.T) {
	want := []string{"init", "key new", "publish", "show", "verify", "pull", "push", "explain"}
	for _, n := range want {
		if c := commandByName(n); c == nil || len(c.Examples) == 0 {
			t.Errorf("%s has no examples", n)
		}
	}
	dir := t.TempDir()
	t.Chdir(dir) // the examples name files and the store by relative path
	data := []byte("a,b\n1,2\n")
	os.WriteFile(filepath.Join(dir, "data.csv"), data, 0o644)
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	run := func(wd, ex string) result {
		f := strings.Fields(strings.ReplaceAll(ex, "<digest>", digest))
		if f[0] != "commons" {
			t.Fatalf("example %q does not start with commons", ex)
		}
		return runIn(wd, nil, f[1:]...)
	}
	// the writers first, in the order a reader of the help would try them
	for _, n := range []string{"init", "key new", "publish", "show", "verify", "explain"} {
		for _, ex := range commandByName(n).Examples {
			if r := run(dir, ex); r.code != 0 {
				t.Errorf("%q: exit %d\n%s%s", ex, r.code, r.stdout, r.stderr)
			}
		}
	}
	// pull: ./package is a store tree
	if r := runIn(dir, nil, "init", "package"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	for _, ex := range commandByName("pull").Examples {
		if r := run(dir, ex); r.code == ExitDidNotStart {
			t.Errorf("%q: exit %d\n%s", ex, r.code, r.stderr)
		}
	}
	// push: inside a hub checkout
	p := newPushWorld(t)
	for _, ex := range commandByName("push").Examples {
		if r := run(p.root, ex); r.code == ExitDidNotStart {
			t.Errorf("%q: exit %d\n%s", ex, r.code, r.stderr)
		}
	}
	// the examples are text-surface only
	if strings.Contains(string(helpJSON(t, "publish")), "Examples") {
		t.Error("examples leaked into --json")
	}
	if !strings.Contains(helpText(t, "80", "help", "publish"), "\nExamples:\n  commons publish ") {
		t.Error("publish help has no Examples section")
	}
}

func helpJSON(t *testing.T, name string) []byte {
	t.Helper()
	return []byte(runIn(t.TempDir(), nil, "help", name, "--json").stdout)
}

func nextOf(t *testing.T, args ...string) string {
	t.Helper()
	r := runIn(t.TempDir(), nil, append(args, "--json")...)
	if r.code != ExitDidNotStart {
		t.Fatalf("%v: exit %d", args, r.code)
	}
	o := jsonOf(t, r)
	return string(o.Members["next"].(canon.String))
}

func TestErrorHints(t *testing.T) {
	const list = "run commons help to list the commands"
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"publish", "--bogus"}, "run commons help publish to list its options"},
		{[]string{"hub", "check", "--bogus"}, "run commons help hub check to list its options"},
		{[]string{"--key", "k", "show", "--bogus"}, "run commons help show to list its options"},
		{[]string{"--bogus"}, "run commons help to list the options"},
		{[]string{"publis"}, "did you mean `commons publish`? " + list},
		{[]string{"hub"}, "did you mean `commons hub check`? " + list},
		{[]string{"hub", "chek"}, "did you mean `commons hub check`? " + list},
		{[]string{"help", "shw"}, "did you mean `commons show`? " + list},
		{[]string{"xyzzy"}, list},
		{[]string{"key"}, list}, // two commands start with it: no single suggestion
	} {
		if got := nextOf(t, c.args...); got != c.want {
			t.Errorf("%v: next %q, want %q", c.args, got, c.want)
		}
	}
	// the problem object keeps every other field
	o := jsonOf(t, runIn(t.TempDir(), nil, "publish", "--bogus", "--json"))
	for _, k := range []string{"type", "title", "detail", "class", "scope", "committed", "next", "exit", "peer_text"} {
		if _, ok := o.Members[k]; !ok {
			t.Errorf("problem lacks %q", k)
		}
	}
}
