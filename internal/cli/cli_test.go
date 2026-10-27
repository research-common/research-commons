package cli

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/run"
	"github.com/research-common/research-commons/internal/wire"
)

// storeCommands are the registered commands that read a store, with the arguments the sweep gives them.
func sweepArgs(w *world) [][]string {
	var out [][]string
	for _, c := range Commands() {
		name := strings.Fields(c.Name)
		if !c.Store {
			// a command that reads no store runs in a fixture of its own (hub check: the store as a git hub)
			if a := w.sweepNonStore(c); a != nil {
				out = append(out, a)
			}
			continue
		}
		if len(c.Args) == 0 || c.Args[0].Optional {
			out = append(out, name)
			continue
		}
		if c.Args[0].Shape == ShapeText {
			out = append(out, append(name, w.pkgDir()))
			continue
		}
		for _, r := range w.refsOf() {
			out = append(out, append(slices.Clone(name), r))
		}
	}
	return out
}

func TestVerifyExits(t *testing.T) {
	conformance.Partial(t, "C-core-133", "checked and passed, checked and wrong, contested, unknown (no authorship claim), unchecked and nothing to re-run exit through the CLI; timeout, failed step and environment mismatch need a re-run path in verify (run.VerifyWithRerun is tested in internal/run)")
	w := fixture(t)
	cases := []struct {
		blob  string
		exit  int
		cause string
	}{
		{"sole", 0, ""}, {"t0", 0, ""}, {"div1", 1, "diverged"}, {"contested", 3, "contested"},
		{"nobody", 3, "no authorship claim"}, {"prot1", 3, "unchecked"}, {"solo", 3, "not re-derived"}, {"partial", 4, "unpinned"},
	}
	for _, c := range cases {
		r := w.run("verify", dig(c.blob), "--json")
		if r.code != c.exit {
			t.Errorf("verify %s: exit %d, want %d\n%s%s", c.blob, r.code, c.exit, r.stdout, r.stderr)
			continue
		}
		toks := map[string]string{}
		collect(jsonOf(t, r), "", toks)
		found := c.cause == ""
		for p, v := range toks {
			if strings.Contains(p, "causes") && v == c.cause {
				found = true
			}
		}
		if !found {
			t.Errorf("verify %s: cause %q missing: %v", c.blob, c.cause, toks)
		}
	}
	// the exit table is the run package's table: every run token exits a code the CLI table names the same way
	for _, k := range []run.Kind{run.Match, run.Diverged, run.Unchecked, run.NotComparable, run.IncompleteOutput, run.FailedExit,
		run.FailedCap, run.Timeout, run.EnvMismatch, run.NothingToRerun} {
		ExitName(k.Exit())
	}
	if run.NothingToRerun.Exit() != ExitNothing || run.EnvMismatch.Exit() != ExitEnvironment || run.Diverged.Exit() != ExitWrong {
		t.Fatal("exit codes drifted from the execution table")
	}
}

// TestExitTwo: C-core-133a. Every command: unknown option, malformed argument, unparseable policy exit 2 with
// a problem-details object, committed false, the root unchanged and nothing on stdout but the problem; help
// exits 0; a verify needing an unconfigured Bitcoin backend exits 3 with backend-unconfigured.
func TestExitTwo(t *testing.T) {
	conformance.Covers(t, "C-core-133a")
	w := fixture(t)
	check := func(label string, r result, before string) {
		t.Helper()
		if r.code != 2 {
			t.Fatalf("%s: exit %d, want 2\n%s%s", label, r.code, r.stdout, r.stderr)
		}
		p := jsonOf(t, r)
		for _, k := range []string{"type", "title", "detail", "class", "scope", "committed", "next"} {
			if _, ok := p.Members[k]; !ok {
				t.Fatalf("%s: problem lacks %s: %s", label, k, r.stdout)
			}
		}
		if p.Members["committed"] != canon.Bool(false) {
			t.Fatalf("%s: committed not false", label)
		}
		if after := snapshot(t, w.root); after != before {
			t.Fatalf("%s: root changed", label)
		}
	}
	for _, c := range Commands() {
		before := snapshot(t, w.root)
		name := strings.Fields(c.Name)
		check(c.Name+" unknown option", w.run(append(slices.Clone(name), "--no-such-option", "--json")...), before)
		if len(c.Args) > 0 {
			for _, bad := range []string{"not-an-id", strings.Repeat("AB", 32), "sha256:" + strings.Repeat("0", 63)} {
				check(c.Name+" malformed "+bad, w.run(append(slices.Clone(name), bad, "--json")...), before)
			}
		}
		for _, bad := range w.badInvocations(c) {
			check(c.Name+" "+strings.Join(bad, " "), w.run(append(append(slices.Clone(name), bad...), "--json")...), before)
		}
		if r := w.run(append(slices.Clone(name), "--help")...); r.code != 0 {
			t.Fatalf("%s --help: exit %d", c.Name, r.code)
		}
		if r := w.run(append([]string{"help"}, name...)...); r.code != 0 {
			t.Fatalf("help %s: exit %d", c.Name, r.code)
		}
	}
	// (c) a policy file present and unparseable, and one with an undefined field
	for _, body := range []string{`{"policy":"rc-hub-policy/1",`, `{"policy":"rc-hub-policy/1","policy":"x"}`, `{"policy":"rc-hub-policy/1","trust":1}`} {
		os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(body), 0o644)
		before := snapshot(t, w.root)
		for _, a := range sweepArgs(w)[:1] {
			check("policy "+body, w.run(append(a, "--json")...), before)
		}
		for _, c := range Commands() {
			if c.Store {
				args := strings.Fields(c.Name)
				if len(c.Args) > 0 {
					args = append(args, dig("sole"))
				}
				check(c.Name+" policy "+body, w.run(append(args, "--json")...), before)
			}
		}
	}
	os.Remove(filepath.Join(w.root, PolicyFile))
	// no store: a directory without a marker
	empty := t.TempDir()
	r := runIn(empty, nil, "list", "--json")
	if r.code != 2 {
		t.Fatalf("no store: exit %d", r.code)
	}
	if ents, _ := os.ReadDir(empty); len(ents) != 0 {
		t.Fatal("a read command created a store")
	}
	if r := runIn(empty, nil, "help"); r.code != 0 {
		t.Fatal("help")
	}
	// (e) control: the anchors need a chain backend; none is configured
	r = w.run("verify", w.ids["anc1"], "--json")
	if r.code != 3 || !strings.Contains(r.stdout, `"time_state":"backend-unconfigured"`) {
		t.Fatalf("anchor verify without backend: exit %d\n%s", r.code, r.stdout)
	}
	r = w.run("verify", dig("contested"), "--json")
	if r.code != 3 || !strings.Contains(r.stdout, `"time_state":"backend-unconfigured"`) {
		t.Fatalf("contested verify without backend: exit %d\n%s", r.code, r.stdout)
	}
	// no fixture exits 1 except the completed comparison that disagreed
	for _, a := range sweepArgs(w) {
		if r := w.run(a...); r.code == 1 && !(a[0] == "verify" && a[1] == dig("div1")) && !w.mayRefuse(a) {
			t.Fatalf("%v exits 1", a)
		}
	}
}

// TestClosedVocabulary: C-core-132. Every surface over the fixture set prints only tokens of the table, and
// every exit is in the exit table; every token constant of the layers below is documented in the table.
func TestClosedVocabulary(t *testing.T) {
	conformance.Partial(t, "C-core-132", "every CLI surface (show, verify, explain, list, status, hub check, pull, gc, fsck) over the fixture set prints only table tokens and table exits, and the table is the docs' source; a rule evaluation's ok/fail/unchecked reaches the CLI only inside the gate's intended_for label detail, not yet as its own typed member")
	w := fixture(t)
	for _, a := range sweepArgs(w) {
		r := w.run(append(a, "--json")...)
		ExitName(r.code)
		if r.code == 2 || strings.Contains(r.stdout, "internal-error") {
			t.Fatalf("%v: %d %s", a, r.code, r.stdout)
		}
		toks := map[string]string{}
		collect(jsonOf(t, r), "", toks)
		for p, v := range toks {
			if !IsToken(v) {
				t.Errorf("%v: %s = %q is not in the closed vocabulary", a, p, v)
			}
		}
		h := w.run(a...)
		if h.code != r.code {
			t.Errorf("%v: human exit %d, json exit %d", a, h.code, r.code)
		}
		for _, v := range toks {
			if !strings.Contains(h.stdout, v) {
				t.Errorf("%v: token %q on the JSON surface is missing on the human surface", a, v)
			}
		}
	}
	var below []string
	for _, s := range []resolve.AuthorshipState{resolve.NoClaim, resolve.SoleAuthor, resolve.Derived, resolve.Priority, resolve.ContestedAuthorship} {
		below = append(below, string(s))
	}
	for _, s := range []resolve.FieldState{resolve.FieldDefault, resolve.FieldContested, resolve.FieldAbsent, resolve.FieldNoDefault} {
		below = append(below, string(s))
	}
	below = append(below, resolve.NoDerivation, resolve.NotRederived, resolve.IdenticalProto, resolve.DivergedToken,
		resolve.UncheckedToken, resolve.NotComparable, resolve.ObservationLeaf, resolve.NotHeld, "T0", "T1", "T2",
		string(resolve.NoBound), string(resolve.Local), string(resolve.Bitcoin),
		string(wire.Valid), string(wire.Unsupported), string(wire.UnknownKind), string(keylog.Chained), string(keylog.Detached),
		"committed, pending install", "committed, needs repair", "replayed", "projected", "needs repair", "quarantined",
		"replaced statement", "removed temporary", string(resolve.RuleOK), string(resolve.RuleFail), string(resolve.RuleUnchecked))
	for _, s := range []btctime.State{btctime.StateVerified, btctime.StateVerifiedHistorical, btctime.StatePending, btctime.StateInsufficient,
		btctime.StateMissingProof, btctime.StateInvalidProof, btctime.StateInvalidAnchor, btctime.StateUnknownHeight, btctime.StateOrphaned,
		btctime.StateStaleChain, btctime.StateUnconfigured, btctime.StateUnavailable, btctime.StateUnsupported, btctime.StateRefused} {
		below = append(below, string(s))
	}
	for _, b := range below {
		if !IsToken(b) {
			t.Errorf("token %q of a lower layer is not in the closed vocabulary", b)
		}
	}
	for code := 0; code < 64; code++ {
		func() {
			defer func() { recover() }()
			ExitName(code)
			if code > 5 {
				t.Errorf("exit %d in the table", code)
			}
		}()
	}
}

// TestOutputsDoc: the documented table is generated from the same source as the code (C-core-132, 133).
func TestOutputsDoc(t *testing.T) {
	root, _ := conformance.RepoRoot()
	p := filepath.Join(root, "docs", "CLI-OUTPUTS.md")
	want := outputsMarkdown()
	if os.Getenv("RC_UPDATE_DOCS") == "1" {
		os.WriteFile(p, []byte(want), 0o644)
	}
	got, err := os.ReadFile(p)
	if err != nil || string(got) != want {
		t.Fatalf("docs/CLI-OUTPUTS.md is not the generated table; run RC_UPDATE_DOCS=1 go test -run TestOutputsDoc ./internal/cli")
	}
}

// TestOneAnswer: C-core-134, C-core-135, C-core-66. show, list, verify and explain give the same authorship,
// grade and disclosure tokens for each blob, and every one prints the full disclosure set beside the grade.
func TestOneAnswer(t *testing.T) {
	conformance.Partial(t, "C-core-134", "authorship, grade, disclosures and labels agree across show, list, verify and explain; corroboration status has no CLI surface yet (the observation view is not wired to a command)")
	conformance.Partial(t, "C-core-135", "listing exits 0 and verify exits 3, both showing contested; push is not built")
	conformance.Partial(t, "C-core-66", "show, list, verify and explain print the full disclosure set beside every grade; the hub CI summary is the gate's surface")
	w := fixture(t)
	listing := jsonOf(t, w.run("list", "--json"))
	if w.run("list").code != 0 {
		t.Fatal("list exit")
	}
	byDigest := map[string]*canon.Object{}
	for _, b := range listing.Members["blobs"].(canon.Array) {
		o := b.(*canon.Object)
		byDigest[string(o.Members["digest"].(canon.String))] = o
	}
	for _, n := range []string{"sole", "contested", "t0", "div1", "prot1", "solo", "partial", "retracted"} {
		d := dig(n)
		var core []string
		for _, src := range []*canon.Object{byDigest[d], jsonOf(t, w.run("show", d, "--json")), jsonOf(t, w.run("verify", d, "--json")), jsonOf(t, w.run("explain", d, "--json"))} {
			if src == nil {
				t.Fatalf("%s not listed", n)
			}
			for _, k := range []string{"grade", "disclosures"} {
				if _, ok := src.Members[k]; !ok {
					t.Fatalf("%s: a surface lacks %s", n, k)
				}
			}
			ds := src.Members["disclosures"].(*canon.Object)
			for _, name := range resolve.Disclosures {
				if _, ok := ds.Members[name]; !ok {
					t.Fatalf("%s: disclosure %s missing beside the grade", n, name)
				}
			}
			s := ""
			for _, k := range []string{"authorship", "grade", "disclosures", "labels", "bytes"} {
				if m, ok := src.Members[k]; ok {
					s += k + "=" + string(canon.Encode(m))
				}
			}
			core = append(core, s)
		}
		for _, c := range core[1:] {
			if c != core[0] {
				t.Fatalf("%s: surfaces disagree:\n%s\n%s", n, core[0], c)
			}
		}
	}
	if !strings.Contains(w.run("list").stdout, "contested") || w.run("verify", dig("contested")).code != 3 {
		t.Fatal("contested listing / verify")
	}
	if !strings.Contains(string(canon.Encode(byDigest[dig("retracted")])), `"labels":["retracted"]`) {
		t.Fatal("retracted label missing from the listing")
	}
}

// TestExplain: C-core-136. For every token shown on every fixture, explain lists the statements (hash and
// signer), the policy digest, the evaluator version and the time context.
func TestExplain(t *testing.T) {
	conformance.Covers(t, "C-core-136")
	w := fixture(t)
	for _, r := range w.refsOf() {
		e := jsonOf(t, w.run("explain", r, "--json"))
		for _, k := range []string{"statements", "policy", "evaluator", "time_context"} {
			if _, ok := e.Members[k]; !ok {
				t.Fatalf("explain %s lacks %s", r, k)
			}
		}
		pol := e.Members["policy"].(*canon.Object)
		if d, _ := pol.Members["digest"].(canon.String); !isDigest(string(d)) {
			t.Fatalf("explain %s: policy digest %v", r, pol.Members["digest"])
		}
		show := jsonOf(t, w.run("show", r, "--json"))
		st := e.Members["statements"].(canon.Array)
		// everything show cites by id is among explain's statements, each with its signer
		cited := map[string]bool{}
		for _, x := range st {
			o := x.(*canon.Object)
			id := string(o.Members["statement"].(canon.String))
			cited[id] = true
			if _, held := o.Members["signer"]; !held && o.Members["status"] != canon.String("no statement held") {
				t.Fatalf("explain %s: statement %s without signer", r, id)
			}
		}
		var walk func(canon.Value)
		walk = func(v canon.Value) {
			switch x := v.(type) {
			case *canon.Object:
				for _, k := range x.Keys {
					if k == "statement" || k == "statements" {
						switch y := x.Members[k].(type) {
						case canon.String:
							if !cited[string(y)] {
								t.Errorf("explain %s: show cites %s, explain does not list it", r, y)
							}
						case canon.Array:
							for _, z := range y {
								if s, ok := z.(canon.String); ok && !cited[string(s)] {
									t.Errorf("explain %s: show cites %s, explain does not list it", r, s)
								}
							}
						}
					}
					walk(x.Members[k])
				}
			case canon.Array:
				for _, z := range x {
					walk(z)
				}
			}
		}
		if isDigest(r) {
			walk(show)
		}
	}
	// P-08 seam: a policy change is a different answer, named by its digest
	a := jsonOf(t, w.run("explain", dig("sole"), "--json")).Members["policy"].(*canon.Object).Members["digest"]
	os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","blobs":"external-only"}`), 0o644)
	b := jsonOf(t, w.run("explain", dig("sole"), "--json")).Members["policy"].(*canon.Object).Members["digest"]
	if a == b {
		t.Fatal("a policy change did not change the policy digest")
	}
}

// TestInert: C-core-122. Peer text with terminal escapes, HTML and shell metacharacters, rendered on every
// surface in both forms: no control sequence reaches the output unescaped, the JSON value round-trips, and
// the CLI links no code path that executes or fetches anything.
func TestInert(t *testing.T) {
	conformance.Covers(t, "C-core-122")
	w := fixture(t)
	sawHostile := false
	for _, a := range sweepArgs(w) {
		for _, js := range []bool{false, true} {
			args := a
			if js {
				args = append(append([]string{}, a...), "--json")
			}
			r := w.run(args...)
			out := r.stdout + r.stderr
			for _, bad := range []string{"\x1b", "\x07", "\u009b", "\u202e", "\r"} {
				if strings.Contains(out, bad) {
					t.Fatalf("%v: raw %q reached the output", args, bad)
				}
			}
			if js && strings.Contains(r.stdout, `\u001b]0;owned`) {
				sawHostile = true
				found := false
				var walk func(canon.Value)
				walk = func(v canon.Value) {
					switch x := v.(type) {
					case canon.String:
						found = found || string(x) == Hostile
					case *canon.Object:
						for _, m := range x.Members {
							walk(m)
						}
					case canon.Array:
						for _, m := range x {
							walk(m)
						}
					}
				}
				walk(jsonOf(t, r))
				if !found {
					t.Fatalf("%v: hostile text did not round-trip through JSON", args)
				}
			}
			if !js && strings.Contains(r.stdout, "<script>") && !strings.Contains(r.stdout, `\x1b]0;owned`) && !strings.Contains(r.stdout, `\u001b]0;owned`) {
				t.Fatalf("%v: hostile text shown without its escapes", args)
			}
		}
	}
	if !sawHostile {
		t.Fatal("the hostile fixture text never reached a surface; the test checks nothing")
	}
	if _, err := os.Stat("/tmp/rc-pwned"); err == nil {
		t.Fatal("something executed peer text")
	}
	// static: the CLI and the binary import nothing that executes or touches the network
	root, _ := conformance.RepoRoot()
	for _, dir := range []string{"internal/cli", "cmd/commons"} {
		ents, _ := os.ReadDir(filepath.Join(root, dir))
		for _, e := range ents {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, dir, e.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				p, _ := strconv.Unquote(imp.Path.Value)
				if p == "os/exec" || p == "net" || strings.HasPrefix(p, "net/") || p == "html/template" || p == "text/template" || strings.HasSuffix(p, "/internal/run") {
					t.Errorf("%s/%s imports %s", dir, e.Name(), p)
				}
			}
		}
	}
	// the CLI's reader of partial provenance agrees with the execution layer's
	b := obj("provenance_partial", canon.Value(obj("unpinned", []string{"a", "b"})))
	if strings.Join(unpinnedOf(b), ",") != strings.Join(run.UnpinnedOf(b), ",") {
		t.Fatal("unpinnedOf drifted from run.UnpinnedOf")
	}
}

// TestStatusAndVersion: status reports the durability declaration and the journal; --version names a commit.
func TestStatusAndVersion(t *testing.T) {
	w := fixture(t)
	s := jsonOf(t, w.run("status", "--json"))
	if s.Members["store_state"] != canon.String("nothing pending") {
		t.Fatalf("status: %s", canon.Encode(s))
	}
	for _, k := range []string{"file_sync", "dir_sync", "rename", "exclusive_create", "same_filesystem", "locks", "gc_grace", "history", "assumes"} {
		if _, ok := s.Members["durability"].(*canon.Object).Members[k]; !ok {
			t.Fatalf("durability lacks %s", k)
		}
	}
	// a corrupt pending journal record: quarantined on open, reported, nothing from it installed
	os.WriteFile(filepath.Join(w.root, "journal", "pending", strings.Repeat("0", 64)+".json"), []byte("{"), 0o644)
	s = jsonOf(t, w.run("status", "--json"))
	if !strings.Contains(string(canon.Encode(s)), `"what":"quarantined"`) {
		t.Fatalf("quarantine not reported: %s", canon.Encode(s))
	}
	v := jsonOf(t, runIn(t.TempDir(), nil, "--version", "--json"))
	if v.Members["version"] != canon.String("test") || v.Members["commit"] != canon.String("0000000") {
		t.Fatalf("version: %s", canon.Encode(v))
	}
	// store discovery: COMMONS_STORE, then the nearest ancestor holding rc-store
	sub := filepath.Join(w.root, "statements")
	if r := runIn(sub, nil, "list"); r.code != 0 {
		t.Fatalf("ancestor discovery: %d %s", r.code, r.stderr)
	}
	if r := runIn(t.TempDir(), map[string]string{StoreEnv: w.root}, "list"); r.code != 0 {
		t.Fatalf("env discovery: %d %s", r.code, r.stderr)
	}
}
