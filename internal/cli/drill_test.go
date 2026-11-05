package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/run"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// drillStore initialises a store in a fresh directory through the command line.
func drillStore(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "store")
	if r := runIn(filepath.Dir(d), nil, "init", d, "--json"); r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stdout)
	}
	return d
}

func drillWrite(t *testing.T, dir, name, data string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestTwoStoreDrill: the loop a second reader runs, through the command line only: one store publishes, another
// pulls and verifies; a hub checkout needs --from-checkout; two stores that each extend one task from the same
// edition are pulled into a third and the resolver reports the fork.
//
// C-core-86: the resolver half (two controllers, one controller twice, every arrival order, each branch
// authorised by its own controller's rule) is TestEditionFork in internal/resolve; this test is the two-hub
// half through `pull`, with a control that pulls one source only and so must not fork.
func TestTwoStoreDrill(t *testing.T) {
	conformance.Covers(t, "C-core-86")
	keys := t.TempDir()
	key, signer := newKeyFile(t, keys, wire.AlgEd25519)
	content := drillWrite(t, keys, "c", "drill content")

	a := drillStore(t)
	r := runIn(a, nil, "publish", "--key", key, "--kind", "authored", "--content", content, "--licence", "CC0-1.0", "--json")
	if r.code != 0 {
		t.Fatalf("publish: %d %s", r.code, r.stdout)
	}
	blob := run.Digest([]byte("drill content"))

	b := drillStore(t)
	if r := runIn(b, nil, "pull", a, "--json"); r.code != 0 {
		t.Fatalf("pull: %d %s", r.code, r.stdout)
	}
	for name, dir := range map[string]string{"a": a, "b": b} {
		if r := runIn(dir, nil, "verify", blob, "--json"); r.code != 0 || !strings.Contains(r.stdout, `"authorship":"sole author"`) {
			t.Fatalf("verify in %s: %d %s", name, r.code, r.stdout)
		}
		if r := runIn(dir, nil, "fsck", "--json"); r.code != 0 {
			t.Fatalf("fsck in %s: %d %s", name, r.code, r.stdout)
		}
	}

	// a git-checkout-shaped package: refused as it is, admitted with the flag, the .git skipped
	pkg := t.TempDir()
	copyData(t, a, pkg)
	os.MkdirAll(filepath.Join(pkg, ".git", "hooks"), 0o755)
	drillWrite(t, filepath.Join(pkg, ".git"), "HEAD", "ref: refs/heads/main\n")
	c := drillStore(t)
	if r := runIn(c, nil, "pull", pkg, "--json"); r.code != 1 {
		t.Fatalf("checkout without the flag: %d %s", r.code, r.stdout)
	}
	if r := runIn(c, nil, "pull", pkg, "--from-checkout", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"skipped":[".git`) {
		t.Fatalf("checkout with the flag: %d %s", r.code, r.stdout)
	}

	// two sources, each carrying a different second edition of one task, with one predecessor
	root := drillStore(t)
	ct := func(extra string) string {
		return drillWrite(t, keys, "ct"+extra+".json", `{"profile":"`+resolve.ProvisionalProfile+`","beneficiary":"`+signer+`","any_issuer":true`+extra+`}`)
	}
	r = runIn(root, nil, "publish", "task", "--key", key, "--name", "drill task", "--contract", ct(""), "--json")
	if r.code != 0 {
		t.Fatalf("publish task: %d %s", r.code, r.stdout)
	}
	task := string(jsonOf(t, r).Members["task"].(canon.String))
	left, right := drillStore(t), drillStore(t)
	for i, dir := range []string{left, right} {
		if r := runIn(dir, nil, "pull", root, "--json"); r.code != 0 {
			t.Fatalf("seed %d: %d %s", i, r.code, r.stdout)
		}
	}
	// each source extends the task from the same edition with a different contract
	for dir, extra := range map[string]string{left: `,"note":"left"`, right: `,"note":"right"`} {
		if r := runIn(dir, nil, "publish", "task", "--key", key, "--task", task, "--contract", ct(extra), "--json"); r.code != 0 {
			t.Fatalf("second edition: %d %s", r.code, r.stdout)
		}
	}
	// control: one source alone is no fork (the mutation reaches the boundary the pulls below test)
	one := drillStore(t)
	if r := runIn(one, nil, "pull", left, "--json"); r.code != 0 {
		t.Fatalf("pull one: %d %s", r.code, r.stdout)
	}
	ost, err := store.Open(one, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ov, err := loadView(ost, nil, resolve.WithContractReader(resolve.ProvisionalContract{}))
	if err != nil {
		t.Fatal(err)
	}
	if ot, ok := ov.r.Task(task); !ok || ot.Current == "" || len(ot.Tips) != 1 {
		t.Fatalf("one source alone: ok=%v current=%q tips=%v", ok, ot.Current, ot.Tips)
	}

	// pulled into one store, in either order: the resolver holds both editions and no tip
	for _, order := range [][]string{{left, right}, {right, left}} {
		reader := drillStore(t)
		for _, src := range order {
			if r := runIn(reader, nil, "pull", src, "--json"); r.code != 0 {
				t.Fatalf("pull %s: %d %s", src, r.code, r.stdout)
			}
		}
		st, err := store.Open(reader, store.Options{})
		if err != nil {
			t.Fatal(err)
		}
		v, err := loadView(st, nil, resolve.WithContractReader(resolve.ProvisionalContract{}))
		if err != nil {
			t.Fatal(err)
		}
		tk, ok := v.r.Task(task)
		if !ok || tk.Current != "" || len(tk.Tips) != 2 {
			t.Fatalf("task after both pulls: ok=%v current=%q tips=%v", ok, tk.Current, tk.Tips)
		}
		// the resolver reports the fork and names no tip, by arrival order or otherwise
		res, ok := v.r.Resource(task)
		if !ok || res.Current != "" || res.VerifyExit() != 3 || len(res.Forks) != 1 || res.Forks[0].Cleared() ||
			len(res.Forks[0].Branches) != 2 || !strings.Contains(res.Render(), "FORK at") {
			t.Fatalf("resource after both pulls: ok=%v current=%q exit=%d forks=%+v", ok, res.Current, res.VerifyExit(), res.Forks)
		}
		for _, e := range tk.Tips {
			if ed, ok := res.Edition(e); !ok || ed.State != resolve.Authorized {
				t.Fatalf("branch %s is not an authorised edition: %+v", e, ed)
			}
		}
		// the reader's own next edition is refused: the key's log has two tips, and so does the task
		r := runIn(reader, nil, "publish", "task", "--key", key, "--task", task, "--contract", ct(`,"note":"third"`), "--json")
		if r.code != ExitCouldNot || !strings.Contains(r.stdout, "FORK") {
			t.Fatalf("publish onto a fork: %d %s", r.code, r.stdout)
		}
		if r := runIn(reader, nil, "fsck", "--json"); r.code != 0 {
			t.Fatalf("fsck: %d %s", r.code, r.stdout)
		}
	}
}
