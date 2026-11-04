package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
)

// revoke runs the command with the world's key file, as a pipe (no terminal) unless env says otherwise.
func (p *pubWorld) revoke(args ...string) result {
	return runIn(p.root, nil, append([]string{"revoke", "--key", p.key, "--json"}, args...)...)
}

// describe publishes a describes with the key file, extending prev when given; it returns the statement id.
func (p *pubWorld) describe(t *testing.T, note string, prev ...string) string {
	t.Helper()
	args := []string{"--kind", "describes", "--about", dig("a"), "--note", note}
	if len(prev) > 0 {
		args = append(args, "--prev", prev[0])
	}
	r := p.publish(args...)
	if r.code != 0 {
		t.Fatalf("publish %s: %d %s", note, r.code, r.stdout)
	}
	return idsOf(outObj(t, r))[0]
}

// rotateFrom signs, with the key file's own key, a rotate_key on a branch from prev, as a second holder of the
// key would, and commits it with publish --draft --prev (the writer path; nothing special).
func (p *pubWorld) rotateFrom(t *testing.T, prev string) string {
	t.Helper()
	d := p.file("rot.json", `{"kind":"rotate_key","body":{"successor":"`+testKey("T").Signer()+`"}}`)
	r := p.publish("--draft", d, "--prev", prev)
	if r.code != 0 {
		t.Fatalf("rotate: %d %s", r.code, r.stdout)
	}
	return idsOf(outObj(t, r))[0]
}

func counted(t *testing.T, p *pubWorld, id string) string {
	t.Helper()
	o := jsonOf(t, p.run("show", id, "--json"))
	s, _ := o.Members["counted"].(canon.String)
	return string(s)
}

// TestRevokeSoftRefusesForeignKeyEvent: the CLI half of C-core-127c. A second holder of the key forks from A1 and
// rotates; the owner, extending A2, asks for a soft revocation: refused (exit 1, reader policy) naming the tip
// and the rotation, pointing at key_compromise and --last-good; nothing written. (b) key_compromise with
// last_good = A2 merges nothing: the rotation stops counting, A1 and A2 still count, and the output names the
// rotation as cut. (c) control: a fork whose other tip is the owner's own describes is merged, the fork clears and
// every line counts.
func TestRevokeSoftRefusesForeignKeyEvent(t *testing.T) {
	conformance.Covers(t, "C-core-127c")
	build := func(t *testing.T) (*pubWorld, string, string, string) {
		p := newPubWorld(t)
		a1 := p.describe(t, "A1")
		a2 := p.describe(t, "A2")
		rot := p.rotateFrom(t, a1)
		return p, a1, a2, rot
	}

	t.Run("a soft refused", func(t *testing.T) {
		p, _, a2, rot := build(t)
		before := snapshot(t, p.root)
		for _, reason := range []string{"superseded", "cessation_of_operation"} {
			r := p.revoke("--reason", reason, "--prev", a2)
			o := outObj(t, r)
			if r.code != 1 || o.Members["class"] != canon.String("reader policy") || o.Members["committed"] != canon.Bool(false) {
				t.Fatalf("%s: exit %d %s", reason, r.code, r.stdout)
			}
			peer, _ := o.Members["peer_text"].(canon.String)
			next, _ := o.Members["next"].(canon.String)
			if !strings.Contains(string(o.Members["title"].(canon.String)), keylog.SoftMergeKeyEvent) || !strings.Contains(string(peer), rot) ||
				!strings.Contains(string(peer), "rotate_key") || !strings.Contains(string(next), "key_compromise") || !strings.Contains(string(next), "--last-good") {
				t.Fatalf("%s: refusal does not name the tip, the event and the next step: %s", reason, r.stdout)
			}
			if snapshot(t, p.root) != before {
				t.Fatalf("%s: a refused revocation wrote something", reason)
			}
		}
		// no --prev: the fork carries a key event, so the tool does not pick a branch (exit 3, nothing written)
		r := p.revoke("--reason", "superseded")
		if r.code != 3 || !strings.Contains(r.stdout, "log-fork") || !strings.Contains(r.stdout, "rotate_key") || snapshot(t, p.root) != before {
			t.Fatalf("soft over a fork with a key event, no --prev: %d %s", r.code, r.stdout)
		}
	})

	t.Run("b hard with last_good", func(t *testing.T) {
		p, a1, a2, rot := build(t)
		if c := counted(t, p, rot); c != "counted" {
			t.Fatalf("the rotation should count before the revocation: %s", c)
		}
		// dry run first: the tips are listed, the rotation's branch marked, nothing written
		before := snapshot(t, p.root)
		r := p.revoke("--reason", "key_compromise", "--prev", a2, "--dry-run")
		if r.code != 0 || !strings.Contains(r.stdout, rot) || !strings.Contains(r.stdout, "outside the revocation's history") ||
			!strings.Contains(r.stdout, "rotate_key "+rot[:12]) || snapshot(t, p.root) != before {
			t.Fatalf("hard dry run: %d %s", r.code, r.stdout)
		}
		r = p.revoke("--reason", "key_compromise", "--prev", a2, "--last-good", a2)
		if r.code != 0 {
			t.Fatalf("hard: %d %s", r.code, r.stdout)
		}
		o := outObj(t, r)
		if _, ok := o.Members["merges"]; ok {
			t.Fatalf("a hard revocation merged something on its own: %s", r.stdout)
		}
		if !strings.Contains(string(canon.Encode(o.Members["stop_counting"].(canon.Value))), rot) {
			t.Fatalf("the cut rotation is not named: %s", r.stdout)
		}
		rev := idsOf(o)[0]
		if c := counted(t, p, rot); c != "not counted" {
			t.Fatalf("the rotation still counts after the hard revocation: %s", c)
		}
		if c := counted(t, p, a1); c != "counted" {
			t.Fatalf("A1 does not count: %s", c)
		}
		// A2 is on a branch the rotation does not include: the rotation stays in force and cuts it (every in-force
		// key event can only shrink what counts, claims-model §4.1), whatever the owner signs after
		if c := counted(t, p, a2); c != "not counted" {
			t.Fatalf("A2 counts despite the rotation's sibling rule: %s", c)
		}
		// the revocation is in force and comes after no other key event (it is itself on a branch the rotation
		// leaves out, so the rotation's sibling rule doubts it like A2; what matters is that it is not "after" one)
		rs := string(canon.Encode(jsonOf(t, p.run("show", rev, "--json")).Members["reasons"].(canon.Value)))
		if strings.Contains(rs, "after rotate_key") || !strings.Contains(rs, "sibling rule") {
			t.Fatalf("revocation reasons: %s", rs)
		}
	})

	t.Run("c control own fork merged", func(t *testing.T) {
		p := newPubWorld(t)
		a1 := p.describe(t, "A1")
		a2 := p.describe(t, "A2")
		b := p.describe(t, "B", a1) // the owner's own second branch from A1
		// no --prev: the highest tip is extended and the other merged (a tie at seq 1 here: name it)
		if r := p.revoke("--reason", "superseded"); r.code != 3 || !strings.Contains(r.stdout, "highest seq") {
			t.Fatalf("tie without --prev: %d %s", r.code, r.stdout)
		}
		r := p.revoke("--reason", "superseded", "--prev", a2)
		if r.code != 0 {
			t.Fatalf("soft over own fork: %d %s", r.code, r.stdout)
		}
		o := outObj(t, r)
		m := o.Members["merges"].(canon.Array)
		if len(m) != 1 || m[0] != canon.String(b) {
			t.Fatalf("merges: %s", r.stdout)
		}
		if _, ok := o.Members["stop_counting"]; ok {
			t.Fatalf("a soft revocation over the owner's own tips cut something: %s", r.stdout)
		}
		for _, id := range []string{a1, a2, b, idsOf(o)[0]} {
			if c := counted(t, p, id); c != "counted" {
				t.Fatalf("%s does not count: %s", id[:12], c)
			}
		}
		// the fork cleared: the next publish needs no --prev
		if r := p.publish("--kind", "describes", "--about", dig("a"), "--note", "after"); r.code != 0 {
			t.Fatalf("fork not cleared: %d %s", r.code, r.stdout)
		}
	})
}

// TestRevokeSoftPicksHighestTip: on a forked log with no key event, a soft revocation without --prev extends the
// one highest tip and merges the rest, so nothing of the key is cut.
func TestRevokeSoftPicksHighestTip(t *testing.T) {
	p := newPubWorld(t)
	a1 := p.describe(t, "A1")
	p.describe(t, "A2")
	a3 := p.describe(t, "A3")
	b := p.describe(t, "B", a1)
	r := p.revoke("--reason", "cessation_of_operation")
	if r.code != 0 {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
	o := outObj(t, r)
	if statementsOf(o)[0].Members["prev"] != canon.String(a3) {
		t.Fatalf("prev is not the highest tip: %s", r.stdout)
	}
	if m := o.Members["merges"].(canon.Array); len(m) != 1 || m[0] != canon.String(b) {
		t.Fatalf("merges: %s", r.stdout)
	}
}

// TestRevokeHard: the C-core-143d outcomes through the writer (the case is covered at the resolver). (a) last_good = seq 5 of 0–8: seq 0–5 count, 6–8 don't, and the
// output lists 6–8 as stopping; (b) last_good none: nothing counts, with a warning; (c) a last_good outside the
// history is refused before signing (exit 1); (d) a soft revocation, then a hard one with last_good = seq 4: the
// stricter later event applies.
func TestRevokeHard(t *testing.T) {
	chain := func(t *testing.T, n int) (*pubWorld, []string) {
		p := newPubWorld(t)
		var ids []string
		for i := 0; i < n; i++ {
			ids = append(ids, p.describe(t, "L"+string(rune('0'+i))))
		}
		return p, ids
	}
	t.Run("a last_good seq 5", func(t *testing.T) {
		p, ids := chain(t, 9)
		r := p.revoke("--reason", "key_compromise", "--last-good", ids[5])
		if r.code != 0 {
			t.Fatalf("%d %s", r.code, r.stdout)
		}
		o := outObj(t, r)
		cut := o.Members["stop_counting"].(canon.Array)
		if len(cut) != 3 {
			t.Fatalf("stop_counting: %s", r.stdout)
		}
		for i, id := range ids {
			want := "counted"
			if i > 5 {
				want = "not counted"
			}
			if c := counted(t, p, id); c != want {
				t.Fatalf("seq %d: %s, want %s", i, c, want)
			}
		}
	})
	t.Run("b last_good none", func(t *testing.T) {
		p, ids := chain(t, 3)
		r := p.revoke("--reason", "key_compromise", "--last-good", "none")
		if r.code != 0 || !strings.Contains(r.stdout, "no line of this key counts") {
			t.Fatalf("%d %s", r.code, r.stdout)
		}
		if _, ok := statementsOf(outObj(t, r))[0].Members["body"]; ok {
			t.Fatal("body printed outside a dry run")
		}
		for _, id := range ids {
			if c := counted(t, p, id); c != "not counted" {
				t.Fatalf("%s counts after last_good none", id[:12])
			}
		}
	})
	t.Run("c last_good outside history", func(t *testing.T) {
		p := newPubWorld(t)
		a1 := p.describe(t, "A1")
		a2 := p.describe(t, "A2")
		b := p.describe(t, "B", a1)
		before := snapshot(t, p.root)
		r := p.revoke("--reason", "key_compromise", "--prev", a2, "--last-good", b)
		if r.code != 1 || !strings.Contains(r.stdout, "last-good-outside-history") || snapshot(t, p.root) != before {
			t.Fatalf("%d %s", r.code, r.stdout)
		}
		// the owner keeps b by merging it: then last_good = b is in the history
		r = p.revoke("--reason", "key_compromise", "--prev", a2, "--merge", b, "--last-good", b)
		if r.code != 0 {
			t.Fatalf("merge + last_good: %d %s", r.code, r.stdout)
		}
		if c := counted(t, p, b); c != "counted" {
			t.Fatalf("b: %s", c)
		}
		if c := counted(t, p, a2); c != "not counted" {
			t.Fatalf("a2 is after last_good b in no sense, yet outside last_good's history: %s", c)
		}
	})
	t.Run("d soft then hard", func(t *testing.T) {
		p, ids := chain(t, 9)
		if r := p.revoke("--reason", "superseded"); r.code != 0 {
			t.Fatalf("soft: %d %s", r.code, r.stdout)
		}
		r := p.revoke("--reason", "key_compromise", "--last-good", ids[4])
		if r.code != 0 {
			t.Fatalf("hard after soft: %d %s", r.code, r.stdout)
		}
		for i, id := range ids {
			want := "counted"
			if i > 4 {
				want = "not counted"
			}
			if c := counted(t, p, id); c != want {
				t.Fatalf("seq %d: %s, want %s", i, c, want)
			}
		}
	})
}

// TestRevokeInvocation: no reason and no terminal is exit 2 with nothing written; the prompt on a terminal takes a
// number or a name and refuses anything else; option conflicts; a hard reason without --last-good outside a dry
// run; --merge checks; the dry run signs nothing; the fork rules for a hard reason.
func TestRevokeInvocation(t *testing.T) {
	p := newPubWorld(t)
	a1 := p.describe(t, "A1")
	a2 := p.describe(t, "A2")
	before := snapshot(t, p.root)
	exit2 := [][]string{
		{},                             // no reason, not a terminal
		{"--reason", "unspecified"},    // not offered
		{"--reason", "Key-Compromise"}, // not a token
		{"--reason", "key_compromise"}, // hard without --last-good
		{"--reason", "superseded", "--last-good", a1},
		{"--reason", "superseded", "--merge", a1},
		{"--reason", "key_compromise", "--last-good", "x"},
		{"--reason", "key_compromise", "--last-good", a1, "--merge", a1 + ",zz"},
	}
	for _, a := range exit2 {
		r := p.revoke(a...)
		if r.code != 2 || snapshot(t, p.root) != before {
			t.Fatalf("%v: exit %d %s", a, r.code, r.stdout)
		}
	}
	// a1 is in a2's history: merges never names it; decided over the held log, so not exit 2
	if r := p.revoke("--reason", "key_compromise", "--last-good", a1, "--merge", a1); r.code != 1 || !strings.Contains(r.stdout, "merge-in-history") || snapshot(t, p.root) != before {
		t.Fatalf("merge in history: %d %s", r.code, r.stdout)
	}
	if r := p.revoke(); !strings.Contains(r.stdout, "not a terminal") {
		t.Fatalf("no reason: %s", r.stdout)
	}
	// no key: exit 2 and the first-run guidance
	if r := runIn(p.root, nil, "revoke", "--reason", "superseded", "--json"); r.code != 2 || !strings.Contains(r.stdout, "commons key new --out <file>") {
		t.Fatalf("no key: %d %s", r.code, r.stdout)
	}
	// a terminal: the prompt is on stderr, the answer on stdin
	term := func(in string, args ...string) result {
		var o, e bytes.Buffer
		code := Main(append([]string{"revoke", "--key", p.key, "--json", "--dry-run"}, args...), &Env{Stdout: &o, Stderr: &e,
			Getenv: func(string) string { return "" }, Getwd: func() (string, error) { return p.root, nil },
			Stdin: strings.NewReader(in), Interactive: true})
		return result{code, o.String(), e.String()}
	}
	for _, in := range []string{"2\n", "superseded\n", "3"} {
		r := term(in)
		if r.code != 0 || !strings.Contains(r.stderr, "no default") || !strings.Contains(r.stderr, "1) key_compromise") {
			t.Fatalf("prompt %q: %d %s %s", in, r.code, r.stdout, r.stderr)
		}
	}
	for _, in := range []string{"", "\n", "4\n", "yes\n", "unspecified\n"} {
		if r := term(in); r.code != 2 {
			t.Fatalf("prompt %q accepted: %d %s", in, r.code, r.stdout)
		}
	}
	if r := term("1\n"); r.code != 0 || !strings.Contains(r.stdout, `"dry_run":true`) || !strings.Contains(r.stdout, a2) {
		t.Fatalf("prompt 1 (hard, dry run lists tips): %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a dry run or refused invocation wrote something")
	}
	// dry run of a soft revocation: the would-be line, nothing written
	r := p.revoke("--reason", "superseded", "--dry-run")
	if o := outObj(t, r); r.code != 0 || o.Members["committed"] != canon.Bool(false) || statementsOf(o)[0].Members["prev"] != canon.String(a2) {
		t.Fatalf("soft dry run: %d %s", r.code, r.stdout)
	}
	// --merge naming a line not held, or not below the new seq
	if r := p.revoke("--reason", "key_compromise", "--last-good", a1, "--merge", strings.Repeat("cd", 32)); r.code != 3 {
		t.Fatalf("merge not held: %d %s", r.code, r.stdout)
	}
	b := p.describe(t, "B", a1)
	b2 := p.describe(t, "B2", b) // seq 2, the same as the new line after a1 would be
	before = snapshot(t, p.root)
	if r := p.revoke("--reason", "key_compromise", "--prev", a1, "--last-good", a1, "--merge", b2); r.code != 1 || !strings.Contains(r.stdout, keylog.TipAboveNext) {
		t.Fatalf("merge above next: %d %s", r.code, r.stdout)
	}
	// a forked log: a hard reason with --last-good but no --prev is exit 3 (the tool does not pick)
	if r := p.revoke("--reason", "key_compromise", "--last-good", a1); r.code != 3 || !strings.Contains(r.stdout, "log-fork") {
		t.Fatalf("hard over a fork without --prev: %d %s", r.code, r.stdout)
	}
	// a hard dry run on the fork without --prev lists both tips as candidates
	r = p.revoke("--reason", "key_compromise", "--dry-run")
	if r.code != 0 || !strings.Contains(r.stdout, a2) || !strings.Contains(r.stdout, b2) || !strings.Contains(r.stdout, "a candidate") {
		t.Fatalf("hard dry run over a fork: %d %s", r.code, r.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("wrote something")
	}
	// a key with no line here: the revocation is its first line
	q := newPubWorld(t)
	if r := q.revoke("--reason", "cessation_of_operation"); r.code != 0 || statementsOf(outObj(t, r))[0].Members["seq"] != canon.Int(0) {
		t.Fatalf("first line: %d %s", r.code, r.stdout)
	}
}
