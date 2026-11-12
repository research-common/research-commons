package cli

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// A key-log fork is shown on every read surface (claims-model note §12, storage note §4.2): show, verify and
// explain of a line on it print the fork (log: FORK at seq N (tips …), or merged once cleared), list and status a
// marker per open fork, fsck every fork, open or cleared. Nothing about it moves an exit or a counted state.

// forkLine is one signed line of a test log: its id, bytes and store path.
type forkLine struct {
	id   string
	line []byte
	path string
}

// signLine signs a describes (or the given kind and body) by key n at seq, extending prev and merging merges,
// without the writer's checks: how a line signed on another machine reaches a reader.
func signLine(w *world, n string, seq int64, prev string, merges []string, note string) forkLine {
	return signKind(w, n, "describes", obj("about", obj("content", dig("a")), "note", note), seq, prev, merges)
}

func signKind(w *world, n, kind string, body *canon.Object, seq int64, prev string, merges []string) forkLine {
	line, id := wire.Sign(wire.Draft{Kind: kind, Seq: seq, Prev: prev, Merges: merges,
		TS: fmt.Sprintf("2026-10-16T03:%02d:00Z", seq), Body: body}, w.key(n))
	return forkLine{id: id, line: line, path: stmtPath(w.signer(n), id)}
}

// pullLines delivers each line to the reader in its own pull, in the order given, through a package holding only
// that line; every delivery is admitted (a detached line is admitted and labelled).
func pullLines(t *testing.T, dst *world, src string, ls ...forkLine) {
	t.Helper()
	for _, l := range ls {
		pkg := t.TempDir()
		os.WriteFile(filepath.Join(pkg, "rc-store"), mustRead(t, filepath.Join(src, "rc-store")), 0o644)
		os.MkdirAll(filepath.Join(pkg, filepath.Dir(l.path)), 0o755)
		os.WriteFile(filepath.Join(pkg, l.path), l.line, 0o644)
		if r := dst.run("pull", pkg, "--json"); r.code != 0 {
			t.Fatalf("pull %s: %d %s", keylog.Short(l.id), r.code, r.stdout)
		}
	}
}

// logForks is the log_forks member of a show/verify/explain --json output: one object per fork the line is on.
func logForks(t *testing.T, r result) []*canon.Object {
	t.Helper()
	a, _ := jsonOf(t, r).Members["log_forks"].(canon.Array)
	var out []*canon.Object
	for _, x := range a {
		out = append(out, x.(*canon.Object))
	}
	return out
}

func memberStr(o *canon.Object, k string) string {
	s, _ := o.Members[k].(canon.String)
	return string(s)
}

func memberStrs(o *canon.Object, k string) []string {
	var out []string
	a, _ := o.Members[k].(canon.Array)
	for _, x := range a {
		out = append(out, string(x.(canon.String)))
	}
	return out
}

// wantForkOn checks every statement surface for id: show, verify and explain carry one log_forks entry with the
// given state, seq and tips (open) or clearing line (merged), the human surfaces print the same line, the line
// still counts as it did, and verify's exit is what it is without the fork (want).
func wantForkOn(t *testing.T, w *world, id, state string, seq int64, tipsOrClear []string, wantExit int) {
	t.Helper()
	human := "FORK at seq " + fmt.Sprint(seq) + " (tips " + strings.Join(tipsOrClear, ", ") + ")"
	if state == "merged" {
		human = "merged at seq " + fmt.Sprint(seq) + " by " + tipsOrClear[0]
	}
	for _, c := range []string{"show", "verify", "explain"} {
		r := w.run(c, id, "--json")
		if c == "verify" && r.code != wantExit {
			t.Fatalf("verify %s: exit %d, want %d (a fork never moves it): %s", keylog.Short(id), r.code, wantExit, r.stdout)
		}
		fs := logForks(t, r)
		if len(fs) != 1 || memberStr(fs[0], "state") != state || fs[0].Members["seq"] != canon.Int(seq) {
			t.Fatalf("%s %s: log_forks %v\n%s", c, keylog.Short(id), fs, r.stdout)
		}
		if state == "FORK" && !slices.Equal(memberStrs(fs[0], "tips"), tipsOrClear) {
			t.Fatalf("%s %s: tips %v, want %v", c, keylog.Short(id), memberStrs(fs[0], "tips"), tipsOrClear)
		}
		if state == "merged" && memberStr(fs[0], "cleared_by") != tipsOrClear[0] {
			t.Fatalf("%s %s: cleared_by %s", c, keylog.Short(id), memberStr(fs[0], "cleared_by"))
		}
		if h := w.run(c, id); !strings.Contains(h.stdout, "log: "+human) {
			t.Fatalf("%s %s: the human surface does not print %q:\n%s", c, keylog.Short(id), human, h.stdout)
		}
	}
}

// wantNoForkOn: id is on no fork: no log_forks member on any statement surface, no log: line.
func wantNoForkOn(t *testing.T, w *world, id string) {
	t.Helper()
	for _, c := range []string{"show", "verify", "explain"} {
		if fs := logForks(t, w.run(c, id, "--json")); len(fs) != 0 {
			t.Fatalf("%s %s: on no fork, yet log_forks %v", c, keylog.Short(id), fs)
		}
		if h := w.run(c, id); strings.Contains(h.stdout, "\nlog: ") {
			t.Fatalf("%s %s: a log: line on a line on no fork:\n%s", c, keylog.Short(id), h.stdout)
		}
	}
}

// storeForks is the log_forks rows of list, status and fsck: each command's rows as "<state> <seq> <key>".
func storeForks(t *testing.T, w *world) (list, status, fsck []string) {
	t.Helper()
	rows := func(c string) []string {
		r := w.run(c, "--json")
		if r.code != 0 {
			t.Fatalf("%s: exit %d (a fork never moves it): %s", c, r.code, r.stdout)
		}
		var out []string
		a, _ := jsonOf(t, r).Members["log_forks"].(canon.Array)
		for _, x := range a {
			o := x.(*canon.Object)
			out = append(out, fmt.Sprintf("%s %v %s", memberStr(o, "state"), o.Members["seq"], memberStr(o, "key")))
		}
		h := w.run(c)
		for _, x := range a {
			if s := memberStr(x.(*canon.Object), "state"); !strings.Contains(h.stdout, "state: "+s) {
				t.Fatalf("%s: human surface lacks the %s row:\n%s", c, s, h.stdout)
			}
		}
		return out
	}
	return rows("list"), rows("status"), rows("fsck")
}

func counts(t *testing.T, w *world, id string) string {
	t.Helper()
	s, _ := jsonOf(t, w.run("show", id, "--json")).Members["counted"].(canon.String)
	return string(s)
}

// TestLogForkTwoProcesses: C-core-127 through the commands. Two OS processes publish on one key from the same
// sequence point (the writer lock disabled, as a filesystem without locks or a second machine sharing the key
// would leave it): both writers' lines are kept and count, every line on the fork shows it (FORK at the seq the
// branches were signed at, tips named), list, status and fsck carry a marker, and no exit moves. Mutation: the
// same store with one branch's lines removed shows no fork anywhere, so the display is what the fork produces.
func TestLogForkTwoProcesses(t *testing.T) {
	conformance.Covers(t, "C-core-127")
	p := newPubWorld(t)
	tips, lines, exits := twoWriters(t, p, 1, true)
	for _, e := range exits {
		if e != nil {
			t.Fatalf("writer failed: %v", e)
		}
	}
	if tips < 2 || lines != 4 {
		t.Fatalf("the writers did not fork (tips %d, lines %d): the test did not reach the boundary", tips, lines)
	}
	lv := deliverLogs(mustStatements(t, p.world)).Log(p.signer).View()
	if len(lv.Forks) != 1 || lv.Forks[0].Cleared() {
		t.Fatalf("%s", lv.Render())
	}
	f := lv.Forks[0]
	seq := forkSeq(lv, f)
	for _, ln := range lv.Lines {
		if c := counts(t, p.world, ln.St.ID); c != "counted" {
			t.Fatalf("%s: %s (lines on both branches count)", keylog.Short(ln.St.ID), c)
		}
		if slices.Contains(lv.Spans[0], ln.St.ID) {
			wantForkOn(t, p.world, ln.St.ID, "FORK", seq, f.Tips, ExitOK)
		} else {
			wantNoForkOn(t, p.world, ln.St.ID)
		}
	}
	key := p.signer
	l, s, fk := storeForks(t, p.world)
	want := []string{fmt.Sprintf("FORK %d %s", seq, key)}
	if !slices.Equal(l, want) || !slices.Equal(s, want) || !slices.Equal(fk, want) {
		t.Fatalf("list %v status %v fsck %v, want %v", l, s, fk, want)
	}

	// mutation: remove one branch (its lines' files); the fork, and every mark of it, goes
	cut := map[string]bool{}
	for _, ln := range lv.Lines {
		if ln.St.Seq >= seq && slices.Contains(lv.Spans[0], ln.St.ID) {
			// the branch through the first branch line: it and its successors
			if ln.St.ID == f.Branches[0] || cut[ln.St.Prev] {
				cut[ln.St.ID] = true
			}
		}
	}
	for id := range cut {
		os.Remove(filepath.Join(p.root, stmtPath(key, id)))
	}
	for _, ln := range lv.Lines {
		if !cut[ln.St.ID] {
			wantNoForkOn(t, p.world, ln.St.ID)
		}
	}
	if l, s, fk := storeForks(t, p.world); len(l)+len(s)+len(fk) != 0 {
		t.Fatalf("one branch left, yet list %v status %v fsck %v", l, s, fk)
	}
}

func mustStatements(t *testing.T, w *world) map[string][]byte {
	t.Helper()
	m, err := w.s.Statements()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// forkCase is a C-core-127a set: lines of key A from P (seq 1): L and S at seq 2, then the case's own lines.
type forkCase struct {
	src            *world
	base0, P, L, S forkLine
}

func newForkCase(t *testing.T) forkCase {
	src := newWorld(t)
	b0 := signLine(src, "A", 0, "", nil, "b0")
	P := signLine(src, "A", 1, b0.id, nil, "P")
	L := signLine(src, "A", 2, P.id, nil, "L")
	S := signLine(src, "A", 2, P.id, nil, "S")
	return forkCase{src, b0, P, L, S}
}

// permutedReaders delivers ls to fresh readers in seeded orders (one line per pull) and returns each reader; the
// display of every statement surface is the same in every order (the caller's checks then run on any of them).
func permutedReaders(t *testing.T, src *world, ls []forkLine, n int) []*world {
	t.Helper()
	r := rand.New(rand.NewPCG(127, 0xa))
	var out []*world
	var first map[string]string
	for i := 0; i < n; i++ {
		p := slices.Clone(ls)
		if i == 1 {
			slices.Reverse(p)
		} else if i > 1 {
			r.Shuffle(len(p), func(a, b int) { p[a], p[b] = p[b], p[a] })
		}
		dst := newWorld(t)
		pullLines(t, dst, src.root, p...)
		got := map[string]string{"list": dst.run("list", "--json").stdout}
		lf, _ := jsonOf(t, dst.run("fsck", "--json")).Members["log_forks"].(canon.Array)
		got["fsck"] = string(canon.Encode(lf))
		for _, l := range ls {
			for _, c := range []string{"show", "verify"} {
				x := dst.run(c, l.id, "--json")
				got[c+" "+l.id] = fmt.Sprint(x.code) + " " + x.stdout
			}
		}
		if first == nil {
			first = got
		} else {
			for k, v := range got {
				if first[k] != v {
					t.Fatalf("delivery order %d changed %s:\n%s\nvs\n%s", i, k, v, first[k])
				}
			}
		}
		out = append(out, dst)
	}
	return out
}

// TestLogForkClearingSurfaces: C-core-127a through the commands, every case in several delivery orders (one line
// per pull, seeded shuffles, reversed): (a) a line following S alone leaves FORK shown, naming L and S as
// branches; (b) a line on S naming L in merges clears it: every line on the fork shows merged with the clearing
// line, whose seq is S's plus 1, list and status drop the marker and fsck keeps a merged row; (c) a three-way fork
// with one tip merged stays FORK naming the unmerged tip; (d) each malformed merges line is refused by pull,
// intrinsic, malformed statement, scoped to that object, and the reader's log is otherwise unchanged. The fork
// and its clearing are keylog.View.Forks, i.e. dag.Forks: the function a resource's editions use (C-core-85).
func TestLogForkClearingSurfaces(t *testing.T) {
	conformance.Covers(t, "C-core-127a")
	const orders = 4

	t.Run("a follows one tip", func(t *testing.T) {
		c := newForkCase(t)
		N := signLine(c.src, "A", 3, c.S.id, nil, "N")
		for _, w := range permutedReaders(t, c.src, []forkLine{c.base0, c.P, c.L, c.S, N}, orders) {
			tips := sortedIDs(c.L.id, N.id)
			for _, id := range []string{c.L.id, c.S.id, N.id} {
				wantForkOn(t, w, id, "FORK", 2, tips, ExitOK)
			}
			fs := logForks(t, w.run("show", N.id, "--json"))
			if !slices.Equal(memberStrs(fs[0], "branches"), sortedIDs(c.L.id, c.S.id)) || memberStr(fs[0], "at") != c.P.id {
				t.Fatalf("FORK does not name L and S as its branches at P: %v", fs)
			}
			wantNoForkOn(t, w, c.P.id)
			l, s, f := storeForks(t, w)
			if len(l) != 1 || len(s) != 1 || len(f) != 1 || !strings.HasPrefix(l[0], "FORK 2 ") {
				t.Fatalf("list %v status %v fsck %v", l, s, f)
			}
		}
	})

	t.Run("b names the other tip", func(t *testing.T) {
		c := newForkCase(t)
		M := signLine(c.src, "A", 3, c.S.id, []string{c.L.id}, "M")
		Z := signLine(c.src, "A", 4, M.id, nil, "Z")
		for _, w := range permutedReaders(t, c.src, []forkLine{c.base0, c.P, c.L, c.S, M, Z}, orders) {
			for _, id := range []string{c.L.id, c.S.id, M.id} {
				wantForkOn(t, w, id, "merged", 2, []string{M.id}, ExitOK)
				if counts(t, w, id) != "counted" {
					t.Fatalf("%s does not count after the merge", keylog.Short(id))
				}
			}
			if seq := jsonOf(t, w.run("show", M.id, "--json")).Members["seq"]; seq != canon.Int(3) {
				t.Fatalf("the clearing line's seq is %v, not S's plus 1", seq)
			}
			wantNoForkOn(t, w, Z.id) // past the clearing line
			wantNoForkOn(t, w, c.P.id)
			l, s, f := storeForks(t, w)
			if len(l)+len(s) != 0 || len(f) != 1 || !strings.HasPrefix(f[0], "merged 2 ") {
				t.Fatalf("a merged fork: list %v status %v (want none), fsck %v (want one merged row)", l, s, f)
			}
		}
	})

	t.Run("c three-way, one merged", func(t *testing.T) {
		c := newForkCase(t)
		T := signLine(c.src, "A", 2, c.P.id, nil, "T")
		M := signLine(c.src, "A", 3, c.S.id, []string{c.L.id}, "M")
		for _, w := range permutedReaders(t, c.src, []forkLine{c.base0, c.P, c.L, c.S, T, M}, orders) {
			fs := logForks(t, w.run("show", M.id, "--json"))
			if len(fs) != 1 || memberStr(fs[0], "state") != "FORK" || !slices.Contains(memberStrs(fs[0], "tips"), T.id) {
				t.Fatalf("a three-way fork with one tip merged: %v", fs)
			}
			wantForkOn(t, w, T.id, "FORK", 2, sortedIDs(M.id, T.id), ExitOK)
		}
	})

	t.Run("d malformed merges", func(t *testing.T) {
		c := newForkCase(t)
		B0 := signLine(c.src, "B", 0, "", nil, "B0")
		hiS := signLine(c.src, "A", 3, c.S.id, nil, "hiS")
		held := []forkLine{c.base0, c.P, c.L, c.S, B0, hiS}
		for _, bad := range []struct {
			name, detail string
			l            forkLine
		}{
			{"own predecessor", "contains prev", signLine(c.src, "A", 3, c.S.id, []string{c.S.id}, "x")},
			{"duplicate", "sorted and duplicate-free", signLine(c.src, "A", 3, c.S.id, []string{c.L.id, c.L.id}, "x")},
			{"unsorted", "sorted and duplicate-free", signLine(c.src, "A", 3, c.S.id, []string{"ff" + c.L.id[2:], "00" + c.L.id[2:]}, "x")},
			{"another key's line", "merges names a line of another key", signLine(c.src, "A", 3, c.S.id, []string{B0.id}, "x")},
			{"seq not lower", "not lower than this line's seq 3", signLine(c.src, "A", 3, c.S.id, []string{hiS.id}, "x")},
		} {
			t.Run(bad.name, func(t *testing.T) {
				for i, w := range permutedReaders(t, c.src, held, 2) {
					before := map[string]string{}
					for _, l := range held {
						before[l.id] = w.run("show", l.id, "--json").stdout
					}
					beforeForks := fmt.Sprint(storeForks(t, w))
					pkg := t.TempDir()
					os.WriteFile(filepath.Join(pkg, "rc-store"), mustRead(t, filepath.Join(c.src.root, "rc-store")), 0o644)
					os.MkdirAll(filepath.Join(pkg, filepath.Dir(bad.l.path)), 0o755)
					os.WriteFile(filepath.Join(pkg, bad.l.path), bad.l.line, 0o644)
					r := w.run("pull", pkg, "--json")
					row := refusedRow(t, r)
					if r.code != 1 || memberStr(row, "class") != "intrinsic" || memberStr(row, "reason") != "malformed statement" ||
						!strings.Contains(memberStr(row, "detail"), bad.detail) || !strings.Contains(memberStr(row, "scope"), bad.l.path) {
						t.Fatalf("order %d: exit %d %s", i, r.code, canon.Encode(row))
					}
					if s := w.run("show", bad.l.id, "--json"); !strings.Contains(s.stdout, "no statement held") {
						t.Fatalf("the refused line was kept: %s", s.stdout)
					}
					for _, l := range held {
						if after := w.run("show", l.id, "--json").stdout; after != before[l.id] {
							t.Fatalf("refusing the line changed %s:\n%s\nvs\n%s", keylog.Short(l.id), after, before[l.id])
						}
					}
					if after := fmt.Sprint(storeForks(t, w)); after != beforeForks {
						t.Fatalf("refusing the line changed the log's forks: %s vs %s", after, beforeForks)
					}
				}
			})
		}
	})
}

func sortedIDs(ids ...string) []string { slices.Sort(ids); return ids }

// TestLogForkWaitsForMergedTip: C-core-127b through the commands. The reader holds S and the clearing line M
// (prev S, merges L) but not L: M is detached, its reason names L by id, it is attributed to A and counts toward
// nothing, and no FORK is shown anywhere, because the reader has not seen one. L arrives: every line on the fork
// shows it merged by M, M chains and counts, nothing else changes. Variant: L is a rotate_key. On arrival the old
// key is retired: the lines in the rotation's history (P and below, L) count; M (after L) and S (on a branch the
// rotation does not include) count toward nothing; nothing decided while M waited is rewritten (what P counted
// before, it counts after).
func TestLogForkWaitsForMergedTip(t *testing.T) {
	conformance.Covers(t, "C-core-127b")
	for _, variant := range []string{"describes", "rotate_key"} {
		t.Run(variant, func(t *testing.T) {
			c := newForkCase(t)
			L := c.L
			if variant == "rotate_key" {
				L = signKind(c.src, "A", "rotate_key", obj("successor", c.src.signer("Z")), 2, c.P.id, nil)
			}
			M := signLine(c.src, "A", 3, c.S.id, []string{L.id}, "M")
			w := newWorld(t)
			pullLines(t, w, c.src.root, M, c.S, c.base0, c.P)

			o := jsonOf(t, w.run("show", M.id, "--json"))
			reasons := fmt.Sprint(memberStrs(o, "reasons"))
			if memberStr(o, "line") != "detached" || memberStr(o, "counted") != "not counted" || memberStr(o, "signer") != c.src.signer("A") ||
				!strings.Contains(reasons, "detached: waiting for "+L.id) {
				t.Fatalf("before L: %s", canon.Encode(o))
			}
			if r := w.run("verify", M.id, "--json"); r.code != ExitCouldNot {
				t.Fatalf("a detached line is not evaluated: verify %d", r.code)
			}
			for _, id := range []string{c.base0.id, c.P.id, c.S.id, M.id} {
				wantNoForkOn(t, w, id)
			}
			if l, s, f := storeForks(t, w); len(l)+len(s)+len(f) != 0 {
				t.Fatalf("a FORK the reader has not seen: list %v status %v fsck %v", l, s, f)
			}
			pBefore := counts(t, w, c.P.id)

			pullLines(t, w, c.src.root, L)
			for _, id := range []string{L.id, c.S.id, M.id} {
				fs := logForks(t, w.run("show", id, "--json"))
				if len(fs) != 1 || memberStr(fs[0], "state") != "merged" || memberStr(fs[0], "cleared_by") != M.id {
					t.Fatalf("after L, %s: %v", keylog.Short(id), fs)
				}
			}
			if o := jsonOf(t, w.run("show", M.id, "--json")); memberStr(o, "line") != "chained" {
				t.Fatalf("M is not evaluated once L arrives: %s", canon.Encode(o))
			}
			if l, s, f := storeForks(t, w); len(l)+len(s) != 0 || len(f) != 1 || !strings.HasPrefix(f[0], "merged 2 ") {
				t.Fatalf("list %v status %v fsck %v", l, s, f)
			}
			want := map[string]string{c.base0.id: "counted", c.P.id: "counted", L.id: "counted", c.S.id: "counted", M.id: "counted"}
			if variant == "rotate_key" {
				want[M.id], want[c.S.id] = "not counted", "not counted"
			}
			for id, wc := range want {
				if got := counts(t, w, id); got != wc {
					t.Fatalf("%s: %s, want %s", keylog.Short(id), got, wc)
				}
			}
			if counts(t, w, c.P.id) != pBefore {
				t.Fatal("a line decided while M waited was rewritten")
			}
			if variant == "rotate_key" {
				o := jsonOf(t, w.run("show", M.id, "--json"))
				if !strings.Contains(fmt.Sprint(memberStrs(o, "reasons")), "after rotate_key") {
					t.Fatalf("M counts toward nothing because it is after the rotation: %s", canon.Encode(o))
				}
			}
		})
	}
}
