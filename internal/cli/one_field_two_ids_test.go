package cli

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/wire"
)

// replayWords are what a surface would print if it showed one statement as a repeat of another: the pull label
// for a line the receiver already holds, and the words a display would use for a duplicate.
var replayWords = []string{"already held", "replay", "duplicate", "same statement", "repeat"}

// TestOneFieldTwoStatementsNoReplay: C-core-02a through the commands.
//
// First pair: two valid statements from one key that differ in exactly one field (an authored's description, an
// unknown extension's value, a retracts' reason), signed from the same position of the key's log. Every pair
// has two ids; pulled one after the other, in either order, the second is admitted and not labelled `already
// held`; both lines are held and count; show, verify and explain of each print that line's own body and never
// the other's id as its original; no surface prints a replay word for either. Control: delivering the same line a
// second time is labelled `already held` and installs nothing, so the label the pair must not get is the one this
// reader does print for a real repeat.
//
// Second pair: one body signed twice with equivalent signature encodings is one statement with one id: every
// other encoding of an EIP-191 signature reads to the same id, a package carrying one is refused `not
// canonical`, and a reader that received only the canonical form once holds one line (the fuller delivery-order
// check is TestPullEquivalentEncodingsOneStatement).
func TestOneFieldTwoStatementsNoReplay(t *testing.T) {
	conformance.Covers(t, "C-core-02a")
	src := newWorld(t)
	src.blob("x", []byte("x"))
	target := src.authored("T", "K1", "x", "licence", "CC0-1.0") // seq 0: the pairs sit at seq 1, one field apart
	pairs := []struct {
		name string
		mk   func(v string, seq int64, prev string) forkLine
		a, b string
	}{
		{"authored description", func(v string, seq int64, prev string) forkLine {
			return signKind(src, "K1", "authored", obj("content", content("x"), "type", "dataset", "licence", "CC0-1.0", "description", v), seq, prev, nil)
		}, "first wording", "second wording"},
		{"unknown extension value", func(v string, seq int64, prev string) forkLine {
			return signKind(src, "K1", "authored", obj("content", content("x"), "type", "dataset", "licence", "CC0-1.0", "x_ttl", v), seq, prev, nil)
		}, "7", "8"},
		{"retracts reason", func(v string, seq int64, prev string) forkLine {
			return signKind(src, "K1", "retracts", obj("of", target, "reason", v), seq, prev, nil)
		}, "superseded", "mistaken"},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			la, lb := p.mk(p.a, 1, target), p.mk(p.b, 1, target)
			if la.id == lb.id {
				t.Fatalf("two bodies, one id")
			}
			for _, order := range [][]forkLine{{la, lb}, {lb, la}} {
				dst := newWorld(t)
				pullLines(t, dst, src.root, forkLine{id: target, line: mustRead(t, filepath.Join(src.root, stmtPath(src.signer("K1"), target))), path: stmtPath(src.signer("K1"), target)})
				for i, l := range order {
					pkg := t.TempDir()
					os.WriteFile(filepath.Join(pkg, "rc-store"), mustRead(t, filepath.Join(src.root, "rc-store")), 0o644)
					os.MkdirAll(filepath.Join(pkg, filepath.Dir(l.path)), 0o755)
					os.WriteFile(filepath.Join(pkg, l.path), l.line, 0o644)
					r := dst.run("pull", pkg, "--json")
					if r.code != 0 || strings.Contains(r.stdout, "already held") {
						t.Fatalf("delivery %d: exit %d, the line is labelled as held already:\n%s", i, r.code, r.stdout)
					}
				}
				stored := mustStatements(t, dst)
				if len(stored) != 3 || stored[la.id] == nil || stored[lb.id] == nil {
					t.Fatalf("%d lines held, want the target and both variants", len(stored))
				}
				for _, l := range []forkLine{la, lb} {
					other := lb
					if l.id == lb.id {
						other = la
					}
					for _, c := range []string{"show", "verify", "explain"} {
						for _, h := range []string{"", "--json"} {
							args := []string{c, l.id}
							if h != "" {
								args = append(args, h)
							}
							out := dst.run(args...)
							if out.code == ExitDidNotStart {
								t.Fatalf("%v: %s", args, out.stdout)
							}
							low := strings.ToLower(out.stdout)
							for _, w := range replayWords {
								if strings.Contains(low, w) {
									t.Fatalf("%v prints %q:\n%s", args, w, out.stdout)
								}
							}
							if c == "show" && h == "" {
								if !strings.Contains(out.stdout, "counted: counted") || !strings.Contains(out.stdout, l.id) {
									t.Fatalf("show %s:\n%s", l.id, out.stdout)
								}
								// the other variant is the same position's other branch: named at most as a fork tip, never as this line's origin
								if strings.Contains(out.stdout, "of "+other.id) || strings.Contains(out.stdout, "replays "+other.id) {
									t.Fatalf("show %s names %s as its original:\n%s", l.id, other.id, out.stdout)
								}
							}
						}
					}
				}
			}
			// the same two bodies as one log's successive lines (b follows a): two ids, both admitted, neither a replay
			lc := p.mk(p.b, 2, la.id)
			if lc.id == la.id || lc.id == lb.id {
				t.Fatal("a chained line shares an id")
			}
			tgt := forkLine{id: target, line: mustRead(t, filepath.Join(src.root, stmtPath(src.signer("K1"), target))), path: stmtPath(src.signer("K1"), target)}
			cd := newWorld(t)
			pullLines(t, cd, src.root, tgt, la, lc)
			if n := len(mustStatements(t, cd)); n != 3 {
				t.Fatalf("%d lines held after a chained pair, want 3", n)
			}
			for _, l := range []forkLine{la, lc} {
				for _, c := range []string{"show", "verify", "explain"} {
					out := cd.run(c, l.id)
					low := strings.ToLower(out.stdout)
					for _, w := range replayWords {
						if strings.Contains(low, w) {
							t.Fatalf("chained %s %s prints %q:\n%s", c, l.id, w, out.stdout)
						}
					}
					if out.code == ExitDidNotStart || (c == "show" && !strings.Contains(out.stdout, "counted: counted")) {
						t.Fatalf("chained %s %s: %d\n%s", c, l.id, out.code, out.stdout)
					}
				}
			}
			// control: the same line delivered twice IS labelled already held and installs nothing
			dst := newWorld(t)
			pullLines(t, dst, src.root, forkLine{id: target, line: mustRead(t, filepath.Join(src.root, stmtPath(src.signer("K1"), target))), path: stmtPath(src.signer("K1"), target)}, la)
			before := snapshot(t, dst.root)
			pkg := t.TempDir()
			os.WriteFile(filepath.Join(pkg, "rc-store"), mustRead(t, filepath.Join(src.root, "rc-store")), 0o644)
			os.MkdirAll(filepath.Join(pkg, filepath.Dir(la.path)), 0o755)
			os.WriteFile(filepath.Join(pkg, la.path), la.line, 0o644)
			if r := dst.run("pull", pkg, "--json"); r.code != 0 || !strings.Contains(r.stdout, "already held") {
				t.Fatalf("control: a repeated line is not labelled already held: %d %s", r.code, r.stdout)
			}
			if snapshot(t, dst.root) != before {
				t.Fatal("control: a repeated line changed the store")
			}
		})
	}

	// second pair: an EIP-191 key's statement and its equivalent encodings
	eip := newWorld(t)
	eip.blob("e", []byte("e"))
	id := eip.authored("E", "K2", "e", "licence", "CC0-1.0")
	if !strings.HasPrefix(eip.signer("K2"), "0x") {
		t.Fatal("K2 is not an EIP-191 key")
	}
	canonical := mustRead(t, filepath.Join(eip.root, stmtPath(eip.signer("K2"), id)))
	st, err := wire.Read(canonical)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := hex.DecodeString(strings.TrimPrefix(st.Sig, "0x"))
	eqs := sig.Equivalents(raw)
	if len(eqs) != 3 {
		t.Fatalf("%d equivalent encodings", len(eqs))
	}
	for _, e := range eqs {
		v, _ := canon.Parse(canonical)
		o := v.(*canon.Object)
		o.Members["sig"] = canon.String("0x" + hex.EncodeToString(e))
		line := canon.Encode(o)
		got, err := wire.Read(line)
		if err != nil || got.ID != id || string(line) == string(canonical) {
			t.Fatalf("equivalent encoding: %v", err)
		}
		pkg := t.TempDir()
		rel := stmtPath(eip.signer("K2"), id)
		os.WriteFile(filepath.Join(pkg, "rc-store"), mustRead(t, filepath.Join(eip.root, "rc-store")), 0o644)
		os.MkdirAll(filepath.Join(pkg, filepath.Dir(rel)), 0o755)
		os.WriteFile(filepath.Join(pkg, rel), line, 0o644)
		dst := newWorld(t)
		r := dst.run("pull", pkg, "--json")
		row := refusedRow(t, r)
		if r.code != 1 || row.Members["reason"] != canon.String("not canonical") || len(mustStatements(t, dst)) != 0 {
			t.Fatalf("a non-canonical encoding: exit %d %s", r.code, r.stdout)
		}
	}
	ref := newWorld(t)
	if r := ref.run("pull", eip.root, "--json"); r.code != 0 || len(mustStatements(t, ref)) != 1 {
		t.Fatalf("canonical delivery: %d %s", r.code, r.stdout)
	}
}
