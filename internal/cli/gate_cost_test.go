package cli

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
)

// TestGateCommandCost is an opt-in end-to-end audit. It times real local commands, including
// directory reads, signature checking, rendering and (for pull and push) installation/transport.
// Fixture construction and restoring the receiver are outside the timer. Set RC_GATE_COST to the
// small size (the second size is eight times it), and optionally RC_GATE_COST_OUTPUT to save normalized
// human/JSON output for a byte comparison across implementations. No network service is used.
func TestGateCommandCost(t *testing.T) {
	text := os.Getenv("RC_GATE_COST")
	if text == "" {
		t.Skip("set RC_GATE_COST to run the command cost audit")
	}
	small, err := strconv.Atoi(text)
	if err != nil || small < 1 {
		t.Fatal("RC_GATE_COST must be a positive integer")
	}
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
	t.Setenv("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
	for _, shape := range []string{"one-key", "many-keys", "blobs", "cuts", "delivery"} {
		t.Run(shape, func(t *testing.T) {
			durations := map[string][]time.Duration{}
			for _, n := range []int{small, small * 8} {
				src := newWorld(t)
				held := newWorld(t)
				if shape == "delivery" {
					for i := 0; i < n; i++ {
						src.authored(fmt.Sprint(i), "KEY", fmt.Sprint(i))
					}
					copyData(t, src.root, held.root)
				}
				src.gitHub()
				base := gitIn(t, src.root, "rev-parse", "HEAD")
				count := n
				if shape == "delivery" {
					count = 32
				}
				if shape == "cuts" {
					src.worker("WORKX")
				}
				identity := ""
				if shape == "cuts" {
					identity, _ = src.identityOf("I", "ROOTX", canon.String("amend"))
				}
				for i := 0; i < count; i++ {
					name := fmt.Sprintf("item-%d", i)
					switch shape {
					case "one-key", "delivery":
						src.authored(name, "KEY", name)
					case "many-keys":
						src.authored(name, fmt.Sprintf("K%06d", i), name)
					case "blobs":
						src.blob(name, []byte(name))
					case "cuts":
						g := src.signRC2(name+"g", "MAKER", "genesis", obj("type", "collection", "name", name,
							"controllers", canon.Array{obj("identity", identity)}, "rule", obj("any_one", true)), [2]string{})
						grant := src.signRC2(name+"grant", "ROOTX", "identity_grant", obj("identity", identity,
							"delegate", obj("key", src.signer("WORKX"), "inception", src.ids["first:WORKX"]),
							"permissions", canon.Array{obj("kind", "edition", "targets", obj("resources", []string{g}))}), [2]string{})
						src.signRC2(name+"edition", "WORKX", "edition", editionBody(g, []string{g}, nil), [2]string{identity, grant})
						src.signRC2(name+"cut", "ROOTX", "identity_cut", obj("identity", identity, "grant", grant, "last_good", canon.Null{}, "reason", "key_compromise"), [2]string{})
					}
				}
				gitIn(t, src.root, "add", "-A")
				gitIn(t, src.root, "commit", "-q", "-m", "delivery")
				remote := filepath.Join(t.TempDir(), "hub.git")
				gitIn(t, src.root, "init", "-q", "--bare", remote)
				gitIn(t, src.root, "remote", "set-url", "origin", remote)
				gitIn(t, src.root, "push", "-q", "origin", base+":refs/heads/main")
				dst := newWorld(t)
				for _, command := range []string{"hub-check", "pull", "push"} {
					reset := func() {
						if command == "pull" {
							// Only this test's disposable receiver is removed.
							if err := os.RemoveAll(dst.root); err != nil {
								t.Fatal(err)
							}
							if err := os.MkdirAll(dst.root, 0755); err != nil {
								t.Fatal(err)
							}
							copyData(t, held.root, dst.root)
						}
						if command == "push" {
							gitIn(t, remote, "update-ref", "refs/heads/main", base)
						}
					}
					run := func(json bool) result {
						var args []string
						wd := src.root
						switch command {
						case "hub-check":
							args = []string{"hub", "check", "--base", base}
						case "pull":
							wd = dst.root
							args = []string{"pull", src.root, "--from-checkout"}
						case "push":
							args = []string{"push", "--base", base, "--branch", "main", "--anchor-policy", "none"}
						}
						if json {
							args = append(args, "--json")
						}
						return runIn(wd, nil, args...)
					}
					best := time.Duration(0)
					for sample := 0; sample < 3; sample++ {
						reset()
						runtime.GC()
						start := time.Now()
						r := run(true)
						elapsed := time.Since(start)
						if r.code != 0 {
							t.Fatalf("%s n=%d: exit %d\n%s\n%s", command, n, r.code, r.stdout, r.stderr)
						}
						if shape == "cuts" && (strings.Contains(r.stdout, "invalid statement") || strings.Count(r.stdout, "cut: editions not counted") != n) {
							t.Fatalf("%s n=%d: the fixture must exercise every valid cut's effects\n%s", command, n, r.stdout)
						}
						if best == 0 || elapsed < best {
							best = elapsed
						}
					}
					durations[command] = append(durations[command], best)
					for _, json := range []bool{false, true} {
						reset()
						r := run(json)
						if r.code != 0 {
							t.Fatalf("%s output: %d %s %s", command, r.code, r.stdout, r.stderr)
						}
						out := fmt.Sprintf("exit %d\n%s\nstderr:\n%s", r.code, r.stdout, r.stderr)
						for _, p := range []string{src.root, dst.root, remote} {
							out = strings.ReplaceAll(out, p, "<path>")
						}
						filename := fmt.Sprintf("%s-%d-%s-%t.txt", shape, n, command, json)
						t.Logf("OUTPUT %s %x", filename, sha256.Sum256([]byte(out)))
						if dir := os.Getenv("RC_GATE_COST_OUTPUT"); dir != "" {
							if err := os.MkdirAll(dir, 0755); err != nil {
								t.Fatal(err)
							}
							if err := os.WriteFile(filepath.Join(dir, filename), []byte(out), 0644); err != nil {
								t.Fatal(err)
							}
						}
					}
				}
			}
			for _, cmd := range []string{"hub-check", "pull", "push"} {
				ds := durations[cmd]
				t.Logf("COST %s %s S=%d %s %s ratio=%.2f", shape, cmd, small, ds[0], ds[1], float64(ds[1])/float64(ds[0]))
			}
		})
	}
}
