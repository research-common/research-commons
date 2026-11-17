//go:build twohub

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// drill runs scripts/two-hub-drill.sh with the freshly built binary and returns its exit code and output.
func drill(t *testing.T, bin string, env ...string) (int, string) {
	t.Helper()
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "two-hub-drill.sh"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", script)
	cmd.Env = append(os.Environ(), append([]string{"COMMONS=" + bin, "TMPDIR=" + t.TempDir()}, env...)...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return 0, string(out)
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), string(out)
	}
	t.Fatalf("running the drill: %v", err)
	return -1, ""
}

// TestTwoHubDrill: the scripted two-hub drill (RELEASING criterion 3). Two bare git repos as hubs and two
// stores with distinct keys exchange a construction, an observation and a resource edition through push and
// pull; both answer show / explain / verify for the same ids with byte-identical --json; a tampered blob in
// one hub is refused on pull. The anchor step is skipped here (it needs a calendar).
func TestTwoHubDrill(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed: the two-hub drill needs it")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh is not installed: the two-hub drill is a POSIX shell script")
	}
	bin := build(t)
	code, out := drill(t, bin)
	if code != 0 || !strings.Contains(out, "two-hub drill: PASS") {
		t.Fatalf("drill exit %d:\n%s", code, out)
	}
	if strings.Contains(out, "DISAGREE") {
		t.Fatalf("drill reported a disagreement yet passed:\n%s", out)
	}
}

// TestTwoHubDrillMutation: one state altered in B alone makes the drill exit non-zero and name the
// comparison that disagreed (a drill that cannot fail proves nothing).
func TestTwoHubDrillMutation(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed: the two-hub drill needs it")
	}
	bin := build(t)
	code, out := drill(t, bin, "TWOHUB_MUTATE=1")
	if code == 0 || !strings.Contains(out, "DISAGREE/FAIL: show sha256:") {
		t.Fatalf("mutated drill: exit %d, want non-zero naming a show disagreement:\n%s", code, out)
	}
}
