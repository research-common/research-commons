package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	research "github.com/research-common/research-commons"
)

// build compiles the command with the given extra go build arguments and returns the binary path.
func build(t *testing.T, args ...string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "commons")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	cmd := exec.Command("go", append(append([]string{"build"}, args...), "-o", bin, ".")...)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func versionLine(t *testing.T, bin string) string {
	t.Helper()
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("--version: %v\n%s", err, out)
	}
	return string(out)
}

func TestUnstampedBuildPrintsVERSION(t *testing.T) {
	out := versionLine(t, build(t))
	if !strings.Contains(out, research.Embedded()) {
		t.Fatalf("unstamped --version %q lacks VERSION %q", out, research.Embedded())
	}
	if strings.Contains(out, "devel") {
		t.Fatalf("unstamped --version still says devel: %q", out)
	}
}

func TestLdflagsStampOverrides(t *testing.T) {
	out := versionLine(t, build(t, "-ldflags", "-X main.version=7.7.7-test.1 -X main.commit=abc1234"))
	if !strings.Contains(out, "7.7.7-test.1") || !strings.Contains(out, "abc1234") {
		t.Fatalf("stamp not reflected: %q", out)
	}
	if strings.Contains(out, research.Embedded()) && research.Embedded() != "7.7.7-test.1" {
		t.Fatalf("embedded VERSION leaked past the stamp: %q", out)
	}
}

// TestCalendarsWired: the binary wires the calendar client `anchor stamp` submits through. A calendar on a loopback
// address without --allow-private is refused by the client's dial guard at connect time (so nothing is dialled);
// a build without the wiring would answer "not available in this build" instead.
func TestCalendarsWired(t *testing.T) {
	bin := build(t)
	dir := t.TempDir()
	st, key, data := filepath.Join(dir, "s"), filepath.Join(dir, "k.key"), filepath.Join(dir, "d")
	os.WriteFile(data, []byte("bytes"), 0o644)
	for _, args := range [][]string{{"init", st}, {"key", "new", "--out", key}, {"publish", "--store", st, "--key", key, "--kind", "authored", "--content", data}} {
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	cmd := exec.Command(bin, "anchor", "stamp", "--store", st, "--key", key, "--calendar", "https://127.0.0.1:9", "--json")
	cmd.Env = append(os.Environ(), "COMMONS_CALENDARS=")
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 3 || !strings.Contains(string(out), "refusing to connect to 127.0.0.1") {
		t.Fatalf("anchor stamp: %v\n%s", err, out)
	}
}
