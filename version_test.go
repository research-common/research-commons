package research

import (
	"regexp"
	"strings"
	"testing"
)

// The official SemVer 2.0.0 regular expression.
var semver = regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)

func TestEmbeddedVersionIsSemVer(t *testing.T) {
	v := Embedded()
	if !semver.MatchString(v) {
		t.Fatalf("VERSION %q is not a SemVer 2.0.0 string", v)
	}
	if strings.ContainsAny(v, " \t\r\n") {
		t.Fatalf("VERSION %q carries whitespace after trimming", v)
	}
}

func TestVersionPrecedence(t *testing.T) {
	if got := Version(""); got != Embedded() {
		t.Fatalf("unstamped: got %q want %q", got, Embedded())
	}
	if got := Version("9.9.9-x.1"); got != "9.9.9-x.1" {
		t.Fatalf("stamped value must win: got %q", got)
	}
	if got := Version(" \n"); got != Embedded() {
		t.Fatalf("blank stamp must fall through: got %q", got)
	}
}

func TestEmbeddedTrimsWhitespace(t *testing.T) {
	old := embedded
	defer func() { embedded = old }()
	embedded = "  1.2.3-alpha.4 \r\n\n"
	if got := Embedded(); got != "1.2.3-alpha.4" {
		t.Fatalf("got %q", got)
	}
	embedded = "\n"
	if got := Version(""); got == "" || got == "\n" {
		t.Fatalf("empty VERSION must fall back, got %q", got)
	}
}
