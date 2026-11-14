package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// TestOnboardingRecoveryLabel (Gate W3): key new and init print, on both surfaces, that a bare key is
// unrecoverable and point at identities. The text is pinned (golden), so a change is a reviewed change.
func TestOnboardingRecoveryLabel(t *testing.T) {
	const golden = "a bare key is unrecoverable: if this file is lost, nothing can sign as it again, and if it is stolen, the thief signs as you until you revoke it; " +
		"what it signed stays attributed to this key alone. For authority that survives losing a working key, create an identity " +
		"(commons identity new with a separate root key kept offline) and act for it with publish --as; a cut grant leaves the identity's earlier acts counting"
	if bareKeyRecovery != golden {
		t.Fatalf("the onboarding label changed:\n%s", bareKeyRecovery)
	}
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"key new": {"key", "new", "--out", filepath.Join(dir, "k.key"), "--alg", wire.AlgEd25519},
		"init":    {"init", filepath.Join(dir, "store")},
	} {
		j := runIn(dir, nil, append(args, "--json")...)
		if j.code != ExitOK || jsonOf(t, j).Members["recovery"] != canon.String(golden) {
			t.Fatalf("%s --json: %d %s", name, j.code, j.stdout)
		}
		if name == "key new" {
			args[3] = filepath.Join(dir, "k2.key")
		}
		h := runIn(dir, nil, args...)
		if h.code != ExitOK || !strings.Contains(squash(h.stdout), "a bare key is unrecoverable") || !strings.Contains(h.stdout, "commons identity new") {
			t.Fatalf("%s human: %d %s", name, h.code, h.stdout)
		}
	}
}
