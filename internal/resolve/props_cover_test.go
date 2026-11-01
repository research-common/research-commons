package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance/fixture"
)

// TestPropertyGeneratorReachesViews guards the property tests against a generator that never reaches the
// states they claim to check: over the P-01 seeds, the snapshots must contain each of these answers at least
// once. If the generator or a view changes so one disappears, the property tests have gone vacuous for it.
func TestPropertyGeneratorReachesViews(t *testing.T) {
	want := map[string]string{
		"a fork":                       "FORK at",
		"a contested/pending edition":  "pending",
		"an authorized edition":        "authorized",
		"a detached edition":           "not counted: detached",
		"a counted corroboration":      "corroborated 1",
		"a counted contradiction":      "contradicted 1",
		"an unchecked corroboration":   "unchecked within statements you hold",
		"a T0 grade":                   "T0",
		"a T1 grade":                   "T1 under",
		"a priority outcome":           "priority",
		"a contested authorship":       "contested",
		"an endorsed member":           "member (endorsed)",
		"a listed, not endorsed":       "listed, not endorsed",
		"a forked key log":             "branches",
		"a held retraction":            "retracted by the observer",
		"a held refutation":            "held refutes",
		"a provisional referent":       "provisional",
		"a group token":                "derived by",
		"a series":                     "frozen_before",
		"a re-capture or re-read":      "re-read by",
		"a bound by a verified anchor": "bitcoin",
	}
	seen := map[string]bool{}
	for i := 0; i < propSeeds; i++ {
		f := fixture.Gen(propBaseSeed+uint64(i), fixture.Extended)
		snap := concretize(t, f).answers(t, nil, propOpts()...)
		_ = snap
		pw := concretize(t, f)
		snap = pw.answers(t, pw.deliver(nil), propOpts()...)
		for name, sub := range want {
			if strings.Contains(snap, sub) {
				seen[name] = true
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("no generated fixture reached %s (%q): the property tests are vacuous for it", name, want[name])
		}
	}
}
