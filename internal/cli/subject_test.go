package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// TestClaimantSubjects: D-1110-1 on the JSON surface. Every claimant carries its typed claim subjects
// (`{"key": K}` for every claim a production reader holds) beside the keys that signed the unit's statements; the
// human surface is the key line it always was (only the JSON shape grows, CLI-OUTPUTS "Stability").
func TestClaimantSubjects(t *testing.T) {
	w := fixture(t)
	for blob, want := range map[string][]string{"sole": {"K1"}, "contested": {"K1", "K2"}, "t0": {"K1", "K2"}} {
		o := jsonOf(t, w.run("show", dig(blob), "--json"))
		cl := o.Members["claimants"].(canon.Array)
		var subjects, signers []string
		for _, c := range cl {
			co := c.(*canon.Object)
			for _, s := range co.Members["subjects"].(canon.Array) {
				so := s.(*canon.Object)
				if len(so.Keys) != 1 || so.Keys[0] != "key" {
					t.Fatalf("%s: subject %v is not a key subject", blob, canon.Encode(so))
				}
				subjects = append(subjects, string(so.Members["key"].(canon.String)))
			}
			for _, s := range co.Members["signers"].(canon.Array) {
				signers = append(signers, string(s.(canon.String)))
			}
		}
		if len(subjects) != len(want) || len(signers) != len(want) {
			t.Fatalf("%s: subjects %v signers %v", blob, subjects, signers)
		}
		for i, n := range want {
			if subjects[i] != w.signer(n) || signers[i] != w.signer(n) {
				t.Fatalf("%s: subjects %v signers %v, want %v", blob, subjects, signers, want)
			}
		}
		h := w.run("show", dig(blob))
		if strings.Contains(h.stdout, "subjects:") || strings.Contains(h.stdout, `{"key"`) {
			t.Fatalf("%s: the human surface grew a subject member:\n%s", blob, h.stdout)
		}
	}
}
