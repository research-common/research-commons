package gate

import (
	"bytes"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/wire"
)

// LabelRootOrdinaryLine: hub check, an admitted statement signed by the root of an identity whose inception the
// evaluated set holds, of a kind outside the closed root vocabulary (fixed-root note, "Root vocabulary on the
// pinned I lineage is closed"). Every reader that holds it reads the identity's acts unknown
// (unsupported_root_event). A label only (I8): the hub admits, readers count; it is raised where the mistake can
// still be undone cheaply, before the line spreads.
const LabelRootOrdinaryLine = "identity root: ordinary line"

// rootLineLabels labels each admitted candidate that is an ordinary line by an identity's root, over the evaluated
// set. The vocabulary is identity.InRootVocabulary, the one list the reader's root walk and the writer share.
func rootLineLabels(results []Result, cands []int, evaluated map[string][]byte) {
	var roots map[string][]string // signer -> inceptions it signed, built on first need
	for _, i := range cands {
		r := &results[i]
		if r.Verdict != Admitted || r.st == nil || !r.st.Verified || r.st.Kind == "identity_inception" || identity.InRootVocabulary(r.st) {
			continue
		}
		if roots == nil {
			roots = inceptionsBySigner(evaluated)
		}
		ids := roots[r.st.Signer]
		if len(ids) == 0 {
			continue
		}
		r.label(LabelRootOrdinaryLine, "line "+r.st.ID+" ("+r.st.Kind+") is signed by the root of identity "+strings.Join(ids, ", identity ")+
			": this line stops the identity's delegates' acts from counting (outside the closed root vocabulary); while it has not left this change, dropping it restores the identity")
	}
}

// inceptionsBySigner maps each signer of a verified, valid identity inception in lines to its inceptions, sorted.
func inceptionsBySigner(lines map[string][]byte) map[string][]string {
	out := map[string][]string{}
	for _, l := range lines {
		if !bytes.Contains(l, []byte(`"identity_inception"`)) {
			continue
		}
		st, err := wire.ReadStored(l)
		if err != nil || !st.Verified || st.Status != wire.Valid || st.Kind != "identity_inception" || st.Seq != 0 {
			continue
		}
		out[st.Signer] = append(out[st.Signer], st.ID)
	}
	for _, ids := range out {
		slices.Sort(ids)
	}
	return out
}
