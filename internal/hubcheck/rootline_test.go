package hubcheck

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/gate"
)

// TestRootOrdinaryLineLabel: issue #271. `hub check` labels an added statement signed by the root of an identity
// the evaluated set holds, of a kind outside the closed root vocabulary, naming the identity and the line. A label
// only (I8): the statement is admitted and the exit stays 0. Root lines inside the vocabulary, other keys' lines,
// and a root whose inception the evaluated set does not hold carry no label (the last is the negative half: the
// label rests on the held inception, so removing it removes the label).
func TestRootOrdinaryLineLabel(t *testing.T) {
	wantLabel := func(t *testing.T, res *Result, path, ident, id string) {
		t.Helper()
		r := verdict(t, res, path)
		if r.Verdict != gate.Admitted || !r.HasLabel(gate.LabelRootOrdinaryLine) {
			t.Fatalf("%s: %s, labels %v\n%s", path, r.Verdict, r.Labels, res.Render())
		}
		for _, l := range r.Labels {
			if l.Token == gate.LabelRootOrdinaryLine && (!strings.Contains(l.Detail, ident) || !strings.Contains(l.Detail, id) ||
				!strings.Contains(l.Detail, "this line stops the identity's delegates' acts from counting")) {
				t.Fatalf("%s: the label does not name the identity and the line: %q", path, l.Detail)
			}
		}
		if res.Exit() != 0 {
			t.Fatalf("the label changed the exit to %d\n%s", res.Exit(), res.Render())
		}
		if !strings.Contains(res.Render(), gate.LabelRootOrdinaryLine) {
			t.Fatalf("the human report lacks the label\n%s", res.Render())
		}
	}
	noLabel := func(t *testing.T, res *Result) {
		t.Helper()
		for _, r := range res.Results {
			if r.HasLabel(gate.LabelRootOrdinaryLine) {
				t.Fatalf("%s is labelled: %v", r.Path, r.Labels)
			}
		}
	}

	t.Run("the root signs an authored after its identity is held", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		w.workerGenesis(h, "W")
		w.grant(h, "G", "W")
		w.act(h, "A", "W", "G")
		h.commit("base: identity, grant and an act")
		h.branch("root-line")
		p, l := w.put("R.y", "R", "rc/1", "authored", w.authored("the root's own bytes"))
		h.write(p, l)
		h.commit("the root signs an ordinary statement")
		wantLabel(t, h.check("main"), p, w.ids["I"], w.ids["R.y"])
		wantLabel(t, h.check(""), p, w.ids["I"], w.ids["R.y"])
	})

	t.Run("a change brings the inception and the root's ordinary line", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		h.commit("empty base")
		h.branch("all")
		w.inception(h)
		p, l := w.put("R.h", "R", "rc/1", "holds", obj("content", contentOf([]byte("held"))))
		h.write(p, l)
		h.commit("inception and a holds by the root")
		wantLabel(t, h.check("main"), p, w.ids["I"], w.ids["R.h"])
	})

	t.Run("vocabulary lines, other keys and unheld inceptions carry no label", func(t *testing.T) {
		w, h := newIDWorld(), newHub(t, "")
		w.inception(h)
		w.workerGenesis(h, "W")
		h.commit("base")
		h.branch("fine")
		w.grant(h, "G", "W")
		p, l := w.put("R.d", "R", "rc/1", "describes", obj("about", obj("statement", w.ids["I"]), "note", "the root's note"))
		h.write(p, l)
		w.cut(h, "G")
		w.workerGenesis(h, "V")
		h.commit("a grant, a describes and a cut by the root; another key's authored")
		res := h.check("main")
		noLabel(t, res)
		if res.Exit() != 0 {
			t.Fatalf("exit %d\n%s", res.Exit(), res.Render())
		}

		// a root key whose inception is nowhere in the evaluated set: nothing to label
		w2, h2 := newIDWorld(), newHub(t, "")
		w2.put("I", "R", "rc/2", "identity_inception", obj("profile", "fixed-root-v1")) // signed, never written
		h2.commit("empty base")
		h2.branch("orphan")
		p2, l2 := w2.put("R.y", "R", "rc/1", "authored", w2.authored("the root's bytes elsewhere"))
		h2.write(p2, l2)
		h2.commit("the root's line without its inception")
		noLabel(t, h2.check("main"))
	})
}
