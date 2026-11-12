package hubcheck

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
)

// Source profiles pinned by a hub policy (`series.source_profiles`, claims-model note §5.3.1a, §8 "a boundary as
// captured"; C-core-104b – C-core-104e).

var settlementProfile = canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "https://api.example/settlement",
	"dialect", resolve.DialectOrderedLabel, "labels", []string{"SF", "R1", "R2", "RF", "DF"}))

func profilePolicy(digests ...string) string {
	var es []string
	for _, d := range digests {
		es = append(es, `{"digest":"`+d+`"}`)
	}
	return `{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true,"source_profiles":[` + strings.Join(es, ",") + `]}}`
}

// profileSeries writes a series of five monthly source-class segments citing src, whose asserted states put
// Jan–Mar at or after RF and Apr–May before it (members final to 2025-04-01 as captured); states overrides
// a month's state. It returns the genesis id and the segment members.
func profileSeries(h *hub, s *signer, src string, states map[int]string) (string, canon.Array) {
	gp, gline, g := s.sign("C", "genesis", obj("type", "series", "name", "settlements", "controllers", []string{s.key("C").Signer()}, "rule", obj("any_one", true)))
	h.write(gp, gline)
	segs := canon.Array{}
	for i, st := range []string{"DF", "RF", "DF", "R2", "SF"} {
		if o, ok := states[i]; ok {
			st = o
		}
		m := fmt.Sprintf("2025-%02d", i+1)
		ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", m), "response_digest", dig([]byte(m)),
			"window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z"))
		p, line, id := s.sign("O", "observed", obj("content", contentOf([]byte(m)), "class", "source", "referent", canon.Value(ref),
			"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted")),
			"finality", obj("rule", "run >= RF", "rule_source", src, "state_at_capture", obj("run", st))))
		h.write(p, line)
		segs = append(segs, obj("statement", id, "role", "segment"))
	}
	return g, segs
}

// freeze signs, on a new branch from main, a series edition declaring frozen_before date, and commits it.
func freeze(h *hub, s *signer, branch, g string, segs canon.Array, date string) string {
	h.git("checkout", "-q", "main")
	h.branch(branch)
	s2 := *s
	s2.head, s2.seq = maps(s.head), maps64(s.seq)
	ep, eline, _ := s2.sign("C", "edition", editionBody(g, []string{g}, "members", segs, "frozen_before", obj("date", date)))
	h.write(ep, eline)
	h.commit(branch)
	return ep
}

// TestPinnedProfileSplitVerdict: C-core-104b and C-core-104c. The base pins the settlement profile and sets the
// knob. A declaration later than the members' asserted boundary is refused (exit 1) on the hub's own evidence; one
// at or before it is could not check (as captured), exit 3, never admitted on the members' word. Control: without
// the pin the same editions are could-not-check for the shipped reason (no re-check ships), so the verdicts come
// from the profile; and a reader's own re-check still decides (it overrides the as-captured reader).
func TestPinnedProfileSplitVerdict(t *testing.T) {
	conformance.Covers(t, "C-core-104b")
	conformance.Covers(t, "C-core-104c")
	pd := dig(settlementProfile)
	h := newHub(t, profilePolicy(pd))
	h.write(gate.BlobPath(pd), settlementProfile)
	s := newSigner()
	g, segs := profileSeries(h, s, pd, nil)
	h.commit("series, segments and the pinned profile")

	late := freeze(h, s, "late", g, segs, "2025-06-01")
	res, err := Check(h.dir, Config{Base: "main"})
	if err != nil {
		t.Fatal(err)
	}
	refusedAs(t, res, late, refusal.Policy, gate.HubRules+": series.refuse_premature_freeze")
	r := verdict(t, res, late)
	if res.Exit() != 1 || r.Series == nil || !r.Series.AsCaptured || r.Series.Comparison != "flagged" ||
		!strings.Contains(r.Refusal.Detail, "members final to 2025-04-01 as captured, not re-checked (2 segments provisional)") ||
		!strings.Contains(r.Refusal.Detail, gate.AsCapturedRefusal) || !strings.Contains(r.Refusal.Detail, "scope series edition") ||
		strings.Contains(r.Refusal.Detail, gate.ReaderRecheck) {
		t.Fatalf("late: exit %d %v\n%s", res.Exit(), r.Refusal, res.Render())
	}

	for _, date := range []string{"2025-04-01", "2025-03-01"} {
		ep := freeze(h, s, "at-"+date, g, segs, date)
		res, err := Check(h.dir, Config{Base: "main"})
		if err != nil {
			t.Fatal(err)
		}
		r := verdict(t, res, ep)
		if r.Verdict != gate.Undecided || res.Exit() != 3 || len(r.Labels) != 1 || r.Labels[0].Token != gate.LabelSeriesUnknown ||
			!strings.HasPrefix(r.Labels[0].Detail, "could not check (as captured): frozen_before "+date+" (declared) · members final to 2025-04-01 as captured, not re-checked") ||
			r.Next != gate.AsCapturedNext || strings.Contains(res.Render(), "ships no finality re-check") {
			t.Fatalf("%s: %s exit %d %v next %q\n%s", date, r.Verdict, res.Exit(), r.Labels, r.Next, res.Render())
		}
		// a reader's own re-check (not as captured) still decides: it comes after the pinned profiles
		f := fakeSegments{}
		for i, m := range segs {
			fin := "final"
			if i >= 3 {
				fin = "provisional"
			}
			id := string(m.(*canon.Object).Members["statement"].(canon.String))
			f[id] = resolve.SegmentState{From: day(fmt.Sprintf("2025-%02d-01", i+1)), Rule: true, Final: fin}
		}
		if cr := verdict(t, h.check("main", resolve.WithSegments(f)), ep); cr.Verdict != gate.Admitted {
			t.Fatalf("%s re-check control: %s %v", date, cr.Verdict, cr.Labels)
		}
	}

	// control: the same tree with the pin removed at the base: the shipped no-re-check verdict for both
	h.git("checkout", "-q", "main")
	h.write(PolicyFile, []byte(`{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`))
	h.commit("unpin")
	for _, name := range []string{"late", "at-2025-04-01"} {
		h.git("checkout", "-q", name)
		h.git("rebase", "-q", "main")
		res, err := Check(h.dir, Config{Base: "main"})
		if err != nil {
			t.Fatal(err)
		}
		ep := late
		if name != "late" {
			ep = res.Report.Results[len(res.Report.Results)-1].Path
		}
		if r := verdict(t, res, ep); r.Verdict != gate.Undecided || !strings.Contains(res.Render(), "ships no finality re-check") {
			t.Fatalf("unpinned %s: %s\n%s", name, r.Verdict, res.Render())
		}
	}
}

// TestProfileUnplaceableSegment: C-core-104e. One segment's asserted state is a label the pinned profile does not
// list: the boundary is unchecked, the explanation says not comparable, and the edition is could not check
// (exit 3), never refused and never admitted, whichever way the declaration falls.
func TestProfileUnplaceableSegment(t *testing.T) {
	conformance.Covers(t, "C-core-104e")
	pd := dig(settlementProfile)
	h := newHub(t, profilePolicy(pd))
	h.write(gate.BlobPath(pd), settlementProfile)
	s := newSigner()
	g, segs := profileSeries(h, s, pd, map[int]string{1: "II"})
	h.commit("series")
	for _, date := range []string{"2025-09-01", "2025-01-01"} {
		ep := freeze(h, s, "e-"+date, g, segs, date)
		res, err := Check(h.dir, Config{Base: "main"})
		if err != nil {
			t.Fatal(err)
		}
		r := verdict(t, res, ep)
		if r.Verdict != gate.Undecided || res.Exit() != 3 || r.Series == nil || r.Series.ComputedState != "unchecked" ||
			!strings.Contains(r.Series.Render(), `state "II" is not in source profile`) || !strings.Contains(r.Series.Render(), "not comparable") {
			t.Fatalf("%s: %s exit %d\n%s", date, r.Verdict, res.Exit(), res.Render())
		}
	}
}

// TestProfilePinnedAtBase: C-core-104d. (a) A change that adds the profile blob and pins it beside a series edition
// does not judge that edition with it: the base policy applies (no pin there: the shipped could-not-check). Then,
// once the profile and its pin are on the base, the same edition is decided by it (control: the mutation is what
// moved the verdict). (b)–(d) A pin the base cannot honour stops the check (exit 2), naming the entry.
func TestProfilePinnedAtBase(t *testing.T) {
	conformance.Covers(t, "C-core-104d")
	pd := dig(settlementProfile)
	h := newHub(t, `{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`)
	s := newSigner()
	g, segs := profileSeries(h, s, pd, nil)
	h.commit("series")
	h.branch("same-change")
	h.write(gate.BlobPath(pd), settlementProfile)
	h.write(PolicyFile, []byte(profilePolicy(pd)))
	s2 := *s
	s2.head, s2.seq = maps(s.head), maps64(s.seq)
	ep, eline, _ := s2.sign("C", "edition", editionBody(g, []string{g}, "members", segs, "frozen_before", obj("date", "2025-06-01")))
	h.write(ep, eline)
	h.commit("profile, pin and the edition it would judge")
	res, err := Check(h.dir, Config{Base: "main"})
	if err != nil {
		t.Fatal(err)
	}
	// the edition is judged under the base policy (no pin: the shipped could-not-check), and the policy change,
	// sent with data, is refused and not applied (the gate's existing control-plane rule)
	if r := verdict(t, res, ep); r.Verdict != gate.Undecided || r.Series == nil || r.Series.AsCaptured || !strings.Contains(res.Render(), "ships no finality re-check") {
		t.Fatalf("same change: %s exit %d\n%s", r.Verdict, res.Exit(), res.Render())
	}
	if pr := verdict(t, res, PolicyFile); pr.Verdict != gate.Refused || !strings.Contains(pr.Refusal.Detail, "not applied") {
		t.Fatalf("policy file: %s %v", pr.Verdict, pr.Refusal)
	}
	// the same with the policy change alone in its own change, then the edition: still judged at the base, which
	// has the pin only once the policy change is merged
	h.git("checkout", "-q", "main")
	h.branch("pin-only")
	h.write(gate.BlobPath(pd), settlementProfile)
	h.write(PolicyFile, []byte(profilePolicy(pd)))
	h.commit("profile and pin")
	h.branch("edition-on-pin-branch")
	h.write(ep, eline)
	h.commit("edition")
	if r := verdict(t, h.check("main"), ep); r.Verdict != gate.Undecided || r.Series.AsCaptured {
		t.Fatalf("edition checked against main (no pin): %s", r.Verdict)
	}
	// control: profile and pin land on the base first; the edition is then judged by them
	h.git("checkout", "-q", "main")
	h.write(gate.BlobPath(pd), settlementProfile)
	h.write(PolicyFile, []byte(profilePolicy(pd)))
	h.commit("pin the profile")
	late := freeze(h, s, "after-pin", g, segs, "2025-06-01")
	refusedAs(t, h.check("main"), late, refusal.Policy, gate.HubRules+": series.refuse_premature_freeze")

	// (b)–(d): the check does not start, naming the entry
	notProfile := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "s", "dialect", resolve.DialectOrderedLabel, "labels", []string{"a", "a"}))
	undefined := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "s", "dialect", resolve.DialectOrderedLabel, "labels", []string{"a"}, "tolerance", 1))
	notCanonical := []byte(`{"source":"s","profile":"rc-source-profile/1","dialect":"ordered-label","labels":["a"]}`)
	var many []string
	for i := range gate.MaxSourceProfiles + 1 {
		many = append(many, dig([]byte{byte(i)}))
	}
	held := dig([]byte("unheld"))
	cases := []struct {
		name   string
		policy string
		blobs  [][]byte
		why    string
	}{
		{"not held", profilePolicy(held), nil, "series.source_profiles[0] " + held + " is not held at the policy revision"},
		{"repeated label", profilePolicy(dig(notProfile)), [][]byte{notProfile}, `series.source_profiles[0] ` + dig(notProfile) + ` is not a rc-source-profile/1 profile: labels[1] "a" repeats`},
		{"undefined member", profilePolicy(dig(undefined)), [][]byte{undefined}, `undefined member "tolerance"`},
		{"not canonical", profilePolicy(dig(notCanonical)), [][]byte{notCanonical}, "not in canonical form"},
		{"65 entries", profilePolicy(many...), nil, "series.source_profiles has 65 entries, more than 64"},
		{"not a digest", profilePolicy("sha256:ABC"), nil, "series.source_profiles[0].digest is not a sha256:<64 hex> digest"},
		{"repeat", profilePolicy(pd, pd), [][]byte{settlementProfile}, "series.source_profiles[1] " + pd + " repeats an entry"},
		{"extra member", `{"policy":"rc-hub-policy/1","series":{"source_profiles":[{"digest":"` + pd + `","note":"x"}]}}`, nil, `series.source_profiles[0] carries undefined field "note"`},
		{"not an object", `{"policy":"rc-hub-policy/1","series":{"source_profiles":["` + pd + `"]}}`, nil, "series.source_profiles[0] is not an object"},
		{"not an array", `{"policy":"rc-hub-policy/1","series":{"source_profiles":{}}}`, nil, "series.source_profiles is not an array"},
	}
	for _, c := range cases {
		n := newHub(t, c.policy)
		for _, b := range c.blobs {
			n.write(gate.BlobPath(dig(b)), b)
		}
		n.commit("base")
		n.branch("x")
		n.commit("x")
		_, err := Check(n.dir, Config{Base: "main"})
		d := didNotStart(t, err)
		if !strings.Contains(d.Detail, c.why) || !strings.Contains(d.Scope, "policy file hub-policy.json") {
			t.Errorf("%s: %q (scope %q), want %q", c.name, d.Detail, d.Scope, c.why)
		}
	}
	// control for the size bound: 64 held profiles start
	var ok []string
	n := newHub(t, "")
	for i := range gate.MaxSourceProfiles {
		b := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", fmt.Sprintf("s%d", i), "dialect", resolve.DialectIntegerDepth))
		n.write(gate.BlobPath(dig(b)), b)
		ok = append(ok, dig(b))
	}
	n.write(PolicyFile, []byte(profilePolicy(ok...)))
	n.commit("64")
	n.branch("y")
	n.commit("y")
	if _, err := Check(n.dir, Config{Base: "main"}); err != nil {
		t.Fatalf("64 entries: %v", err)
	}
}
