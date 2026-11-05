package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
)

const completenessStation = "urn:example:station-7"

// stationReading signs a phenomenon observation of blob x by instrument at time at (timescale "" leaves it UTC).
func (w *world) stationReading(name, n, x, instrument, at, timescale string) string {
	kv := []any{"instrument", instrument, "location", "geo:39.74,-104.99", "at", at}
	if timescale != "" {
		kv = append(kv, "timescale", timescale)
	}
	return w.observedRef(name, n, x, "phenomenon", obj(kv...))
}

// completenessScope is the scope of a claim over completenessStation's January 2026 readings.
func completenessScope(kv ...any) canon.Value {
	o := obj("class", "phenomenon", "source", completenessStation, "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-02-01T00:00:00Z"))
	for i := 0; i < len(kv); i += 2 {
		o.Members[kv[i].(string)] = obj(kv...).Members[kv[i].(string)]
		if !slices.Contains(o.Keys, kv[i].(string)) {
			o.Keys = append(o.Keys, kv[i].(string))
		}
	}
	return o
}

// TestCompletenessClaim: C-core-60. A hub (here a collection under controller A) claims completeness for
// completenessStation's phenomenon readings in January 2026 and lists two of them; the reader also holds a third reading
// from the completenessStation in January, signed by another observer, that the hub does not list. The check reports
// `fail`, naming that reading. The hub's other content is unaffected: each listed member's membership, the
// edition's authorization, the resource's verify exit and the artifact views are the same as under a control
// edition with the same members and no claim. Controls: readings outside the window (the exclusive end
// included), from another instrument and of another class are out of scope; a reading the hub lists by its
// content (another observer's statement on the same bytes) counts as listed; with the missing reading listed,
// the check is `ok`, scoped to the statements held. A reading positioned in another timescale is `unchecked`,
// never `ok`, unless another reading already fails the claim; a claim with no scope is `unchecked`.
func TestCompletenessClaim(t *testing.T) {
	conformance.Covers(t, "C-core-60")
	w := newWorld(t)
	g := w.sign("G", "A", "genesis", obj("type", "collection", "name", "january", "controllers", w.controllers("A"), "rule", obj("any_one", true)))
	r1 := w.stationReading("R1", "O1", "jan-03", completenessStation, "2026-01-03T12:00:00Z", "")
	r2 := w.stationReading("R2", "O1", "jan-10", completenessStation, "2026-01-10T12:00:00Z", "")
	missing := w.stationReading("R3", "O2", "jan-20", completenessStation, "2026-01-20T12:00:00Z", "")
	// out of scope: before, at the exclusive end, another instrument, another class
	w.stationReading("Rdec", "O2", "dec-31", completenessStation, "2025-12-31T23:59:59.999999999Z", "")
	w.stationReading("Rfeb", "O2", "feb-01", completenessStation, "2026-02-01T00:00:00Z", "")
	w.stationReading("Rother", "O2", "other", "urn:example:station-8", "2026-01-15T00:00:00Z", "")
	w.observedRef("Rsrc", "O2", "src", "source", obj("endpoint", completenessStation, "parameters", obj(), "response_digest", dig("src")),
		"finality", obj("rule", "r", "state_at_capture", obj("captured_at", "2026-01-15T00:00:00Z")))
	// listed by content: O2's statement on R2's bytes is covered by the hub's content entry for them
	byContent := w.stationReading("R2b", "O2", "jan-10", completenessStation, "2026-01-10T12:00:00Z", "")
	other := w.authored("X", "M", "x", "licence", "MIT")
	members := entries(st(r1), Entry("content", dig("jan-10"), "member"), st(other))
	ctrl := w.editionWith("E0", "A", g, []string{g}, "members", members)
	beforeRes := w.store(nil)
	before := completenessSnapshot(t, beforeRes, g, r1, other)
	claim := w.editionWith("E1", "A", g, []string{ctrl}, "members", members, "selection", "completeness", "completeness", completenessScope())

	r := w.store(nil)
	c, ok := r.Completeness(g, "")
	if !ok || c.Edition != w.ed(claim) {
		t.Fatalf("no check at the claim edition: %+v", c)
	}
	if c.Outcome != RuleFail || !slices.Equal(c.Missing, []string{missing}) {
		t.Fatalf("want fail naming %s: %s", keylog.Short(missing), c.Render())
	}
	if !slices.Equal(c.Listed, completenessIDs(r1, r2, byContent)) {
		t.Fatalf("listed %v, want R1, R2 and R2b (by content)", c.Listed)
	}
	if len(c.Unread) != 0 {
		t.Fatalf("unread: %v", c.Unread)
	}
	// one answer in any delivery order (I14)
	var rev []int
	for i := len(w.lines) - 1; i >= 0; i-- {
		rev = append(rev, i)
	}
	if cr, _ := w.store(rev).Completeness(g, ""); cr.Render() != c.Render() {
		t.Fatalf("reversed delivery:\n%s\nwant\n%s", cr.Render(), c.Render())
	}
	has(t, c.Render(), "reading "+keylog.Short(missing)+" by ")
	has(t, c.Render(), "· fail (1 reading not listed) "+ScopeHeld)
	// the hub's other content is unaffected
	if after := completenessSnapshot(t, r, g, r1, other); after != before {
		t.Fatalf("the claim moved the hub's other content:\n%s\nwant\n%s", after, before)
	}
	res, _ := r.Resource(g)
	if e, _ := res.Edition(claim); e.State != Authorized || res.VerifyExit() != 0 {
		t.Fatalf("a failed claim moved the edition or the exit: %s %d", e.State, res.VerifyExit())
	}

	// control: list the missing reading; ok, scoped
	fixed := w.editionWith("E2", "A", g, []string{claim}, "members", append(slices.Clone(members), st(missing)),
		"selection", "completeness", "completeness", completenessScope())
	c, _ = w.store(nil).Completeness(g, "")
	if c.Edition != w.ed(fixed) || c.Outcome != RuleOK || len(c.Missing) != 0 || !strings.HasSuffix(c.Line(), "ok "+ScopeHeld) {
		t.Fatalf("control: %s", c.Render())
	}
	// ok is scoped, and claims nothing about readings the reader never received (C-core-01)
	if m := completenessClaim.FindString(c.Render()); m != "" {
		t.Fatalf("ok claims completeness (%s): %s", m, c.Render())
	}
	// the earlier edition still fails: the check is per edition
	if c, _ := w.store(nil).Completeness(g, claim); c.Outcome != RuleFail {
		t.Fatalf("the claim edition no longer fails: %s", c.Render())
	}

	// a reading in another timescale is not comparable: unchecked, never ok
	tai := w.stationReading("Rtai", "O2", "tai", completenessStation, "2026-01-05T00:00:37", "TAI")
	c, _ = w.store(nil).Completeness(g, "")
	if c.Outcome != RuleUnchecked || c.Unread[tai] == "" || !strings.Contains(c.Unread[tai], "never converted") {
		t.Fatalf("timescale: %s", c.Render())
	}
	// ...unless another reading already fails the claim
	if c, _ := w.store(nil).Completeness(g, claim); c.Outcome != RuleFail {
		t.Fatalf("unread masked a fail: %s", c.Render())
	}
	// a completeness selection with no scope: unchecked
	w.editionWith("E3", "A", g, []string{fixed}, "members", members, "selection", "completeness")
	c, _ = w.store(nil).Completeness(g, "")
	if !c.Declared || c.Scoped || c.Outcome != RuleUnchecked {
		t.Fatalf("unscoped: %s", c.Render())
	}
	// no claim: nothing is checked, and nothing is said to be ok
	if c, _ := w.store(nil).Completeness(g, ctrl); c.Declared || c.Outcome != "" || c.Line() != "no completeness claim" {
		t.Fatalf("no claim: %s", c.Render())
	}
}

// completenessSnapshot renders the hub's other content: the listed members' memberships (without the selection line,
// which is the edition's declaration), the artifacts' views and the resource's verify exit.
func completenessSnapshot(t *testing.T, r *Resolver, g string, keys ...string) string {
	t.Helper()
	var b strings.Builder
	for _, k := range keys {
		m, ok := r.Membership(g, k)
		if !ok {
			t.Fatalf("no membership view for %s", k)
		}
		m.Edition, m.Selection = "", ""
		m.Explain = nil
		b.WriteString(m.Render())
		if p, ok := r.Statement(k); ok {
			b.WriteString(r.Artifact(contentDigest(p.St.Body)).Render())
		}
	}
	res, _ := r.Resource(g)
	b.WriteString(string(rune('0' + res.VerifyExit())))
	return b.String()
}

func completenessIDs(ids ...string) []string {
	out := slices.Clone(ids)
	slices.Sort(out)
	return out
}

// TestCompletenessSourceClass: a completeness claim over a source (one month of a dataset endpoint), as a hub
// that captures in batches and after the fact would declare it. A reading's position is its referent window
// (the period the response covers), not when it was fetched: a November capture of October data is in an
// October window, and missing from the edition it makes the check `fail`. A batch names its source by
// `requests.endpoint`; a batch without one cannot be placed (`unchecked`). The endpoint is compared after RFC
// 3986 normalization (an upper-case host and the default port are the same endpoint, in scope); a spelling
// equal only once a trailing slash is set aside is undecided (`unchecked`, never out of scope); a reading with
// no window falls back to its finality state's `captured_at`, and with a run-labelled state it has no position.
func TestCompletenessSourceClass(t *testing.T) {
	const ep = "https://data.example.org/api/v1/datasets/B1610"
	w := newWorld(t)
	g := w.sign("G", "A", "genesis", obj("type", "collection", "name", "october", "controllers", w.controllers("A"), "rule", obj("any_one", true)))
	oct := func(from, to string) canon.Value { return obj("from", from, "to", to) }
	batch := func(name, x, endpoint string, window canon.Value, captured string) string {
		req := obj("digest", dig(x+"-log"), "format", "jsonl", "count", 300)
		if endpoint != "" {
			req = obj("digest", dig(x+"-log"), "format", "jsonl", "count", 300, "endpoint", endpoint)
		}
		ref := obj("requests", req)
		if window != nil {
			ref = obj("requests", req, "window", window)
		}
		return w.observedRef(name, "O1", x, "source", ref, "finality", obj("rule", "settlement", "state_at_capture", obj("captured_at", captured)))
	}
	// listed: an October batch captured in October
	listed := batch("B1", "oct-a", ep, oct("2026-10-01T00:00:00Z", "2026-10-08T00:00:00Z"), "2026-10-09T00:00:00Z")
	// missing: October data captured on 20 November, endpoint spelled with an upper-case host and port 443
	late := batch("B2", "oct-b", "https://DATA.example.org:443/api/v1/datasets/B1610", oct("2026-10-08T00:00:00Z", "2026-10-15T00:00:00Z"), "2026-11-20T00:00:00Z")
	// out of scope: September data captured in October (its window is outside, though its capture is inside)
	batch("B3", "sep", ep, oct("2026-09-24T00:00:00Z", "2026-10-01T00:00:00Z"), "2026-10-02T00:00:00Z")
	scope := obj("class", "source", "source", ep, "window", obj("from", "2026-10-01T00:00:00Z", "to", "2026-11-01T00:00:00Z"))
	claim := w.editionWith("E1", "A", g, []string{g}, "members", entries(st(listed)), "selection", "completeness", "completeness", scope)
	c, _ := w.store(nil).Completeness(g, "")
	if c.Edition != w.ed(claim) || c.Outcome != RuleFail || !slices.Equal(c.Missing, []string{late}) || len(c.Unread) != 0 {
		t.Fatalf("want fail naming the late capture of October data: %s", c.Render())
	}
	// list it: ok
	w.editionWith("E2", "A", g, []string{claim}, "members", entries(st(listed), st(late)), "selection", "completeness", "completeness", scope)
	if c, _ := w.store(nil).Completeness(g, ""); c.Outcome != RuleOK {
		t.Fatalf("both listed: %s", c.Render())
	}
	// a batch that names no endpoint: its source cannot be read
	anon := batch("B4", "anon", "", oct("2026-10-15T00:00:00Z", "2026-10-22T00:00:00Z"), "2026-10-23T00:00:00Z")
	c, _ = w.store(nil).Completeness(g, "")
	if c.Outcome != RuleUnchecked || !strings.Contains(c.Unread[anon], "requests.endpoint") {
		t.Fatalf("batch without endpoint: %s", c.Render())
	}
	// a trailing slash: maybe another resource, so undecided, never out of scope
	w2 := newWorld(t)
	g2 := w2.sign("G", "A", "genesis", obj("type", "collection", "name", "october", "controllers", w2.controllers("A"), "rule", obj("any_one", true)))
	slash := w2.observedRef("S1", "O1", "s", "source", obj("endpoint", ep+"/", "parameters", obj(), "response_digest", dig("s"),
		"window", oct("2026-10-03T00:00:00Z", "2026-10-04T00:00:00Z")))
	// no window: placed by captured_at; a run-labelled finality state gives no position
	byCapture := w2.observedRef("S2", "O1", "c", "source", obj("endpoint", ep, "parameters", obj(), "response_digest", dig("c")),
		"finality", obj("rule", "r", "state_at_capture", obj("captured_at", "2026-10-05T00:00:00Z")))
	noPos := w2.observedRef("S3", "O1", "r", "source", obj("endpoint", ep, "parameters", obj(), "response_digest", dig("r")),
		"finality", obj("rule", "r", "state_at_capture", obj("run", "SF")))
	w2.editionWith("E1", "A", g2, []string{g2}, "members", entries(st(byCapture)), "selection", "completeness", "completeness", scope)
	c, _ = w2.store(nil).Completeness(g2, "")
	if c.Outcome != RuleUnchecked || !strings.Contains(c.Unread[slash], "trailing /") || c.Unread[noPos] == "" || len(c.Missing) != 0 {
		t.Fatalf("loose match and no position must be unchecked, the captured_at reading listed: %s", c.Render())
	}
	if !slices.Contains(c.Listed, byCapture) {
		t.Fatalf("a reading with no window is placed by captured_at: %s", c.Render())
	}
}
