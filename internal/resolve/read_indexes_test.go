package resolve

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/rctime"
)

func TestPartOfIndexMatchesWalk(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("g", "KEY", 0, "KEY")
	other := w.genesis("other", "KEY", 0, "KEY")
	keys := []string{dig("x"), strings.Repeat("a", 64), g}
	for i, field := range []string{"content", "statement", "resource"} {
		for j, resource := range []string{g, other} {
			w.sign(fmt.Sprintf("d%d-%d", i, j), "KEY", "describes", obj("about", obj(field, keys[i]), "links", canon.Array{obj("resource", resource, "rel", "part-of")}))
		}
	}
	r := w.store(nil)
	for _, resource := range []string{g, other, "absent"} {
		for _, key := range append(keys, "", "absent") {
			if got, want := r.partOfClaims(resource, key), r.scanPartOfClaims(resource, key); !reflect.DeepEqual(got, want) {
				t.Fatalf("%s %s: got %+v want %+v", resource, key, got, want)
			}
		}
	}
}

func TestCompletenessIndexMatchesWalk(t *testing.T) {
	w := newWorld(t)
	sources := []string{"https://example.org", "https://example.org/", "HTTPS://EXAMPLE.ORG:443/", "https://example.org/a", "https://example.org/a/", "https://example.org/%61", "https://example.org/a%2Fb", "https://example.org/a/b", "urn:example:A", "urn:example:B", "plain-text"}
	var first string
	for i, source := range sources {
		x := fmt.Sprint(i)
		id := w.stationReading("p"+x, "OBS", x, source, "2026-01-15T00:00:00Z", "")
		if i == 0 {
			first = id
		}
		w.observed("s"+x, "OBS", "s"+x, "source", apiRef(source))
	}
	w.observed("unread", "OBS", "unread", "source", obj())
	w.observed("batch", "OBS", "batch", "source", obj("requests", obj("endpoint", sources[0])))
	for i, source := range sources {
		for _, class := range []string{"phenomenon", "source"} {
			name := fmt.Sprintf("%d-%s", i, class)
			g := w.genesis("g"+name, "KEY", 0, "KEY")
			w.editionWith("e"+name, "KEY", g, []string{g}, "members", entries(st(first)), "selection", "completeness", "completeness", completenessScope("source", source, "class", class))
		}
	}
	r := w.store(nil)
	sawMissing, sawListed, sawUnread := false, false, false
	for _, g := range r.byKind["genesis"] {
		got, ok := r.Completeness(g.St.ID, "")
		want, wok := r.scanCompleteness(g.St.ID, "")
		if ok != wok || !reflect.DeepEqual(got, want) {
			t.Fatalf("completeness changed: got %+v want %+v", got, want)
		}
		sawMissing = sawMissing || len(got.Missing) > 0
		sawListed = sawListed || len(got.Listed) > 0
		sawUnread = sawUnread || len(got.Unread) > 0
	}
	if !sawMissing || !sawListed || !sawUnread {
		t.Fatalf("missing=%v listed=%v unread=%v", sawMissing, sawListed, sawUnread)
	}
}

func TestMethodDeclarationIndexMatchesWalk(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("g", "KEY", 0, "KEY")
	e1 := w.editionWith("e1", "KEY", g, []string{g}, "system_keys", []string{"model"})
	e2 := w.editionWith("e2", "KEY", g, []string{e1}, "system_keys", []string{"model", "provider"})
	orphan := w.editionWith("orphan", "KEY", g, []string{strings.Repeat("a", 64)}, "system_keys", []string{"model"})
	r := w.store(nil)
	for _, ed := range []string{w.ed(e2), w.ed(orphan), w.ed(e1), strings.Repeat("b", 64)} {
		got := r.methodDecl(ed)
		want := methodDecl{Edition: ed, Unread: DeclNotHeld}
		resource, _ := r.Resource(g)
		for _, e := range resource.Editions {
			if e.ID == ed {
				want.Unread = ""
				if e.State != Authorized {
					want.Unread = string(e.State)
				} else {
					want.Keys = declaredSystemKeys(e.Body)
				}
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v want %+v", got, want)
		}
	}
}

func (r *Resolver) scanPartOfClaims(resource, key string) []*Placed {
	var out []*Placed
	for _, p := range r.byKind["describes"] {
		if !r.counts(p) {
			continue
		}
		about, _ := p.St.Body.Get("about")
		ao := about.(*canon.Object)
		if str(ao, "content") != key && str(ao, "statement") != key && str(ao, "resource") != key {
			continue
		}
		links, _ := p.St.Body.Get("links")
		la, _ := links.(canon.Array)
		for _, l := range la {
			if str(l.(*canon.Object), "resource") == resource {
				out = append(out, p)
				break
			}
		}
	}
	slices.SortFunc(out, func(a, b *Placed) int { return strings.Compare(a.St.ID, b.St.ID) })
	return out
}

func (r *Resolver) scanCompleteness(id, edition string) (*Completeness, bool) {
	res, ok := r.Resource(id)
	if !ok {
		return nil, false
	}
	if edition == "" {
		edition = res.Current
	}
	e, ok := res.Edition(edition)
	if !ok || e.State != Authorized {
		return nil, false
	}
	c := &Completeness{Resource: id, Edition: e.ID, Scope: r.obs.scope, Unread: map[string]string{}}
	// the selection is read here only to find the claim; it informs no agreement model (C-core-59)
	if c.Declared = Selection(e.Body) == "completeness"; !c.Declared {
		c.Explain = append(c.Explain, "the edition declares no completeness claim; nothing to check")
		return c, true
	}
	contents, _ := e.Body.Get("contents")
	sv, ok := contents.(*canon.Object).Get("completeness")
	if !ok {
		c.Outcome = RuleUnchecked
		c.Explain = append(c.Explain, "the completeness claim names no scope (class, source, window): it cannot be checked")
		return c, true
	}
	sc := sv.(*canon.Object)
	w := object(sc, "window")
	c.Scoped, c.Class, c.Source, c.From, c.To, c.Timescale = true, str(sc, "class"), str(sc, "source"), str(w, "from"), str(w, "to"), str(sc, "timescale")
	from, err1 := rctime.ParseIn(c.From, c.Timescale)
	to, err2 := rctime.ParseIn(c.To, c.Timescale)
	if err1 != nil || err2 != nil {
		c.Outcome = RuleUnchecked // the schema refuses this edition; kept for a body read some other way
		c.Explain = append(c.Explain, "the claim's window does not read in its timescale")
		return c, true
	}

	listed := map[string]bool{}
	for _, m := range r.editionMembers(e) {
		listed[m.Key] = true
		if m.Digest != "" {
			listed[m.Digest] = true
		}
	}
	for _, p := range r.byKind["observed"] {
		if !r.counts(p) || str(p.St.Body, "class") != c.Class {
			continue
		}
		in, why := c.inScope(p, from, to)
		switch {
		case why != "":
			c.Unread[p.St.ID] = why
		case !in:
		case listed[p.St.ID] || listed[contentDigest(p.St.Body)]:
			c.Listed = append(c.Listed, p.St.ID)
		default:
			c.Missing = append(c.Missing, p.St.ID)
		}
	}
	slices.Sort(c.Listed)
	slices.Sort(c.Missing)
	switch {
	case len(c.Missing) > 0:
		c.Outcome = RuleFail
		for _, id := range c.Missing {
			c.Explain = append(c.Explain, fmt.Sprintf("reading %s by %s from %s in the window is not listed by %s",
				keylog.Short(id), shortKey(r.byID[id].St.Signer), c.Source, keylog.Short(e.ID)))
		}
	case len(c.Unread) > 0:
		c.Outcome = RuleUnchecked
	default:
		c.Outcome = RuleOK
	}
	for _, id := range sortedKeys(c.Unread) {
		c.Explain = append(c.Explain, fmt.Sprintf("reading %s: %s", keylog.Short(id), c.Unread[id]))
	}
	return c, true
}
