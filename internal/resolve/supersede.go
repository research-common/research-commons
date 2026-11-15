package resolve

import (
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Supersession (bitcoin-time note §1 rule 5). A signer may hold several `anchors` lines for one covered head:
// typically a pending stamp and, later, the upgraded proof, or the same head stamped twice. Every line stays in
// the log and every one is evaluated; per (signer, covered head) one of them is displayed:
//
//   - the earliest verified bound, if any line of the head yields one (as for priority: by height, then id);
//   - else the usable line latest in the signer's log order: a line that descends from another through `prev`
//     (and `merges`) supersedes it. Lines on forked branches descend from neither, so the lower id is shown;
//   - else (every line refused) the refused line latest in log order, shown as refused: still no bound.
//
// A refused line never displaces a usable one, and the choice never reads a timestamp, file position or delivery
// order. Priority and every other answer read verified bounds only, so the display rule changes none of them:
// the earliest verified bound is the same with or without it.

// AnchorLine is one `anchors` line of a statement's signer whose covered head has the statement in its history,
// as explain lists it.
type AnchorLine struct {
	Anchor  string
	Covered string
	// Bound is what the reader's verifier derived from the line. Usable is false for a line that yields no bound
	// at all (an incoherent anchors line whose proof places nothing); a refused line is usable=true with
	// Quality NoBound and Anchor set, and bounds nothing.
	Bound  Bound
	Usable bool
	// Displayed marks the line shown for its covered head; Why says why it is or is not (the reason only: Displayed
	// carries which).
	Displayed bool
	Why       string
}

// anchorCand is a counting anchors line of st's signer whose covered head has st in its history.
type anchorCand struct {
	p   *Placed
	cov string
	b   Bound
	ok  bool // false: the line yields no bound (anchorBound)
}

// anchorCands is every counting anchors line of st's signer that bounds st (covered head reached by the anchor
// line, st in the head's history), by anchor id.
func (r *Resolver) anchorCands(st *wire.Statement) []anchorCand {
	var out []anchorCand
	for _, a := range r.byKind["anchors"] {
		if a.St.Signer != st.Signer || !r.anchorCounts(a) {
			continue
		}
		cov := str(a.St.Body, "covered")
		if !r.precedes(st.Signer, cov, a.St.ID) || !closure(cov, r.chained[st.Signer])[st.ID] {
			continue
		}
		b, ok := r.anchorBound(a)
		out = append(out, anchorCand{p: a, cov: cov, b: b, ok: ok})
	}
	slices.SortFunc(out, func(x, y anchorCand) int { return strings.Compare(x.p.St.ID, y.p.St.ID) })
	return out
}

// latestInLog is the line of cs latest in signer's log order: the lines no other line of cs descends from, and
// among those (forked branches) the lower id. cs is non-empty and sorted by id.
func (r *Resolver) latestInLog(signer string, cs []anchorCand) anchorCand {
	for _, c := range cs {
		if !slices.ContainsFunc(cs, func(d anchorCand) bool { return r.precedes(signer, c.p.St.ID, d.p.St.ID) }) {
			return c // the first maximal line in id order: the lower id among forked branches
		}
	}
	return cs[0] // unreachable: a finite partial order has a maximal element
}

// displayedFor picks the displayed line among the usable lines of one covered head (rule above), and false when
// none is usable.
func (r *Resolver) displayedFor(signer string, cs []anchorCand) (anchorCand, bool) {
	var verified, local, refused []anchorCand
	for _, c := range cs {
		switch {
		case !c.ok:
		case c.b.verified():
			verified = append(verified, c)
		case c.b.Quality == NoBound:
			refused = append(refused, c)
		default:
			local = append(local, c)
		}
	}
	if len(verified) > 0 {
		best := verified[0]
		for _, c := range verified[1:] {
			if c.b.Height < best.b.Height {
				best = c // ties keep the lower id (cs is sorted by id)
			}
		}
		return best, true
	}
	if len(local) > 0 {
		return r.latestInLog(signer, local), true
	}
	if len(refused) > 0 {
		return r.latestInLog(signer, refused), true
	}
	return anchorCand{}, false
}

// byHead groups candidates by covered head, heads sorted.
func byHead(cs []anchorCand) (heads []string, groups map[string][]anchorCand) {
	groups = map[string][]anchorCand{}
	for _, c := range cs {
		groups[c.cov] = append(groups[c.cov], c)
	}
	return sortedKeys(groups), groups
}

// AnchorLines is every counting anchors line of the statement's signer that bounds statement id, with the line
// displayed for each covered head marked and the reason for each line's place, ordered by covered head, then
// log position (seq), then id. Nil for a statement not held or on an incoherent line (it has no bound).
func (r *Resolver) AnchorLines(id string) []AnchorLine {
	p, ok := r.byID[id]
	if !ok || r.incoherent(id) {
		return nil
	}
	signer := p.St.Signer
	heads, groups := byHead(r.anchorCands(p.St))
	var out []AnchorLine
	for _, h := range heads {
		cs := groups[h]
		shown, has := r.displayedFor(signer, cs)
		slices.SortStableFunc(cs, func(x, y anchorCand) int {
			if x.p.St.Seq != y.p.St.Seq {
				if x.p.St.Seq < y.p.St.Seq {
					return -1
				}
				return 1
			}
			return strings.Compare(x.p.St.ID, y.p.St.ID)
		})
		for _, c := range cs {
			l := AnchorLine{Anchor: c.p.St.ID, Covered: h, Bound: c.b, Usable: c.ok}
			if has && c.p.St.ID == shown.p.St.ID {
				l.Displayed = true
				l.Why = r.shownWhy(signer, shown, cs)
			} else {
				l.Why = r.notShownWhy(signer, c, shown, has)
			}
			out = append(out, l)
		}
	}
	return out
}

// shownWhy says why the displayed line of one covered head is displayed.
func (r *Resolver) shownWhy(signer string, shown anchorCand, cs []anchorCand) string {
	switch {
	case len(cs) == 1:
		return "the only anchors line for this head"
	case shown.b.verified():
		return "verified preferred (the earliest verified bound for this head)"
	case shown.b.Quality == NoBound:
		return "every anchors line for this head is refused; the latest in log order is shown, and it bounds nothing"
	}
	for _, c := range cs {
		if c.p.St.ID != shown.p.St.ID && c.ok && c.b.Quality == Local && !r.precedes(signer, c.p.St.ID, shown.p.St.ID) {
			return "latest in log order; the unverified lines on forked branches descend from neither, so the lower id is shown"
		}
	}
	return "latest in log order"
}

// notShownWhy says why line c is not the line displayed for its covered head (shown).
func (r *Resolver) notShownWhy(signer string, c, shown anchorCand, has bool) string {
	switch {
	case !c.ok:
		return "incoherent line; its proof places no bound, so no bound is derived from it"
	case !has:
		return "no line of this head yields a bound" // unreachable: a line yielding none is caught above
	case shown.b.verified() && c.b.verified():
		return "a later verified bound; " + keylog.Short(shown.p.St.ID) + " is earlier"
	case shown.b.verified():
		return "verified preferred (" + keylog.Short(shown.p.St.ID) + ")"
	case c.b.Quality == NoBound && shown.b.Quality != NoBound:
		return "refused; a refused anchor never displaces a usable one (" + keylog.Short(shown.p.St.ID) + ")"
	case r.precedes(signer, c.p.St.ID, shown.p.St.ID):
		return "superseded by " + keylog.Short(shown.p.St.ID)
	}
	return "on a forked branch; " + keylog.Short(shown.p.St.ID) + " (lower id) is shown"
}
