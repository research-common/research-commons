package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Credit (claims-model note §9.5): a projection, never a balance. Contribution, citation, reproduction,
// refutation, review, corroboration and acceptance are counted separately for one key, under a rule the reader
// chooses: the window and, per count, the denominator. Every count shows its denominator, its rule and its
// window. No default projection ships (Credit with no rule computes nothing), and nothing it returns is
// transferable: it is recomputed from the statements held, so a superseding decision changes it, and the
// superseded decision stays in its explain (I3, I5).
//
// The counts, each over counted statements in the window:
//   - contribution: the key's `submit` statements;
//   - citation: `authored` statements of other keys whose provenance inputs name a blob the key authored;
//   - reproduction: the key's `reproduced` statements;
//   - refutation: the key's `refutes` statements, a track of its own (§9.4: refutations are first-class);
//   - review: the key's counted `decide` statements (decisions it signed as a task's beneficiary);
//   - corroboration: the key's `corroborates` statements;
//   - acceptance: the key's submissions whose beneficiary decision, after supersession, is `accept`.

// CreditCounts are the separate counts, in display order.
var CreditCounts = []string{"contribution", "citation", "reproduction", "refutation", "review", "corroboration", "acceptance"}

// Denominators a reader may choose per count.
const (
	// DenomAll: every counted statement of the count's kind in the window, by any key.
	DenomAll = "all"
	// DenomOwnSubmissions: the key's own counted submissions in the window.
	DenomOwnSubmissions = "own-submissions"
	// DenomDecided: the key's submissions that have a beneficiary decision (acceptance only).
	DenomDecided = "decided"
)

// CreditWindow selects the statements a projection counts. The reader chooses it.
type CreditWindow interface {
	Label() string
	Contains(st *wire.Statement, b Bound) (bool, string)
}

// AllHeld is the window of every statement held.
type AllHeld struct{}

// Label implements CreditWindow.
func (AllHeld) Label() string { return "all statements held" }

// Contains implements CreditWindow.
func (AllHeld) Contains(*wire.Statement, Bound) (bool, string) { return true, "" }

// HeightWindow is a window of verified Bitcoin bounds [From, To]: a statement with no verified bound is outside
// it (its time is unknown to this reader), never placed by its own `ts`.
type HeightWindow struct{ From, To int64 }

// Label implements CreditWindow.
func (w HeightWindow) Label() string {
	return fmt.Sprintf("verified bitcoin bounds at heights %d to %d", w.From, w.To)
}

// Contains implements CreditWindow.
func (w HeightWindow) Contains(_ *wire.Statement, b Bound) (bool, string) {
	if !b.verified() {
		return false, "no verified bound"
	}
	return b.Height >= w.From && b.Height <= w.To, ""
}

// CreditRule is the reader's chosen projection: a name, a window and a denominator per count (DenomAll when
// a count has none).
type CreditRule struct {
	Name         string
	Window       CreditWindow
	Denominators map[string]string
}

// CreditCount is one count of a projection.
type CreditCount struct {
	Name        string
	N, Of       int
	Denominator string
	Statements  []string
}

// Credit is one key's credit projection.
type Credit struct {
	Key     string
	Rule    *CreditRule
	Counts  []CreditCount
	Explain []string
}

// NoProjection is what Credit says with no rule: no default projection ships (§9.5).
const NoProjection = "no credit projection configured: credit is a projection under rules the reader chooses; none ships"

// Credit computes key's credit under rule. With a nil rule it counts nothing and says so.
func (r *Resolver) Credit(key string, rule *CreditRule) *Credit {
	c := &Credit{Key: key, Rule: rule}
	if rule == nil {
		c.Explain = append(c.Explain, NoProjection)
		return c
	}
	win := rule.Window
	if win == nil {
		win = AllHeld{}
	}
	outside := 0
	in := func(p *Placed) bool {
		if !p.Counts() {
			return false
		}
		ok, _ := win.Contains(p.St, r.bound(p.St))
		if !ok {
			outside++
		}
		return ok
	}
	kinds := map[string]string{"contribution": "submit", "reproduction": "reproduced", "refutation": "refutes", "review": "decide", "corroboration": "corroborates", "citation": "authored"}
	inWin := map[string][]*Placed{}
	for _, k := range []string{"submit", "reproduced", "refutes", "decide", "corroborates", "authored"} {
		for _, p := range r.byKind[k] {
			if in(p) {
				inWin[k] = append(inWin[k], p)
			}
		}
	}
	// the key's counted decisions: only those a task view counts (the bound edition's beneficiary, citing a
	// submission); the task views also give acceptance
	counted := map[string]bool{}
	verdict := map[string]string{} // the key's submission id -> settled verdict
	var tasks []*Task
	for _, g := range r.byKind["genesis"] {
		if str(g.St.Body, "type") != "task" {
			continue
		}
		if t, ok := r.Task(g.St.ID); ok {
			tasks = append(tasks, t)
		}
	}
	for _, t := range tasks {
		mine := map[string]bool{}
		for _, s := range t.Submissions {
			mine[s.Statement] = s.Signer == key
		}
		for _, d := range t.Decisions {
			if d.Counts {
				counted[d.Statement] = true
			}
			if d.Counts && d.SupersededBy != "" {
				for _, s := range d.Submissions {
					if !mine[s] {
						continue
					}
					c.Explain = append(c.Explain, fmt.Sprintf("decision %s (%s %s) superseded by %s: kept in the log, no longer counted", keylog.Short(d.Statement), d.Verdict, keylog.Short(s), keylog.Short(d.SupersededBy)))
				}
			}
		}
		for _, s := range t.Submissions {
			if s.Signer == key && s.Counts && s.Verdict != "" {
				verdict[s.Statement] = s.Verdict
				for _, d := range t.Decisions {
					if d.Counts && d.SupersededBy == "" && slices.Contains(d.Submissions, s.Statement) {
						c.Explain = append(c.Explain, fmt.Sprintf("submission %s: %s by decision %s", keylog.Short(s.Statement), d.Verdict, keylog.Short(d.Statement)))
					}
				}
			}
		}
	}
	authoredByKey := map[string]bool{}
	for _, p := range r.byKind["authored"] {
		if p.Counts() && p.St.Signer == key {
			authoredByKey[contentDigest(p.St.Body)] = true
		}
	}
	isCitation := func(p *Placed) bool {
		if p.St.Signer == key {
			return false
		}
		if pv := provenance(p.St.Body); pv != nil {
			for _, x := range pv.Inputs {
				if authoredByKey[x] {
					return true
				}
			}
		}
		return false
	}
	var own []*Placed
	for _, p := range inWin["submit"] {
		if p.St.Signer == key {
			own = append(own, p)
		}
	}
	for _, name := range CreditCounts {
		den := rule.Denominators[name]
		if den == "" {
			den = DenomAll
		}
		cc := CreditCount{Name: name, Denominator: den}
		var pool []*Placed
		switch name {
		case "acceptance":
			pool = own
		case "citation":
			for _, p := range inWin["authored"] {
				if provenance(p.St.Body) != nil {
					pool = append(pool, p)
				}
			}
		case "review":
			for _, p := range inWin["decide"] {
				if counted[p.St.ID] {
					pool = append(pool, p)
				}
			}
		default:
			pool = inWin[kinds[name]]
		}
		for _, p := range pool {
			var hit bool
			switch name {
			case "acceptance":
				hit = verdict[p.St.ID] == "accept"
			case "citation":
				hit = isCitation(p)
			default:
				hit = p.St.Signer == key
			}
			if hit {
				cc.N++
				cc.Statements = append(cc.Statements, p.St.ID)
			}
		}
		switch den {
		case DenomOwnSubmissions:
			cc.Of = len(own)
		case DenomDecided:
			for _, p := range own {
				if verdict[p.St.ID] != "" {
					cc.Of++
				}
			}
		default:
			cc.Of = len(pool)
		}
		c.Counts = append(c.Counts, cc)
	}
	if outside > 0 {
		c.Explain = append(c.Explain, fmt.Sprintf("%d counted statement(s) outside the window", outside))
	}
	return c
}

// Render is the projection display: every count separately, each with its denominator, rule and window.
func (c *Credit) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "credit of %s (a projection; nothing transferable)\n", shortKey(c.Key))
	if c.Rule == nil {
		fmt.Fprintf(&b, "  %s\n", NoProjection)
		return b.String()
	}
	win := c.Rule.Window
	if win == nil {
		win = AllHeld{}
	}
	fmt.Fprintf(&b, "  rule %q, window: %s (chosen by the reader)\n", c.Rule.Name, win.Label())
	for _, cc := range c.Counts {
		fmt.Fprintf(&b, "  %s: %d of %d (denominator: %s)\n", cc.Name, cc.N, cc.Of, cc.Denominator)
	}
	for _, x := range c.Explain {
		fmt.Fprintf(&b, "  explain: %s\n", x)
	}
	return b.String()
}
