package resolve

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
)

// Edition rules (claims-model note §8 "Rules read statements", §13; CONFORMANCE C-core-90 – C-core-95).
//
// The core fixes what a rule may read and its three outcomes; the rule language is a profile (§15). So this
// file owns the domain and the outcomes, and a rule dialect plugs in through Dialect. A reader with no dialect
// configured evaluates every rule `unchecked` ("unsupported dialect"), which is the honest answer (I4): no
// dialect note exists yet, and this package ships none.
//
// The domain of a rule is exactly:
//   - the candidate member's record: its signed statement's disclosures, provenance and referent record
//     (§5.3.1), plus its role in the edition;
//   - its content, unit by unit, through the reader's ContentReader (forbidden keys, member schema);
//   - the edition under formation: the same record and content of every member the proposed edition lists,
//     so uniqueness and quota rules can be stated.
//
// Nothing else is in a rule's domain. A read outside it (the statements of an artifact that is neither the
// candidate nor a member, network data, any other field) is recorded and names the reference; the evaluation
// is then `unchecked`, never `ok`, whatever the dialect answered (C-core-93). The same downgrade applies when
// the rule read content the reader could not scan completely (C-core-95, storage note §8), and when a limit
// stopped the evaluation, which is also reported as an operational refusal naming the limit and its scope
// (this rule, this member; C-core-94, I8, I15).
//
// A set-level rule is evaluated over the whole proposed edition: the formation is a set, handed to the dialect
// sorted by member key, and every member is evaluated against the same set, so no member is admitted by order
// and a failure names every member in conflict (C-core-93b, I14).
//
// A failing rule rejects the membership, never the artifact: nothing here touches an artifact's view or its
// verify exit (C-core-91).

// Outcome is the result of one rule evaluation (§13: every rule evaluation is one of these three).
type Outcome string

const (
	RuleOK        Outcome = "ok"
	RuleFail      Outcome = "fail"
	RuleUnchecked Outcome = "unchecked"
)

// Dialect is a rule language profile. Compile returns an error naming the construct it does not support.
type Dialect interface {
	Name() string
	Compile(expr string) (Rule, error)
}

// Rule is one compiled rule. Eval reads only through the Domain it is given and returns its outcome, why, and
// for a set-level failure every member in conflict (member keys, as Domain.Members names them).
type Rule interface {
	Eval(d *Domain) (out Outcome, why string, conflicts []string)
}

// ContentUnit is one scannable unit of a blob: the blob itself, or one member of an archive. Unscanned is
// non-empty when the reader could not read the unit (`compression=xz unsupported`, `size limit=…`); Data is
// then nil (storage note §8).
type ContentUnit struct {
	Name      string
	Data      []byte
	Unscanned string
}

// ContentReader gives rules the bytes of a blob, unit by unit. The reader configures it; the default holds
// no bytes, so a content rule is `unchecked` (content not held).
type ContentReader interface {
	Units(digest string) (units []ContentUnit, held bool)
}

// DefaultRuleSteps is the step budget of one rule evaluation for one member: every domain read and every
// Domain.Step a dialect takes counts one. It is the documented limit behind C-core-94.
const DefaultRuleSteps = 100000

// RuleStepLimit names the limit in refusals.
const RuleStepLimit = "rule step limit"

type ruleConfig struct {
	dialects map[string]Dialect
	content  ContentReader
	steps    int
	segments SegmentReader
}

// WithDialect adds a rule dialect the reader supports.
func WithDialect(d Dialect) Option {
	return func(r *Resolver) {
		if r.rules.dialects == nil {
			r.rules.dialects = map[string]Dialect{}
		}
		r.rules.dialects[d.Name()] = d
	}
}

// WithContent sets where rules read blob content from.
func WithContent(c ContentReader) Option { return func(r *Resolver) { r.rules.content = c } }

// WithRuleSteps sets the step budget of one rule evaluation (DefaultRuleSteps when unset or < 1).
func WithRuleSteps(n int) Option { return func(r *Resolver) { r.rules.steps = n } }

// Member is one entry of an edition (or a candidate for one) and the record rules read for it.
type Member struct {
	// Key is what the entry names: a content digest, a resource id or a statement id. Members are keyed by it.
	Key  string
	Role string
	// By is "content", "resource" or "statement": which field of the entry named Key.
	By string
	// Statement and Signer identify the record's statement; "" for a draft (the pre-pin check) or when the
	// record comes from the artifact's resolved defaults.
	Statement, Signer string
	// Digest is the member's content digest, when it has content.
	Digest string
	record *canon.Object
	// fieldWhy explains a field the record cannot give (contested default, observation fields of a content
	// member); recordWhy explains a member with no record at all.
	fieldWhy  map[string]string
	recordWhy string
}

// Eval is one rule's evaluation for one member of a formation.
type Eval struct {
	Rule    int // index in contents.rules
	Dialect string
	Expr    string
	Member  string
	Outcome Outcome
	Why     string
	// Conflicts names every member in conflict for a set-level failure, sorted.
	Conflicts []string
	// Read lists what the evaluation read ("candidate:referent.system.routing_era", "member <k>:…",
	// "content:<unit>"), sorted; Outside, Missing and Unscanned the reads that could not be answered.
	Read, Outside, Missing, Unscanned []string
	// Refusal is set when a limit stopped the evaluation (class operational, scope this rule and member).
	Refusal *refusal.Refusal
}

func (e Eval) String() string {
	s := fmt.Sprintf("rule %d (%s %q) on %s: %s", e.Rule, e.Dialect, e.Expr, shortMember(e.Member), e.Outcome)
	if e.Why != "" {
		s += " (" + e.Why + ")"
	}
	if len(e.Conflicts) > 0 {
		s += " in conflict: " + strings.Join(shortMembers(e.Conflicts), ",")
	}
	return s
}

// Domain is everything a rule may read for one member of one formation. A dialect reads only through it.
type Domain struct {
	r      *Resolver
	cand   *Member
	form   map[string]*Member
	keys   []string
	steps  int
	limit  int
	reads  map[string]bool
	out    map[string]bool
	miss   map[string]bool
	unscan map[string]bool
	stop   *refusal.Refusal
	scope  string
}

// Candidate is the member under evaluation.
func (d *Domain) Candidate() string { return d.cand.Key }

// Members lists the edition under formation (the candidate included), sorted: a set, never an order.
func (d *Domain) Members() []string { return slices.Clone(d.keys) }

// Step charges one step of the budget. It returns false once the budget is spent; the dialect must stop.
func (d *Domain) Step() bool {
	if d.stop != nil {
		return false
	}
	d.steps++
	if d.steps > d.limit {
		d.stop = &refusal.Refusal{Class: refusal.Operational, Reason: RuleStepLimit,
			Detail: fmt.Sprintf("%s=%d, scope %s", RuleStepLimit, d.limit, d.scope)}
		return false
	}
	return true
}

// inDomain lists the record fields a rule may read: the disclosures, provenance, the referent record and the
// observation fields that belong to it (class, finality), and the member's role (§8 "Rules read statements").
var inDomain = map[string]bool{"licence": true, "licence_texts": true, "attribution": true, "availability": true,
	"replication": true, "comparator": true, "sampling": true, "shelf_life_days": true, "pre_registration": true,
	"fulfills": true, "intended_for": true, "description": true, "provenance": true, "referent": true,
	"class": true, "finality": true, "role": true, "content": true}

// Get reads a dotted path of a record. ref is "" for the candidate or a member key of the formation; anything
// else (another artifact's statements, a URL, "network:…") is outside the domain, recorded, and answers
// nothing (C-core-93). A path whose first field is not in the domain is outside it too.
func (d *Domain) Get(ref, path string) (canon.Value, bool) {
	if !d.Step() {
		return nil, false
	}
	m, label := d.member(ref)
	if m == nil {
		d.out[ref+":"+path] = true
		return nil, false
	}
	parts := strings.Split(path, ".")
	if !inDomain[parts[0]] {
		d.out[label+":"+path+" (not a field a rule may read)"] = true
		return nil, false
	}
	d.reads[label+":"+path] = true
	if parts[0] == "role" && len(parts) == 1 {
		return canon.String(m.Role), true
	}
	if m.record == nil {
		d.miss[label+":"+path+" ("+m.recordWhy+")"] = true
		return nil, false
	}
	if why, ok := m.fieldWhy[parts[0]]; ok {
		d.miss[label+":"+path+" ("+why+")"] = true
		return nil, false
	}
	var v canon.Value = m.record
	for _, p := range parts {
		o, ok := v.(*canon.Object)
		if !ok {
			d.miss[label+":"+path] = true
			return nil, false
		}
		if v, ok = o.Get(p); !ok {
			d.miss[label+":"+path] = true
			return nil, false
		}
	}
	return v, true
}

// Content returns the content units of the candidate (ref "") or of a member. A unit the reader could not
// scan is recorded: the evaluation cannot be `ok` (C-core-95, storage note §8).
func (d *Domain) Content(ref string) ([]ContentUnit, bool) {
	if !d.Step() {
		return nil, false
	}
	m, label := d.member(ref)
	if m == nil {
		d.out[ref+":content"] = true
		return nil, false
	}
	if m.Digest == "" || d.r.rules.content == nil {
		d.miss[label+":content (not held)"] = true
		return nil, false
	}
	units, held := d.r.rules.content.Units(m.Digest)
	if !held {
		d.miss[label+":content (not held)"] = true
		return nil, false
	}
	for _, u := range units {
		d.reads[label+":content:"+u.Name] = true
		if u.Unscanned != "" {
			d.unscan[label+":"+u.Name+" unscanned ("+u.Unscanned+")"] = true
		}
	}
	return units, true
}

// ContentJSON parses one content unit with the strict reader. The parser's depth limit is an operational
// refusal; it stops the evaluation with its scope (C-core-94).
func (d *Domain) ContentJSON(u ContentUnit) (canon.Value, bool) {
	if !d.Step() || u.Data == nil {
		return nil, false
	}
	v, err := canon.Parse(u.Data)
	if err != nil {
		if rf, ok := err.(*refusal.Refusal); ok && rf.Class == refusal.Operational {
			d.stop = &refusal.Refusal{Class: refusal.Operational, Reason: rf.Reason,
				Detail: fmt.Sprintf("%s, scope %s, unit %s", rf.Detail, d.scope, u.Name)}
		}
		return nil, false
	}
	return v, true
}

func (d *Domain) member(ref string) (*Member, string) {
	if ref == "" || ref == d.cand.Key {
		return d.cand, "candidate"
	}
	if m, ok := d.form[ref]; ok {
		return m, "member " + shortMember(ref)
	}
	return nil, ""
}

// compiled is one rule of an edition after loading.
type compiled struct {
	i              int
	dialect, expr  string
	rule           Rule
	unsupportedWhy string
}

// loadRules reads contents.rules of an edition body. Every rule is loaded and named, supported or not
// (C-core-92: the evaluation output names the rule and the unsupported construct).
func (r *Resolver) loadRules(body *canon.Object) []compiled {
	contents, _ := body.Get("contents")
	c, _ := contents.(*canon.Object)
	var out []compiled
	rv, _ := c.Get("rules")
	ra, _ := rv.(canon.Array)
	for i, x := range ra {
		o := x.(*canon.Object)
		cr := compiled{i: i, dialect: str(o, "dialect"), expr: str(o, "expr")}
		if d, ok := r.rules.dialects[cr.dialect]; !ok {
			cr.unsupportedWhy = "unsupported dialect " + cr.dialect
		} else if rule, err := d.Compile(cr.expr); err != nil {
			cr.unsupportedWhy = "unsupported construct: " + err.Error()
		} else {
			cr.rule = rule
		}
		out = append(out, cr)
	}
	// A member schema (contents.schema) is a rule over content in the member-schema dialect, which no note
	// defines yet (wire-format note §11). It is loaded, named and `unchecked`, so an edition that declares one
	// endorses nothing on a schema check that never ran (I4).
	if sch := str(c, "schema"); sch != "" {
		out = append(out, compiled{i: len(ra), dialect: "member-schema", expr: sch,
			unsupportedWhy: "member schema " + shortDigest(sch) + ": no member-schema dialect configured"})
	}
	return out
}

// evalRules evaluates every rule for every member of the formation. It is a function of the set of members:
// the result is sorted by member key, then rule.
func (r *Resolver) evalRules(rules []compiled, form []*Member) []Eval {
	set := map[string]*Member{}
	for _, m := range form {
		set[m.Key] = m
	}
	keys := sortedKeys(set)
	limit := r.rules.steps
	if limit < 1 {
		limit = DefaultRuleSteps
	}
	var out []Eval
	for _, k := range keys {
		for _, cr := range rules {
			e := Eval{Rule: cr.i, Dialect: cr.dialect, Expr: cr.expr, Member: k}
			if cr.rule == nil {
				e.Outcome, e.Why = RuleUnchecked, cr.unsupportedWhy
				out = append(out, e)
				continue
			}
			d := &Domain{r: r, cand: set[k], form: set, keys: keys, limit: limit, reads: map[string]bool{},
				out: map[string]bool{}, miss: map[string]bool{}, unscan: map[string]bool{},
				scope: fmt.Sprintf("rule %d (%s), member %s", cr.i, cr.dialect, shortMember(k))}
			o, why, conf := cr.rule.Eval(d)
			e.Outcome, e.Why = o, why
			e.Read, e.Outside, e.Missing, e.Unscanned = sortedKeys(d.reads), sortedKeys(d.out), sortedKeys(d.miss), sortedKeys(d.unscan)
			if o == RuleFail {
				e.Conflicts = slices.Sorted(slices.Values(slices.Compact(slices.Sorted(slices.Values(conf)))))
			}
			switch {
			case d.stop != nil:
				e.Outcome, e.Refusal, e.Conflicts = RuleUnchecked, d.stop, nil
				e.Why = d.stop.Error()
			case len(e.Outside) > 0 && o != RuleUnchecked:
				// An answer that read outside the domain is not an answer of this rule (§8 "nothing else").
				e.Outcome, e.Conflicts = RuleUnchecked, nil
				e.Why = "read outside the rule's domain: " + strings.Join(e.Outside, ", ")
			case len(e.Outside) > 0 && e.Why == "":
				e.Why = "read outside the rule's domain: " + strings.Join(e.Outside, ", ")
			case len(e.Unscanned) > 0 && o == RuleOK:
				// An incomplete scan is never clean (storage note §8, C-core-95, C-core-130).
				e.Outcome = RuleUnchecked
				e.Why = "incomplete scan: " + strings.Join(e.Unscanned, ", ")
			}
			if e.Outcome != RuleOK && e.Outcome != RuleFail && e.Outcome != RuleUnchecked {
				e.Why = fmt.Sprintf("dialect returned %q, not a rule outcome", e.Outcome)
				e.Outcome, e.Conflicts = RuleUnchecked, nil
			}
			out = append(out, e)
		}
	}
	return out
}

// memberRecord builds the record rules read for one edition entry (§8). A `statement` entry is that
// statement, when it counts and is an `authored` or `observed`. A `content` entry reads the blob's authorship
// defaults (§5.1, §5.2): a contested or undeclared field answers nothing, and the observation fields (referent,
// class, finality) need a `statement` entry, because several observers may each hold a statement on the same
// bytes. A `resource` entry has no record; only its role is readable.
func (r *Resolver) memberRecord(entry *canon.Object) *Member {
	m := &Member{Role: str(entry, "role"), fieldWhy: map[string]string{}}
	switch {
	case str(entry, "statement") != "":
		m.By, m.Key = "statement", str(entry, "statement")
		p, ok := r.byID[m.Key]
		switch {
		case !ok:
			m.recordWhy = "statement not held"
		case p.St.Kind != "authored" && p.St.Kind != "observed":
			m.recordWhy = "a " + p.St.Kind + " is not a member record"
		case !p.Counts():
			m.recordWhy = "statement counts toward nothing (" + notCountedWhy(p) + ")"
		default:
			m.record, m.Statement, m.Signer, m.Digest = p.St.Body, p.St.ID, p.St.Signer, contentDigest(p.St.Body)
		}
	case str(entry, "content") != "":
		m.By, m.Key, m.Digest = "content", str(entry, "content"), str(entry, "content")
		a := r.authorship(m.Key)
		if a.State == NoClaim {
			m.recordWhy = "no counted authored statement for this content; name the statement"
			break
		}
		rec := &canon.Object{Members: map[string]canon.Value{}}
		for _, f := range a.Fields {
			v, ok := f.Default()
			if !ok {
				if f.State != FieldAbsent {
					m.fieldWhy[f.Name] = string(f.State)
				}
				continue
			}
			pv, _ := canon.Parse([]byte(v))
			rec.Keys = append(rec.Keys, f.Name)
			rec.Members[f.Name] = pv
		}
		if a.Default != nil && a.Default.Provenance != nil && len(a.Default.Claims) > 0 && len(a.Default.Claims[0].current) > 0 {
			if pv, ok := a.Default.Claims[0].current[0].Body.Get("provenance"); ok {
				rec.Keys = append(rec.Keys, "provenance")
				rec.Members["provenance"] = pv
			}
		} else if a.Default == nil {
			m.fieldWhy["provenance"] = "authorship " + string(a.State)
		}
		for _, f := range []string{"referent", "class", "finality"} {
			m.fieldWhy[f] = "a content member carries no observation record; name the observed statement"
		}
		slices.SortFunc(rec.Keys, canon.CompareKeys)
		m.record = rec
	default:
		m.By, m.Key = "resource", str(entry, "resource")
		m.recordWhy = "a resource member has no statement record"
	}
	return m
}

// draftMember is the pre-pin check's candidate: an unsigned body, its content named by its digest.
func draftMember(body *canon.Object) *Member {
	d := contentDigest(body)
	return &Member{Key: d, By: "content", Digest: d, Role: "member", record: body, fieldWhy: map[string]string{}}
}

func (r *Resolver) editionMembers(e *Edition) []*Member {
	var out []*Member
	for _, x := range e.Members {
		if o, ok := x.(*canon.Object); ok {
			out = append(out, r.memberRecord(o))
		}
	}
	return out
}

func shortMember(k string) string {
	if strings.HasPrefix(k, "sha256:") {
		return shortDigest(k)
	}
	return keylog.Short(k)
}

func shortMembers(ks []string) []string {
	out := make([]string, len(ks))
	for i, k := range ks {
		out[i] = shortMember(k)
	}
	return out
}
