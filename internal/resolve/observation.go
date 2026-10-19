package resolve

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// The observation view (claims-model note §5.3; wire-format note §5 `observed`).
//
// An observation is one `observed` statement, never a blob: the class is per statement (§5.3.1 "one class per
// statement, one class per blob"), so two observers asserting different classes for the same bytes are two
// observations, each listed with its signer and each corroborated under the model its own class names
// (C-core-36). No blob-level class is shown.
//
// Everything the observer signed (class, referent, finality rule, capture record, roles) is displayed as the
// observer's statement with a pointer to it (I2). What the reader computes is shown beside it and never
// rewrites it: the referent status (§5.3.1, §7), the capture evidence the reader verified (§5.3.3) and the
// corroboration status (§5.3.2, corroboration.go).
//
// External facts the reader needs are behind the reader's own interfaces (I9), like TimeVerifier and
// Comparator: re-reading a referent (ReferentChecker), evaluating a source's finality rule (FinalityRules),
// verifying a device attestation (AttestationVerifier), knowing which blobs it holds (BlobIndex) and applying a
// cohort rule (CohortRules). Every default checks nothing, so with no options every re-check is `unchecked`
// and every attestation unverified. Nothing here reaches the network.

// Referent fields each class pins, in display order (wire §5).
var referentOrder = map[string][]string{
	"exact-bytes": {"chain_id", "block_hash", "depth"},
	"source":      {"endpoint", "parameters", "response_digest", "requests"},
	"phenomenon":  {"instrument", "location", "place", "at", "timescale"},
	"method":      {"method_edition", "environment", "system", "inputs", "window", "timescale"},
}

// Referent statuses (claims §5.3.1, §7 table). Provisional is rendered with its states.
const (
	RefUnpinned      = "unpinned"
	RefNotCanonical  = "not canonical"
	RefUnavailable   = "source unavailable"
	RefRevised       = "revised"
	RefFinal         = "final"
	RefProvisional   = "provisional"
	RefCanonical     = "still canonical"
	RefAvailable     = "source still available"
	RefUnknown       = "unknown (not re-checked by this reader)"
	RefPinned        = "pinned"
	RefNoneYet       = "no referent (class none-yet)"
	RefRuleUnchecked = "finality unchecked"
)

// State is a capture's state under a finality rule (wire §5 `finality.state_at_capture`): exactly one of a
// depth, a run label or a capture time.
type State struct {
	HasDepth   bool
	Depth      int64
	Run        string
	CapturedAt string
}

func (s State) String() string {
	switch {
	case s.HasDepth:
		return strconv.FormatInt(s.Depth, 10)
	case s.Run != "":
		return s.Run
	case s.CapturedAt != "":
		return s.CapturedAt
	}
	return "?"
}

// FinalityRules evaluates a source's declared finality rule. The rule is a claim about the source's policy
// (§5.3.1); a reader resolves it against a source profile it chooses. Evaluate reports whether the rule is met
// at state, the final state's display, and whether the reader can evaluate the rule at all. Compare orders two
// states under the rule (-1, 0, +1); ok is false when they are not comparable.
type FinalityRules interface {
	Evaluate(rule string, s State) (met bool, final string, known bool)
	Compare(rule string, a, b State) (c int, ok bool)
}

// DepthRules is the default: it understands confirmation-depth rules (`confirmations >= N`, `confirmations ≥ N`)
// over a depth state, and nothing else. Any other rule (a settlement run, an epoch) needs a source profile the
// reader configures; until then the rule is shown and its status is `finality unchecked`.
type DepthRules struct{}

var reDepthRule = regexp.MustCompile(`^\s*confirmations\s*(>=|≥)\s*([0-9]{1,18})\s*$`)

// Evaluate implements FinalityRules.
func (DepthRules) Evaluate(rule string, s State) (bool, string, bool) {
	m := reDepthRule.FindStringSubmatch(rule)
	if m == nil || !s.HasDepth {
		return false, "", false
	}
	n, _ := strconv.ParseInt(m[2], 10, 64)
	return s.Depth >= n, m[2], true
}

// Compare implements FinalityRules: depths numerically, run labels by equality only.
func (DepthRules) Compare(_ string, a, b State) (int, bool) {
	switch {
	case a.HasDepth && b.HasDepth:
		return cmpInt(a.Depth, b.Depth), true
	case a.Run != "" && a.Run == b.Run:
		return 0, true
	}
	return 0, false
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Re-check outcomes.
const (
	ReSame         = "identical bytes"
	ReDifferent    = "different bytes"
	ReNotCanonical = "not canonical"
	ReUnavailable  = "source unavailable"
	ReUnchecked    = "unchecked"
)

// ReCheck is the reader's own re-read of an observation's referent: the block at the pinned hash from the
// reader's node, the pinned endpoint queried again.
type ReCheck struct {
	Outcome string
	// State is the referent's state at the re-check (the block's depth now, the run label now), when known.
	State State
	// Digest is the content digest of the bytes the re-check got, when it got any.
	Digest string
	Why    string
}

// ReferentChecker re-reads an observation's referent. It answers from the reader's own sources only (I9).
type ReferentChecker interface {
	Check(st *wire.Statement) ReCheck
}

// NoReferentChecker is the default: it re-reads nothing.
type NoReferentChecker struct{}

// Check implements ReferentChecker.
func (NoReferentChecker) Check(*wire.Statement) ReCheck {
	return ReCheck{Outcome: ReUnchecked, Why: "no referent checker configured"}
}

// AttestationVerifier verifies a device attestation against the bytes the statement names (§5.3.3). It must
// answer from receiver-local trust roots, never from a field of the statement.
type AttestationVerifier interface {
	VerifyAttestation(st *wire.Statement) (ok bool, why string)
}

// NoAttestationVerifier is the default: it verifies no attestation format.
type NoAttestationVerifier struct{}

// VerifyAttestation implements AttestationVerifier.
func (NoAttestationVerifier) VerifyAttestation(*wire.Statement) (bool, string) {
	return false, "no attestation verifier configured"
}

// BlobIndex reports whether the reader holds a blob (a rule document, a request log).
type BlobIndex interface {
	Has(digest string) bool
}

type noBlobs struct{}

func (noBlobs) Has(string) bool { return false }

// obsConfig is the reader's configuration for observations and corroboration.
type obsConfig struct {
	referents ReferentChecker
	finality  FinalityRules
	attest    AttestationVerifier
	blobs     BlobIndex
	cohorts   CohortRules
	counter   Counter
	scope     string
}

func defaultObsConfig() *obsConfig {
	return &obsConfig{referents: NoReferentChecker{}, finality: DepthRules{}, attest: NoAttestationVerifier{}, blobs: noBlobs{},
		cohorts: NoCohortRules{}, counter: KeyCounter{}, scope: ScopeHeld}
}

// WithReferentChecker sets the reader's referent re-checker.
func WithReferentChecker(c ReferentChecker) Option { return func(r *Resolver) { r.obs.referents = c } }

// WithFinalityRules sets the reader's finality-rule evaluator (its source profiles).
func WithFinalityRules(f FinalityRules) Option { return func(r *Resolver) { r.obs.finality = f } }

// WithAttestationVerifier sets the reader's attestation verifier.
func WithAttestationVerifier(v AttestationVerifier) Option {
	return func(r *Resolver) { r.obs.attest = v }
}

// WithBlobIndex tells the resolver which blobs the reader holds.
func WithBlobIndex(b BlobIndex) Option { return func(r *Resolver) { r.obs.blobs = b } }

// WithScope sets the scope every status is printed with (§6 (1), I4). The default is ScopeHeld; a hub surface
// that resolves only its own holdings passes ScopeHub. A scope never widens what the statements support.
func WithScope(s string) Option { return func(r *Resolver) { r.obs.scope = s } }

// Scopes.
const (
	ScopeHeld = "within statements you hold"
	ScopeHub  = "within this hub"
)

// Finality is the declared finality rule with its provenance (§5.3.1).
type Finality struct {
	Rule, RuleSource string
	// Provenance is `cited (document held)`, `cited (document not held)`, `cited (location only, unverified)` or
	// `observer's convention`.
	Provenance string
	State      State
	// RuleDocument lists the counted `observed` statements of the rule document, when the source is a digest:
	// the document is itself a source-class observation others can corroborate.
	RuleDocument []string
}

// Capture is the capture record as signed, beside what the reader verified (§5.3.3).
type Capture struct {
	At, Declared string
	// Display is the level as the reader shows it: only what it verified (`device-attested (unverified)`).
	Display string
	// Verified is the strongest level the reader verified: device-attested, anchored-at-capture, witnessed or
	// self-asserted (the floor: the observer's signed word).
	Verified string
	// Operator and Instrument are the declared roles, "" when undeclared; never inferred from the key.
	Operator, Instrument string
	// Witnesses are the named keys; Witnessed those with their own counted `observed` of the same bytes.
	Witnesses, Witnessed []string
	Bound                Bound
}

// Observation is the view of one `observed` statement.
type Observation struct {
	Statement, Signer, Digest string
	Counts                    bool
	// Class is the observer's assertion (§5.3.1 rule 1), never rewritten by the reader.
	Class string
	// Referent is each pinned field as the observer signed it (canonical JSON), in display order.
	Referent [][2]string
	Unpinned []string
	Finality *Finality
	// ReferentStatus is the reader's computation; ReferentHistory explains it.
	ReferentStatus  string
	ReferentHistory []string
	ReCheck         ReCheck
	Capture         Capture
	Corroboration   *Corroboration
	// Others are the other observations of the same bytes, with how each relates to this one.
	Others []string
	// Comparability lists, for a method-class observation, each other method-class observation of the same
	// method edition and whether the two pin the same clause members (C-core-32).
	Comparability []string
	Explain       []string
}

// Observations resolves every `observed` statement for blob d, by signer then statement id.
func (r *Resolver) Observations(d string) []*Observation {
	var out []*Observation
	for _, p := range r.observedOf(d, false) {
		out = append(out, r.observation(p))
	}
	return out
}

// Observation resolves one `observed` statement by id.
func (r *Resolver) Observation(id string) (*Observation, bool) {
	p, ok := r.byID[id]
	if !ok || p.St.Kind != "observed" {
		return nil, false
	}
	return r.observation(p), true
}

// observedOf lists the `observed` statements for d (only the counted ones when counted), sorted.
func (r *Resolver) observedOf(d string, counted bool) []*Placed {
	var out []*Placed
	for _, p := range r.byKind["observed"] {
		if contentDigest(p.St.Body) == d && (!counted || p.Counts()) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b *Placed) int { return strings.Compare(a.St.Signer+a.St.ID, b.St.Signer+b.St.ID) })
	return out
}

func (r *Resolver) observation(p *Placed) *Observation {
	st := p.St
	o := &Observation{Statement: st.ID, Signer: st.Signer, Digest: contentDigest(st.Body), Counts: p.Counts(),
		Class: str(st.Body, "class"), Unpinned: st.Unpinned}
	ref := object(st.Body, "referent")
	for _, f := range referentOrder[o.Class] {
		if v, ok := ref.Get(f); ok {
			o.Referent = append(o.Referent, [2]string{f, string(canon.Encode(v))})
		}
	}
	if !o.Counts {
		o.Explain = append(o.Explain, "this statement counts toward nothing: "+notCountedWhy(p))
	}
	o.Finality = r.finality(st)
	o.Capture = r.capture(st)
	r.referentStatus(o, st)
	r.others(o, st)
	if o.Class == "method" {
		r.comparability(o, st)
	}
	o.Corroboration = r.corroboration(o, st)
	return o
}

// finality reads the declared finality rule and its provenance (§5.3.1 "rule provenance").
func (r *Resolver) finality(st *wire.Statement) *Finality {
	fv, ok := st.Body.Get("finality")
	if !ok {
		return nil
	}
	fo := fv.(*canon.Object)
	f := &Finality{Rule: str(fo, "rule"), RuleSource: str(fo, "rule_source"), State: stateOf(object(fo, "state_at_capture"))}
	switch {
	case f.RuleSource == "":
		f.Provenance = "observer's convention"
	case reDigestForm.MatchString(f.RuleSource) && r.obs.blobs.Has(f.RuleSource):
		f.Provenance = "cited (document held)"
	case reDigestForm.MatchString(f.RuleSource):
		f.Provenance = "cited (document not held)"
	default:
		f.Provenance = "cited (location only, unverified)"
	}
	if reDigestForm.MatchString(f.RuleSource) {
		for _, q := range r.observedOf(f.RuleSource, true) {
			f.RuleDocument = append(f.RuleDocument, q.St.ID)
		}
	}
	return f
}

var reDigestForm = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

func stateOf(o *canon.Object) State {
	var s State
	if v, ok := o.Get("depth"); ok {
		if n, ok := v.(canon.Int); ok {
			s.HasDepth, s.Depth = true, int64(n)
		}
	}
	s.Run = str(o, "run")
	s.CapturedAt = str(o, "captured_at")
	return s
}

// capture displays the capture record: each level only as far as the reader verified it (§5.3.3).
func (r *Resolver) capture(st *wire.Statement) Capture {
	co := object(st.Body, "capture")
	c := Capture{At: str(co, "at"), Declared: str(co, "evidence"), Operator: str(co, "operator"), Instrument: str(co, "instrument"),
		Verified: "self-asserted", Bound: r.bound(st)}
	c.Witnesses = ids(co, "witnesses")
	d := contentDigest(st.Body)
	mine := string(canon.Encode(co))
	for _, w := range c.Witnesses {
		for _, q := range r.observedOf(d, true) {
			// a witness counts with its own observed statement carrying its own capture record; a statement that
			// repeats this one's capture record byte for byte is a co-signature, not a capture (C-core-44, 54)
			if q.St.Signer == w && q.St.Signer != st.Signer && string(canon.Encode(object(q.St.Body, "capture"))) != mine {
				c.Witnessed = append(c.Witnessed, w)
				break
			}
		}
	}
	switch c.Declared {
	case "self-asserted":
		c.Display = "self-asserted"
	case "anchored-at-capture":
		switch {
		case c.Bound.verified():
			c.Display = "anchored at capture (" + c.Bound.String() + ")"
			c.Verified = "anchored-at-capture"
		case c.Bound.Quality == Local:
			c.Display = "anchored at capture (local, self-declared)"
		default:
			c.Display = "anchored at capture (no anchor held)"
		}
	case "witnessed":
		if len(c.Witnessed) > 0 {
			c.Display = fmt.Sprintf("witnessed by %d", len(c.Witnessed))
			c.Verified = "witnessed"
		} else {
			c.Display = "witnessed (0 own statements)"
		}
	case "device-attested":
		if ok, _ := r.obs.attest.VerifyAttestation(st); ok {
			c.Display = "device-attested"
			c.Verified = "device-attested"
		} else {
			c.Display = "device-attested (unverified)"
		}
	}
	return c
}

// referentStatus computes the referent status from the statement's pins, its finality rule, the reader's
// re-check and the other captures of the same referent the reader holds (§5.3.1). A fork or a vanished source
// never counts against the observer: it is a status, not a corroboration (C-core-33, C-core-34).
func (r *Resolver) referentStatus(o *Observation, st *wire.Statement) {
	if len(o.Unpinned) > 0 {
		o.ReferentStatus = RefUnpinned
		o.ReferentHistory = append(o.ReferentHistory, "the referent lacks "+strings.Join(o.Unpinned, ", ")+
			", which its class requires: admitted, no class-specific agreement model applied (claims §5.3.1)")
		o.ReCheck = ReCheck{Outcome: ReUnchecked, Why: "referent unpinned"}
		return
	}
	switch o.Class {
	case "none-yet":
		o.ReferentStatus = RefNoneYet
		return
	case "phenomenon", "method":
		o.ReferentStatus = RefPinned
		return
	}
	o.ReCheck = r.obs.referents.Check(st)
	rc := o.ReCheck
	var status string
	f := o.Finality
	if f != nil {
		met, final, known := r.obs.finality.Evaluate(f.Rule, f.State)
		switch {
		case !known:
			status = RefRuleUnchecked
			o.ReferentHistory = append(o.ReferentHistory, fmt.Sprintf("at capture: state %s under rule %q, which this reader cannot evaluate (no source profile for it)", f.State, f.Rule))
		case met:
			status = RefFinal
			o.ReferentHistory = append(o.ReferentHistory, fmt.Sprintf("at capture: state %s meets rule %q: final", f.State, f.Rule))
		default:
			status = fmt.Sprintf("%s (%s; final at %s)", RefProvisional, f.State, final)
			o.ReferentHistory = append(o.ReferentHistory, fmt.Sprintf("at capture: state %s, rule %q unmet: %s", f.State, f.Rule, status))
			if rev := r.revision(o, st); rev != "" {
				status = RefRevised
				o.ReferentHistory = append(o.ReferentHistory, rev)
			}
		}
	}
	switch rc.Outcome {
	case ReNotCanonical:
		status = RefNotCanonical
		o.ReferentHistory = append(o.ReferentHistory, "reader re-check: not canonical ("+rc.Why+"); the observation stays true of what it pinned and nothing counts against the observer")
	case ReUnavailable:
		status = RefUnavailable
		o.ReferentHistory = append(o.ReferentHistory, "reader re-check: source unavailable ("+rc.Why+"); existing corroborations stand")
	case ReSame:
		if f != nil {
			if met, _, known := r.obs.finality.Evaluate(f.Rule, rc.State); known && met && status != RefRevised {
				status = RefFinal
				o.ReferentHistory = append(o.ReferentHistory, fmt.Sprintf("reader re-check: state %s, identical bytes: final (asserted state %s shown beside it)", rc.State, f.State))
				break
			}
			o.ReferentHistory = append(o.ReferentHistory, fmt.Sprintf("reader re-check: state %s, identical bytes", rc.State))
			break
		}
		if o.Class == "source" {
			status = RefAvailable
		} else {
			status = RefCanonical
		}
		o.ReferentHistory = append(o.ReferentHistory, "reader re-check: identical bytes")
	case ReDifferent:
		o.ReferentHistory = append(o.ReferentHistory, "reader re-check: different bytes (counted in the corroboration status)")
	case ReUnchecked:
		if rc.Why != "" {
			o.ReferentHistory = append(o.ReferentHistory, "reader re-check: unchecked ("+rc.Why+")")
		}
	}
	if status == "" {
		status = RefUnknown
		if rc.Outcome == ReDifferent {
			status = RefCanonical
			if o.Class == "source" {
				status = RefAvailable
			}
		}
	}
	o.ReferentStatus = status
}

// revision finds a later capture of the same referent, by any key, at a different state with different bytes
// while the rule was unmet at this capture: the referent was revised (§5.3.1), which is not a contradiction.
func (r *Resolver) revision(o *Observation, st *wire.Statement) string {
	for _, q := range r.byKind["observed"] {
		if !q.Counts() || q.St.ID == st.ID || contentDigest(q.St.Body) == o.Digest || !sameReferent(st, q.St) {
			continue
		}
		qs := captureState(q.St)
		if c, ok := r.obs.finality.Compare(o.Finality.Rule, o.Finality.State, qs); ok && c >= 0 {
			continue // not later
		} else if !ok && qs == o.Finality.State {
			continue
		}
		return fmt.Sprintf("capture %s by %s at state %s holds different bytes for the same referent: revised before finality; this observation stays true of what it pinned",
			keylog.Short(q.St.ID), shortKey(q.St.Signer), qs)
	}
	return ""
}

// sameReferent: two statements pin the same referent. Exact-bytes: chain id and block hash (depth is a state).
// Source: endpoint and parameters, or the same request-log digest. Phenomenon and method referents are never
// compared here: their agreement needs a declared physical or statistical model (§5.3.1 table), and a
// phenomenon location compares numerically under RFC 5870, never as text.
func sameReferent(a, b *wire.Statement) bool {
	ca, cb := str(a.Body, "class"), str(b.Body, "class")
	if len(a.Unpinned) > 0 || len(b.Unpinned) > 0 {
		return false
	}
	ra, rb := object(a.Body, "referent"), object(b.Body, "referent")
	switch {
	case ca == "exact-bytes" && cb == "exact-bytes":
		return str(ra, "chain_id") == str(rb, "chain_id") && str(ra, "block_hash") == str(rb, "block_hash")
	case ca == "source" && cb == "source":
		if ga, ok := ra.Get("requests"); ok {
			gb, ok := rb.Get("requests")
			return ok && str(ga.(*canon.Object), "digest") == str(gb.(*canon.Object), "digest")
		}
		pa, _ := ra.Get("parameters")
		pb, _ := rb.Get("parameters")
		return str(ra, "endpoint") == str(rb, "endpoint") && pa != nil && pb != nil && string(canon.Encode(pa)) == string(canon.Encode(pb))
	}
	return false
}

// others lists the other observations of the same bytes and what they are to this one.
func (r *Resolver) others(o *Observation, st *wire.Statement) {
	for _, q := range r.observedOf(o.Digest, false) {
		if q.St.ID == st.ID {
			continue
		}
		line := fmt.Sprintf("also observed by %s in %s as %s", shortKey(q.St.Signer), keylog.Short(q.St.ID), str(q.St.Body, "class"))
		switch {
		case !q.Counts():
			line += " (counts toward nothing: " + notCountedWhy(q) + ")"
		case str(q.St.Body, "class") != o.Class:
			line += " (another class: each statement is corroborated under its own class's model)"
		case o.Class == "source" && !r.finalAt(st, q.St):
			line += " (source class: identical bytes are a second publication, not a corroboration)"
		case o.Class != "exact-bytes" && o.Class != "source":
			line += " (identical bytes in this class are a copy, not a corroboration)"
		}
		o.Others = append(o.Others, line)
	}
}

// finalAt reports whether this statement declares a finality rule and q's capture meets it: the condition under
// which a re-capture with identical bytes is an exact-bytes corroboration (§5.3.1 "class migration by rule").
func (r *Resolver) finalAt(st, q *wire.Statement) bool {
	f := r.finality(st)
	if f == nil {
		return false
	}
	met, _, known := r.obs.finality.Evaluate(f.Rule, captureState(q))
	return known && met
}

// captureState is the state a capture saw: its declared finality state, else, for an exact-bytes referent, the
// confirmation depth it pinned (§5.3.1: chain referents pin the depth at capture).
func captureState(st *wire.Statement) State {
	if f := object(st.Body, "finality"); f != nil {
		return stateOf(object(f, "state_at_capture"))
	}
	if str(st.Body, "class") == "exact-bytes" {
		return stateOf(object(st.Body, "referent"))
	}
	return State{}
}

// comparability checks a method-class observation against every other counted method-class observation of the
// same method edition: two that do not pin the same measured-system members are not comparable, and the
// display names what is missing (C-core-32). Comparability is a precondition of any statistical agreement
// model; it never reads as `supports`.
func (r *Resolver) comparability(o *Observation, st *wire.Statement) {
	ref := object(st.Body, "referent")
	ed := str(ref, "method_edition")
	mine := memberKeys(object(ref, "system"))
	for _, q := range r.byKind["observed"] {
		if !q.Counts() || q.St.ID == st.ID || str(q.St.Body, "class") != "method" {
			continue
		}
		qr := object(q.St.Body, "referent")
		if str(qr, "method_edition") != ed {
			continue
		}
		theirs := memberKeys(object(qr, "system"))
		var missingHere, missingThere []string
		for _, k := range theirs {
			if !slices.Contains(mine, k) {
				missingHere = append(missingHere, "system."+k)
			}
		}
		for _, k := range mine {
			if !slices.Contains(theirs, k) {
				missingThere = append(missingThere, "system."+k)
			}
		}
		line := fmt.Sprintf("vs %s by %s: ", keylog.Short(q.St.ID), shortKey(q.St.Signer))
		if len(missingHere)+len(missingThere) == 0 && len(o.Unpinned) == 0 && len(q.St.Unpinned) == 0 {
			line += "same pinned clause members (comparable; agreement needs a declared model)"
		} else {
			var parts []string
			if len(missingHere) > 0 {
				parts = append(parts, "this observation does not pin "+strings.Join(missingHere, ", "))
			}
			if len(missingThere) > 0 {
				parts = append(parts, "it does not pin "+strings.Join(missingThere, ", "))
			}
			if len(o.Unpinned)+len(q.St.Unpinned) > 0 {
				parts = append(parts, "unpinned "+strings.Join(append(append([]string{}, o.Unpinned...), q.St.Unpinned...), ", "))
			}
			line += "comparability unchecked (" + strings.Join(parts, "; ") + ")"
		}
		o.Comparability = append(o.Comparability, line)
	}
	slices.Sort(o.Comparability)
}

func memberKeys(o *canon.Object) []string {
	if o == nil {
		return nil
	}
	k := append([]string{}, o.Keys...)
	slices.Sort(k)
	return k
}

// object returns member k of o as an object; nil when absent or not an object.
func object(o *canon.Object, k string) *canon.Object {
	if o == nil {
		return nil
	}
	v, ok := o.Get(k)
	if !ok {
		return nil
	}
	x, _ := v.(*canon.Object)
	return x
}

// Render is the observation display: a function of the view only.
func (o *Observation) Render() string {
	var b strings.Builder
	fmt.Fprintf(&b, "observed %s by %s: blob %s\n", keylog.Short(o.Statement), shortKey(o.Signer), shortDigest(o.Digest))
	fmt.Fprintf(&b, "  class %s (asserted by %s in %s)\n", o.Class, shortKey(o.Signer), keylog.Short(o.Statement))
	for _, f := range o.Referent {
		fmt.Fprintf(&b, "  referent.%s: %s (observer's statement)\n", f[0], f[1])
	}
	fmt.Fprintf(&b, "  referent status: %s\n", o.ReferentStatus)
	for _, h := range o.ReferentHistory {
		fmt.Fprintf(&b, "    %s\n", h)
	}
	if f := o.Finality; f != nil {
		fmt.Fprintf(&b, "  finality: rule %q, %s", f.Rule, f.Provenance)
		if f.RuleSource != "" {
			fmt.Fprintf(&b, " %s", f.RuleSource)
		}
		fmt.Fprintf(&b, "; state at capture %s\n", f.State)
		for _, id := range f.RuleDocument {
			fmt.Fprintf(&b, "    rule document observed in %s (a source-class observation that can be corroborated)\n", keylog.Short(id))
		}
	}
	c := o.Capture
	fmt.Fprintf(&b, "  capture at %s; evidence %s\n", c.At, c.Display)
	fmt.Fprintf(&b, "  roles: signer %s (statement %s) · operator %s · instrument %s\n", shortKey(o.Signer), keylog.Short(o.Statement),
		declaredLabel(c.Operator), declaredLabel(c.Instrument))
	for _, w := range c.Witnesses {
		if slices.Contains(c.Witnessed, w) {
			fmt.Fprintf(&b, "    witness %s: own observed statement held\n", shortKey(w))
		} else {
			fmt.Fprintf(&b, "    witness %s: named only, no own observed statement held (not counted)\n", shortKey(w))
		}
	}
	for _, x := range o.Others {
		fmt.Fprintf(&b, "  %s\n", x)
	}
	for _, x := range o.Comparability {
		fmt.Fprintf(&b, "  comparability %s\n", x)
	}
	if o.Corroboration != nil {
		b.WriteString(o.Corroboration.render("  "))
	}
	for _, x := range o.Explain {
		fmt.Fprintf(&b, "  explain: %s\n", x)
	}
	return b.String()
}

func declaredLabel(s string) string {
	if s == "" {
		return "undeclared"
	}
	return fmt.Sprintf("%q (declared)", s)
}
