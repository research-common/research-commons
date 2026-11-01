package wire

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
)

// This file is the CANDIDATE fixed-root identity reader (docs/DESIGN-notes-fixed-root-identity.md). It is
// local and opt-in: Read, the zero Reader, NewReader and Major are unchanged, so every existing consumer still
// retains rc/2 as an unverified other-major line. Nothing here is a frozen wire format.

const (
	// CandidateMajor is the candidate identity major. It is NOT Major: no global flip.
	CandidateMajor = 2
	// IdentityCrit is the only critical extension the candidate profile recognizes.
	IdentityCrit = "x_identity_v1"
	// ActorField is the signed envelope member naming the identity and grant a signature acts for.
	ActorField = "x_actor_v1"
	// FixedRootProfile is the only identity profile this reader understands.
	FixedRootProfile = "fixed-root-v1"

	maxPermissions = 64
	maxSetEntries  = 256
)

// reProfile is an identity profile token (fixed-root-v1 has hyphens; reason tokens do not).
var reProfile = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Invalid: the signature verified over the exact bytes, but the statement breaks a rule this reader checks
// (body schema, times, critical marker, actor). It is retained, attributable evidence, never authority. Only
// IdentityReader produces it; Read still refuses such a line.
const Invalid Status = "invalid"

// Actor is the identity context a signature claims. It is a claim, not authority: an evaluator must still
// check the grant, the root and the lineage. Fields that did not parse are empty.
type Actor struct {
	Identity, Grant string
}

// IdentityReader reads rc/1 exactly as Read does for valid lines, plus the candidate rc/2, with one deliberate
// difference: it verifies the signature BEFORE interpreting anything the signer could get wrong (ts, body,
// crit, marker, actor). A verified line that breaks such a rule is returned with Status Invalid instead of
// being refused, so an authentic but malformed root control stays visible as non-passing evidence instead of
// disappearing and turning a denial into a pass. Lines whose linkage envelope (rc, kind, signer, alg, seq,
// prev, merges) or signature is malformed are still refused: no reader can place them.
type IdentityReader struct{}

// NewIdentityReader returns the candidate reader. It has no configuration and no extension registry.
func NewIdentityReader() *IdentityReader { return &IdentityReader{} }

// Read parses one received line. See IdentityReader.
func (r *IdentityReader) Read(line []byte) (*Statement, error) {
	if len(line) > MaxLine {
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
			Detail: "size limit " + strconv.Itoa(MaxSignedString) + " (line of " + strconv.Itoa(len(line)) + " bytes refused before parsing)"}
	}
	v, err := canon.Parse(line)
	if err != nil {
		return nil, err
	}
	full, ok := v.(*canon.Object)
	if !ok {
		return nil, refusal.Malformed("top level is not an object")
	}
	sigV, ok := full.Get("sig")
	if !ok {
		return nil, refusal.Malformed("missing sig")
	}
	sigS, ok := sigV.(canon.String)
	if !ok {
		return nil, refusal.Malformed("sig is not a string")
	}
	env := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range full.Keys {
		if k != "sig" {
			env.Keys = append(env.Keys, k)
			env.Members[k] = full.Members[k]
		}
	}
	s := &Statement{env: env, Status: Valid}
	rc, err := str(env, "rc")
	if err != nil {
		return nil, err
	}
	m := reRC.FindStringSubmatch(rc)
	if m == nil {
		return nil, refusal.Malformed("rc %q is not rc/<positive integer>", rc)
	}
	major, err := strconv.Atoi(m[1])
	if err != nil || major < 1 {
		return nil, refusal.Malformed("rc %q is not rc/<positive integer>", rc)
	}
	s.RC = rc
	if major != Major && major != CandidateMajor {
		return otherMajor(s, env, major, string(sigS))
	}
	if err := linkageEnvelope(s, env); err != nil {
		return nil, err
	}
	s.SignedString = PAE(PayloadType(s.Kind, major), canon.Encode(env))
	if len(s.SignedString) > MaxSignedString {
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: refusal.SizeLimit,
			Detail: "size limit " + strconv.Itoa(MaxSignedString)}
	}
	s.ID = ID(s.SignedString)
	switch s.Alg {
	case AlgEIP191, AlgEd25519:
	default:
		s.Status, s.Why, s.Sig = Unsupported, "alg "+s.Alg, string(sigS)
		return s, nil
	}
	if err := s.verify(string(sigS)); err != nil {
		return nil, err
	}
	s.Verified = true
	// Everything below is attributable to the signer: a failure marks the statement, it does not drop it.
	var st Status
	var why string
	if major == Major {
		st, why = interpretV1(s, env)
	} else {
		st, why = interpretCandidate(s, env)
	}
	if st != Valid {
		s.Status, s.Why = st, why
	}
	return s, nil
}

// linkageEnvelope reads the fields every placement needs. A failure here is a refusal, as in Read.
func linkageEnvelope(s *Statement, env *canon.Object) error {
	var err error
	if s.Kind, err = str(env, "kind"); err != nil {
		return err
	}
	if !reKind.MatchString(s.Kind) {
		return refusal.Malformed("kind %q", s.Kind)
	}
	if s.Signer, err = str(env, "signer"); err != nil {
		return err
	}
	if s.Alg, err = str(env, "alg"); err != nil {
		return err
	}
	isAddr, isEd := reAddr.MatchString(s.Signer), reEdKey.MatchString(s.Signer)
	if !isAddr && !isEd {
		return refusal.Malformed("signer %q is neither 0x + 40 lowercase hex nor ed25519: + 64 lowercase hex", s.Signer)
	}
	switch {
	case s.Alg == AlgEIP191 && !isAddr, s.Alg == AlgEd25519 && !isEd:
		return refusal.Malformed("alg %s with signer %s", s.Alg, s.Signer)
	}
	seqV, ok := env.Get("seq")
	if !ok {
		return refusal.Malformed("missing envelope field %q", "seq")
	}
	seq, ok := seqV.(canon.Int)
	if !ok || seq < 0 {
		return refusal.Malformed("seq is not a non-negative integer")
	}
	s.Seq = int64(seq)
	prevV, ok := env.Get("prev")
	if !ok {
		return refusal.Malformed("missing envelope field %q", "prev")
	}
	switch p := prevV.(type) {
	case canon.Null:
		if s.Seq != 0 {
			return refusal.Malformed("prev null at seq %d", s.Seq)
		}
	case canon.String:
		if !reID.MatchString(string(p)) {
			return refusal.Malformed("prev %q is not a statement id", string(p))
		}
		if s.Seq == 0 {
			return refusal.Malformed("prev set at seq 0")
		}
		s.Prev = string(p)
	default:
		return refusal.Malformed("prev is neither null nor a string")
	}
	if mv, present := env.Get("merges"); present {
		if s.Merges, err = mergesList(mv, s.Seq, s.Prev); err != nil {
			return err
		}
	}
	return nil
}

// common reads body, crit and ts. ok=false means the statement is Invalid with the returned reason. The body is
// kept before ts or crit can fail, so an authenticated-invalid control keeps its readable binding (a cut with a bad
// time is still addressed to its grant).
func common(s *Statement, env *canon.Object) (string, bool) {
	bodyV, ok := env.Get("body")
	if !ok {
		return "missing envelope field \"body\"", false
	}
	body, ok := bodyV.(*canon.Object)
	if !ok {
		return "body is not an object", false
	}
	s.Body = body
	tsV, ok := env.Get("ts")
	if !ok {
		return "missing envelope field \"ts\"", false
	}
	tsS, ok := tsV.(canon.String)
	if !ok {
		return "ts is not a string", false
	}
	t, err := rctime.ParseUTC(string(tsS))
	if err != nil {
		return err.Error(), false
	}
	s.TS = t
	if c, present := env.Get("crit"); present {
		crit, err := critList(c, body)
		if err != nil {
			return err.Error(), false
		}
		s.Crit = crit
	}
	return "", true
}

// interpretV1 is Read's evaluation of an rc/1 line, after verification. The identity reader registers no rc/1
// extension, so any crit (including x_identity_v1, which this profile does not admit in rc/1) is Unsupported.
// An rc/1 envelope actor is NOT read: rc/1 is never upgraded to an identity act.
func interpretV1(s *Statement, env *canon.Object) (Status, string) {
	if why, ok := common(s, env); !ok {
		return Invalid, why
	}
	if len(s.Crit) > 0 {
		return Unsupported, "crit " + strings.Join(s.Crit, ",")
	}
	return baseBody(s)
}

func baseBody(s *Statement) (Status, string) {
	known, unpinned, err := checkBody(s.Kind, s.Body)
	if err != nil {
		return Invalid, err.Error()
	}
	if err := checkBodyTimes(s.Kind, s.Body); err != nil {
		return Invalid, err.Error()
	}
	s.Unpinned = unpinned
	if !known {
		return UnknownKind, s.Kind
	}
	return Valid, ""
}

// candidateNotImplemented are rc/2 kinds the profile defines but this slice does not evaluate (typed resource
// controllers, major-aware edition ids, task roles and contracts). They are verified and non-passing.
var candidateNotImplemented = map[string]bool{
	"genesis": true, "edition": true, "withdraw_approval": true,
	"intent": true, "withdraw": true, "progress": true, "submit": true, "decide": true,
}

// candidateBase are rc/2 kinds whose body is the unchanged rc/1 base schema plus the marker.
var candidateBase = map[string]bool{
	"authored": true, "observed": true, "holds": true, "reproduced": true, "corroborates": true,
	"refutes": true, "retracts": true, "anchors": true, "describes": true,
}

func interpretCandidate(s *Statement, env *canon.Object) (Status, string) {
	// The actor is read first so that a later failure still reports an invalid identity context, never a bare key.
	actorWhy := candidateActor(s, env)
	why, ok := common(s, env)
	switch {
	case actorWhy != "":
		return Invalid, actorWhy
	case !ok:
		return Invalid, why
	case len(s.Merges) > maxSetEntries:
		// Profile syntax cap, rc/2 only (rc/1 and the default readers are unchanged).
		return Invalid, "merges has more than " + strconv.Itoa(maxSetEntries) + " entries"
	}
	return candidateBody(s)
}

// candidateActor reads x_actor_v1 when present. A non-empty result is the reason the statement is Invalid; s.Actor
// is set whenever the field is present, even malformed, so the line keeps an identity context.
func candidateActor(s *Statement, env *canon.Object) string {
	av, ok := env.Get(ActorField)
	if !ok {
		return ""
	}
	s.Actor = &Actor{}
	ao, ok := av.(*canon.Object)
	if !ok {
		return ActorField + " is not an object"
	}
	if why := closed(ao, ActorField, "identity", "grant"); why != "" {
		return why
	}
	s.Actor.Identity, _ = idValue(ao, "identity")
	s.Actor.Grant, _ = idValue(ao, "grant")
	if s.Actor.Identity == "" || s.Actor.Grant == "" {
		return ActorField + " needs identity and grant statement ids"
	}
	return ""
}

func candidateBody(s *Statement) (Status, string) {
	switch {
	case len(s.Crit) == 0:
		return Invalid, "rc/2 requires crit [" + IdentityCrit + "]"
	case !slices.Contains(s.Crit, IdentityCrit):
		return Invalid, "rc/2 crit lacks " + IdentityCrit
	case len(s.Crit) != 1:
		return Unsupported, "crit " + strings.Join(s.Crit, ",")
	}
	markerV, _ := s.Body.Get(IdentityCrit)
	marker, ok := markerV.(*canon.Object)
	if !ok {
		return Invalid, "body." + IdentityCrit + " is not an object"
	}
	admin := s.Kind == "identity_inception" || s.Kind == "identity_grant" || s.Kind == "identity_cut"
	if s.Actor != nil && (admin || s.Kind == "genesis" || s.Kind == "describes") {
		return Invalid, s.Kind + " is a raw-key statement and takes no " + ActorField
	}
	switch {
	case s.Kind == "identity_inception":
		return inceptionBody(s, marker)
	case s.Kind == "identity_grant":
		return grantBody(s, marker)
	case s.Kind == "identity_cut":
		return cutBody(s, marker)
	case s.Kind == "rotate_key" || s.Kind == "revoke_key":
		return Invalid, "raw key events stay rc/1 in this profile"
	case candidateNotImplemented[s.Kind]:
		return Unsupported, "rc/2 " + s.Kind + " not implemented by this reader"
	case candidateBase[s.Kind]:
		if s.Kind == "authored" || s.Kind == "observed" {
			if why := closed(marker, "body."+IdentityCrit, "amends"); why != "" {
				return Invalid, why
			}
			if av, ok := marker.Get("amends"); ok {
				if err := boundedSet(av, "body."+IdentityCrit+".amends", id()); err != nil {
					return Invalid, err.Error()
				}
				if s.Actor == nil {
					return Invalid, "amends requires an identity actor"
				}
			}
		} else if len(marker.Keys) != 0 {
			return Invalid, "body." + IdentityCrit + " must be {} for " + s.Kind
		}
		return baseBody(s)
	default:
		return UnknownKind, s.Kind
	}
}

func inceptionBody(s *Statement, marker *canon.Object) (Status, string) {
	if len(marker.Keys) != 0 {
		return Invalid, "body." + IdentityCrit + " must be {}"
	}
	if s.Seq != 0 {
		return Invalid, "identity_inception must be seq 0"
	}
	p, ok := s.Body.Get("profile")
	ps, isStr := p.(canon.String)
	if !ok || !isStr || !reProfile.MatchString(string(ps)) {
		return Invalid, "body.profile is not a profile token"
	}
	if string(ps) != FixedRootProfile {
		return Unsupported, "identity profile " + string(ps)
	}
	return Valid, ""
}

func grantBody(s *Statement, marker *canon.Object) (Status, string) {
	if len(marker.Keys) != 0 {
		return Invalid, "body." + IdentityCrit + " must be {}"
	}
	if s.Seq < 1 {
		return Invalid, "identity_grant must follow the identity inception"
	}
	if _, ok := idValue(s.Body, "identity"); !ok {
		return Invalid, "body.identity is not a statement id"
	}
	dv, _ := s.Body.Get("delegate")
	d, ok := dv.(*canon.Object)
	if !ok {
		return Invalid, "body.delegate is not an object"
	}
	if why := closed(d, "body.delegate", "key", "inception"); why != "" {
		return Invalid, why
	}
	kv, ok := d.Get("key")
	if !ok || key()(kv, "body.delegate.key", &schemaCtx{}) != nil {
		return Invalid, "body.delegate.key is not a key"
	}
	if string(kv.(canon.String)) == s.Signer {
		return Invalid, "a dedicated root cannot grant to itself"
	}
	if _, ok := idValue(d, "inception"); !ok {
		return Invalid, "body.delegate.inception is not a statement id"
	}
	pv, _ := s.Body.Get("permissions")
	ps, ok := pv.(canon.Array)
	if !ok || len(ps) == 0 || len(ps) > maxPermissions {
		return Invalid, "body.permissions is not a list of 1.." + strconv.Itoa(maxPermissions) + " permissions"
	}
	unknown := ""
	for i, p := range ps {
		path := "body.permissions[" + strconv.Itoa(i) + "]"
		k, why := permission(p, path)
		if why != "" {
			return Invalid, why
		}
		if k != "" && unknown == "" {
			unknown = k
		}
		if i > 0 && canon.CompareKeys(string(canon.Encode(ps[i-1])), string(canon.Encode(p))) >= 0 {
			return Invalid, "body.permissions is not sorted and duplicate-free"
		}
	}
	if unknown != "" {
		return Unsupported, "permission kind " + unknown
	}
	return Valid, ""
}

// PermissionDomain returns the target domain of a permission kind in the candidate profile's closed registry
// (§3), or "" for a kind the registry does not hold. The registry itself is not exported, so no importer can
// widen it at run time.
func PermissionDomain(kind string) string { return permissionDomains[kind] }

var permissionDomains = map[string]string{
	"authored": "contents", "observed": "contents", "holds": "contents",
	"reproduced": "statements", "corroborates": "statements", "refutes": "statements", "retracts": "statements",
	"edition": "resources", "withdraw_approval": "resources",
	"intent": "tasks", "withdraw": "tasks", "progress": "tasks", "submit": "tasks", "decide": "tasks",
	"anchors": "log",
}

// nonDelegable are known kinds a grant can never carry: they are definitely invalid, not merely unknown.
var nonDelegable = map[string]bool{
	"identity_inception": true, "identity_grant": true, "identity_cut": true,
	"rotate_key": true, "revoke_key": true, "genesis": true, "describes": true,
}

// permission checks one entry. It returns the kind when the kind is unknown (the grant is then Unsupported,
// never broader), or a reason when the entry is malformed.
func permission(v canon.Value, p string) (unknownKind, why string) {
	o, ok := v.(*canon.Object)
	if !ok {
		return "", p + " is not an object"
	}
	kv, _ := o.Get("kind")
	ks, ok := kv.(canon.String)
	if !ok || !reKind.MatchString(string(ks)) {
		return "", p + ".kind is not a kind"
	}
	kind := string(ks)
	domain, known := permissionDomains[kind]
	if nonDelegable[kind] {
		return "", p + ".kind " + kind + " is never delegable (root administration, key events, genesis, describes)"
	}
	if !known {
		return kind, ""
	}
	amend := kind == "authored" || kind == "observed"
	allowed := []string{"kind", "targets"}
	switch {
	case domain == "log":
		allowed = []string{"kind"}
	case amend:
		allowed = append(allowed, "amend")
	}
	if why := closed(o, p, allowed...); why != "" {
		return "", why
	}
	if amend {
		av, ok := o.Get("amend")
		if _, isBool := av.(canon.Bool); !ok || !isBool {
			return "", p + ".amend is required and boolean"
		}
	}
	if domain == "log" {
		return "", ""
	}
	tv, ok := o.Get("targets")
	t, isObj := tv.(*canon.Object)
	if !ok || !isObj || len(t.Keys) != 1 {
		return "", p + ".targets must be an object with exactly one target mode"
	}
	mode := t.Keys[0]
	elem := id()
	switch {
	case domain == "contents" && mode == "any_content", domain == "statements" && mode == "any_statement":
		if b, ok := t.Members[mode].(canon.Bool); !ok || !bool(b) {
			return "", p + ".targets." + mode + " is not true"
		}
		return "", ""
	case mode != domain:
		return "", p + ".targets." + mode + " is not a target mode for " + kind
	case domain == "contents":
		elem = digest()
	}
	if err := boundedSet(t.Members[mode], p+".targets."+mode, elem); err != nil {
		return "", err.Error()
	}
	return "", ""
}

func cutBody(s *Statement, marker *canon.Object) (Status, string) {
	if len(marker.Keys) != 0 {
		return Invalid, "body." + IdentityCrit + " must be {}"
	}
	if s.Seq < 1 {
		return Invalid, "identity_cut must follow the identity inception"
	}
	if _, ok := idValue(s.Body, "identity"); !ok {
		return Invalid, "body.identity is not a statement id"
	}
	if _, ok := idValue(s.Body, "grant"); !ok {
		return Invalid, "body.grant is not a statement id"
	}
	lv, ok := s.Body.Get("last_good")
	if !ok {
		return Invalid, "body.last_good is required (null preserves nothing)"
	}
	if _, isNull := lv.(canon.Null); !isNull {
		if _, ok := idValue(s.Body, "last_good"); !ok {
			return Invalid, "body.last_good is neither null nor a statement id"
		}
	}
	rv, _ := s.Body.Get("reason")
	if rs, ok := rv.(canon.String); !ok || !reToken.MatchString(string(rs)) {
		return Invalid, "body.reason is not a reason token"
	}
	return Valid, ""
}

func closed(o *canon.Object, p string, allowed ...string) string {
	for _, k := range o.Keys {
		if !slices.Contains(allowed, k) {
			return p + "." + k + " is not a member of this closed object"
		}
	}
	return ""
}

func idValue(o *canon.Object, k string) (string, bool) {
	if o == nil {
		return "", false
	}
	v, ok := o.Get(k)
	s, isStr := v.(canon.String)
	if !ok || !isStr || !reID.MatchString(string(s)) {
		return "", false
	}
	return string(s), true
}

func boundedSet(v canon.Value, p string, elem rule) error {
	if err := set(elem, true)(v, p, &schemaCtx{}); err != nil {
		return err
	}
	if len(v.(canon.Array)) > maxSetEntries {
		return bad(p, "has more than "+strconv.Itoa(maxSetEntries)+" entries")
	}
	return nil
}
