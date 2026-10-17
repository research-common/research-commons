package wire

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

// The per-kind body schema of wire-format note §5: field names, types and presence, nothing more. Field
// semantics (what `match` means, how a rule is evaluated) belong to the resolver and the profiles. Time values
// are checked by checkBodyTimes before this runs; here a ts or date field is only required to be a string.
//
// Rules this file applies everywhere:
//   - an absent R field is malformed (intrinsic), except a class-required referent field of an observed,
//     which is reported as unpinned and admitted (§5, claims-model note §5.3.1);
//   - a present field of the wrong type is malformed, including null where the table does not list it (§1);
//   - unknown fields, at any depth, are retained and ignored (§6);
//   - a list the table calls a set is sorted by the key order of §1 with no duplicates (§1, "arrays");
//   - "exactly one of" means one member present and the others absent.

var (
	reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reKey    = regexp.MustCompile(`^(0x[0-9a-f]{40}|ed25519:[0-9a-f]{64})$`)
	reHex64  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reCommit = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
	// reToken is a revoke_key reason: any bounded token, so a reason this reader does not know is still a
	// well-formed revocation (it reads as hard, claims-model note §4.1) and never fails open as malformed.
	reToken = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// rule checks one value at path. ctx collects unpinned referent fields.
type rule func(v canon.Value, path string, ctx *schemaCtx) error

type schemaCtx struct{ unpinned []string }

type field struct {
	name string
	req  bool
	r    rule
}

func req(name string, r rule) field { return field{name, true, r} }
func opt(name string, r rule) field { return field{name, false, r} }

func bad(path, what string) error { return refusal.Malformed("%s %s", path, what) }

func text() rule {
	return func(v canon.Value, p string, _ *schemaCtx) error {
		if _, ok := v.(canon.String); !ok {
			return bad(p, "is not a string")
		}
		return nil
	}
}

func pattern(re *regexp.Regexp, what string) rule {
	return func(v canon.Value, p string, _ *schemaCtx) error {
		s, ok := v.(canon.String)
		if !ok || !re.MatchString(string(s)) {
			return bad(p, "is not "+what)
		}
		return nil
	}
}

func digest() rule { return pattern(reDigest, "a content digest (sha256: + 64 lowercase hex)") }
func id() rule     { return pattern(reID, "a statement id (64 lowercase hex)") }
func key() rule {
	return pattern(reKey, "a key (ed25519: + 64 lowercase hex, or 0x + 40 lowercase hex)")
}
func ts() rule   { return text() } // value checked by checkBodyTimes
func date() rule { return text() } // value checked by checkBodyTimes

func integer() rule {
	return func(v canon.Value, p string, _ *schemaCtx) error {
		if _, ok := v.(canon.Int); !ok {
			return bad(p, "is not an integer")
		}
		return nil
	}
}

func boolean() rule {
	return func(v canon.Value, p string, _ *schemaCtx) error {
		if _, ok := v.(canon.Bool); !ok {
			return bad(p, "is not a boolean")
		}
		return nil
	}
}

func isTrue() rule {
	return func(v canon.Value, p string, _ *schemaCtx) error {
		if b, ok := v.(canon.Bool); !ok || !bool(b) {
			return bad(p, "is not true")
		}
		return nil
	}
}

func enum(vals ...string) rule {
	return func(v canon.Value, p string, _ *schemaCtx) error {
		s, ok := v.(canon.String)
		if ok {
			for _, x := range vals {
				if string(s) == x {
					return nil
				}
			}
		}
		return bad(p, "is not one of "+strings.Join(vals, ", "))
	}
}

func anyObject() rule {
	return func(v canon.Value, p string, _ *schemaCtx) error {
		if _, ok := v.(*canon.Object); !ok {
			return bad(p, "is not an object")
		}
		return nil
	}
}

// stringMap: an object with free keys whose values are strings (referent.system, licence_texts).
func stringMap() rule {
	return func(v canon.Value, p string, _ *schemaCtx) error {
		o, ok := v.(*canon.Object)
		if !ok {
			return bad(p, "is not an object")
		}
		for _, k := range o.Keys {
			if _, ok := o.Members[k].(canon.String); !ok {
				return bad(p+"."+k, "is not a string")
			}
		}
		return nil
	}
}

func list(elem rule) rule {
	return func(v canon.Value, p string, ctx *schemaCtx) error {
		a, ok := v.(canon.Array)
		if !ok {
			return bad(p, "is not a list")
		}
		for i, e := range a {
			if err := elem(e, p+"["+itoa(i)+"]", ctx); err != nil {
				return err
			}
		}
		return nil
	}
}

// set: a list of strings, each passing elem, sorted by the key order of §1 with no duplicates. nonEmpty
// refuses an empty set where the note implies at least one member.
func set(elem rule, nonEmpty bool) rule {
	return func(v canon.Value, p string, ctx *schemaCtx) error {
		if err := list(elem)(v, p, ctx); err != nil {
			return err
		}
		a := v.(canon.Array)
		if nonEmpty && len(a) == 0 {
			return bad(p, "is an empty set")
		}
		for i := 1; i < len(a); i++ {
			if canon.CompareKeys(string(a[i-1].(canon.String)), string(a[i].(canon.String))) >= 0 {
				return bad(p, "is a set and is not sorted and duplicate-free")
			}
		}
		return nil
	}
}

func object(fields ...field) rule {
	return func(v canon.Value, p string, ctx *schemaCtx) error {
		o, ok := v.(*canon.Object)
		if !ok {
			return bad(p, "is not an object")
		}
		return checkFields(o, p, ctx, fields)
	}
}

func checkFields(o *canon.Object, p string, ctx *schemaCtx, fields []field) error {
	for _, f := range fields {
		fv, present := o.Get(f.name)
		if !present {
			if f.req {
				return bad(p+"."+f.name, "is missing")
			}
			continue
		}
		if err := f.r(fv, p+"."+f.name, ctx); err != nil {
			return err
		}
	}
	return nil
}

// exactlyOne: an object in which exactly one of the alternatives is present (plus any extra fields).
func exactlyOne(alts []field, extra ...field) rule {
	return func(v canon.Value, p string, ctx *schemaCtx) error {
		o, ok := v.(*canon.Object)
		if !ok {
			return bad(p, "is not an object")
		}
		var names []string
		found := 0
		for _, a := range alts {
			names = append(names, a.name)
			if fv, present := o.Get(a.name); present {
				found++
				if err := a.r(fv, p+"."+a.name, ctx); err != nil {
					return err
				}
			}
		}
		if found != 1 {
			return bad(p, "must carry exactly one of "+strings.Join(names, ", "))
		}
		return checkFields(o, p, ctx, extra)
	}
}

func uniqueNames(r rule) rule {
	return func(v canon.Value, p string, ctx *schemaCtx) error {
		if err := r(v, p, ctx); err != nil {
			return err
		}
		seen := map[string]bool{}
		for _, e := range v.(canon.Array) {
			n := string(e.(*canon.Object).Members["name"].(canon.String))
			if seen[n] {
				return bad(p, "names "+n+" twice")
			}
			seen[n] = true
		}
		return nil
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// Shared body objects (§5).
var (
	contentObj = object(req("digest", digest()), req("size", integer()), opt("media_type", text()))
	envObj     = object(opt("image_digest", digest()), opt("platform", text()), opt("harness_commit", pattern(reCommit, "a full lowercase commit hash")))
	provObj    = object(req("workflow", digest()), req("inputs", list(digest())), opt("environment", envObj))
	windowObj  = object(req("from", ts()), req("to", ts()))
	edRef      = object(req("resource", id()), req("edition", id()))
	ruleObj    = exactlyOne([]field{opt("any_one", isTrue()), opt("k_of_n", object(req("k", integer())))})

	disclosures = []field{
		opt("licence", text()),
		opt("licence_texts", stringMap()),
		opt("attribution", text()),
		opt("availability", object(req("redistribution", enum("permitted", "restricted", "withheld")),
			req("obtainable", boolean()), opt("withheld_until", text()))),
		opt("replication", enum("bytes", "protocol", "none")),
		opt("comparator", digest()),
		opt("sampling", object(req("n", integer()), req("unit", text()),
			opt("groups", uniqueNames(list(object(req("name", text()), req("n", integer()))))),
			opt("window", windowObj), opt("dispersion", anyObject()))),
		opt("shelf_life_days", integer()),
		opt("pre_registration", enum("exploratory")),
		opt("fulfills", edRef),
		opt("intended_for", object(req("resource", id()), req("edition", id()), req("edition_applied", id()),
			req("outcome", enum("ok", "unchecked")))),
		opt("description", text()),
	}

	finalityObj = object(req("rule", text()), opt("rule_source", text()),
		req("state_at_capture", exactlyOne([]field{opt("depth", integer()), opt("run", text()), opt("captured_at", ts())})))

	captureObj = object(req("at", ts()),
		req("evidence", enum("self-asserted", "anchored-at-capture", "witnessed", "device-attested")),
		opt("operator", text()), opt("instrument", text()), opt("witnesses", list(key())), opt("attestation", anyObject()))

	taskRef = []field{req("task", id()), req("edition", id())}
)

func with(base []field, more ...field) []field {
	return append(append([]field{}, base...), more...)
}

// kinds is the closed vocabulary of §5, except observed, whose referent depends on its class.
var kinds = map[string][]field{
	"authored": with(disclosures, req("content", contentObj),
		req("type", enum("dataset", "workflow", "skill", "synthesis", "report", "other")),
		opt("provenance", provObj), opt("supersedes", digest()), opt("extends", digest())),
	"holds": {req("content", contentObj), opt("locations", list(text()))},
	"describes": {
		req("about", exactlyOne([]field{opt("content", digest()), opt("statement", id()), opt("resource", id())})),
		opt("tags", list(text())), opt("note", text()),
		opt("links", list(exactlyOne([]field{opt("content", digest()), opt("statement", id()), opt("resource", id()), opt("url", text())},
			req("rel", text())))),
	},
	"reproduced": {req("of", id()), req("result", enum("match", "diverged", "not-comparable")), req("content", contentObj),
		req("provenance", provObj), opt("comparator", digest()), opt("report", digest())},
	"corroborates": {req("of", id()), req("result", id()), req("verdict", enum("supports", "contradicts", "inconclusive")),
		req("model", text()), req("cohort", exactlyOne([]field{opt("rule", text()), opt("hand_picked", isTrue())})),
		opt("shares", list(text())), opt("cause", text())},
	"refutes":  {req("of", id()), req("evidence", digest()), opt("note", text())},
	"retracts": {req("of", id()), opt("reason", text())},
	"anchors":  {req("covered", id()), req("proof", digest()), req("proof_format", text()), opt("services", list(text()))},
	"genesis": {req("type", enum("collection", "task", "series")), req("name", text()), req("controllers", set(key(), false)),
		req("rule", ruleObj), opt("forked_from", id())},
	"edition": {req("resource", id()), req("predecessors", set(id(), true)), req("contents", object(
		opt("members", list(exactlyOne([]field{opt("content", digest()), opt("resource", id()), opt("statement", id())}, req("role", text())))),
		opt("schema", digest()),
		opt("rules", list(object(req("dialect", text()), req("expr", text())))),
		opt("contract", anyObject()),
		opt("selection", enum("curated", "rule-based", "completeness")),
		opt("frozen_before", exactlyOne([]field{opt("date", date()), opt("height", integer()), opt("run", text())})),
		opt("controllers", set(key(), false)),
		opt("rule", ruleObj),
	))},
	"intent":   taskRef,
	"withdraw": taskRef,
	"progress": with(taskRef, opt("note", text())),
	"submit":   with(taskRef, req("result", digest()), opt("salt", text()), opt("self_declared_independence", boolean())),
	"decide": with(taskRef, req("submissions", list(id())), req("verdict", enum("accept", "reject")),
		opt("evaluations", list(digest())), opt("supersedes", id())),
	"withdraw_approval": {req("resource", id()), req("edition", id())},
	"rotate_key":        {req("successor", key())},
	"revoke_key": {req("reason", pattern(reToken, "a reason token ([a-z][a-z0-9_]{0,63})")),
		opt("last_good", id()), opt("note", text())},
}

// Observation classes and the referent fields each requires (§5). A missing one is unpinned, not malformed.
var observedClasses = []string{"exact-bytes", "source", "phenomenon", "method", "none-yet"}

var referentFields = map[string][]field{
	"exact-bytes": {req("chain_id", text()), req("block_hash", pattern(reHex64, "a block hash (64 lowercase hex)")), req("depth", integer())},
	"phenomenon":  {req("instrument", text()), req("location", text()), opt("place", text()), req("at", ts()), opt("timescale", text())},
	"method": {req("method_edition", id()),
		req("environment", object(req("image_digest", digest()), req("platform", text()), req("harness_commit", pattern(reCommit, "a full lowercase commit hash")))),
		req("system", stringMap()), opt("inputs", list(digest())), req("window", windowObj), opt("timescale", text())},
}

var (
	sourceOne   = []field{req("endpoint", text()), req("parameters", anyObject()), req("response_digest", digest())}
	sourceBatch = []field{req("requests", object(req("digest", digest()), req("format", text()), req("count", integer())))}
)

// checkBody applies §5 to a body. known is false for a kind §5 does not list (C-core-13): such a statement is
// stored and grants nothing, so its body is not interpreted. unpinned lists the class-required referent fields
// an observed lacks.
func checkBody(kind string, body *canon.Object) (known bool, unpinned []string, err error) {
	ctx := &schemaCtx{}
	if kind == "observed" {
		err := checkObserved(body, ctx)
		return true, ctx.unpinned, err
	}
	fields, ok := kinds[kind]
	if !ok {
		return false, nil, nil
	}
	if err := checkFields(body, "body", ctx, fields); err != nil {
		return true, nil, err
	}
	if kind == "genesis" {
		return true, nil, satisfiable(body, "body")
	}
	return true, nil, nil
}

// satisfiable refuses a genesis whose rule no set of its controllers can ever meet: no controllers, or a
// k_of_n with k < 1 or k > n. Such a statement cannot mean what its kind means (a resource some key can
// extend), which is the intrinsic class (claims-model §11), and refusing it at the gate is a better answer
// than a resource that silently never accepts an edition. A controller-change edition is checked against the
// previous edition by the resource rules, not here: its controllers and rule are optional and partial.
func satisfiable(body *canon.Object, p string) error {
	ctrl := body.Members["controllers"].(canon.Array)
	if len(ctrl) == 0 {
		return bad(p+".controllers", "is empty: no key could ever extend this resource")
	}
	rule := body.Members["rule"].(*canon.Object)
	if kn, ok := rule.Get("k_of_n"); ok {
		k := int64(kn.(*canon.Object).Members["k"].(canon.Int))
		if k < 1 || k > int64(len(ctrl)) {
			return bad(p+".rule.k_of_n.k", "is "+strconv.FormatInt(k, 10)+" with "+itoa(len(ctrl))+" controllers: no set of controllers satisfies it")
		}
	}
	return nil
}

func checkObserved(body *canon.Object, ctx *schemaCtx) error {
	cv, ok := body.Get("class")
	if !ok {
		return bad("body.class", "is missing")
	}
	if _, isList := cv.(canon.Array); isList {
		return refusal.Malformed("body.class is a list: one class per statement; publish separate blobs (C-core-35)")
	}
	if err := enum(observedClasses...)(cv, "body.class", ctx); err != nil {
		return err
	}
	class := string(cv.(canon.String))
	if _, has := body.Get("finality"); has && class != "exact-bytes" && class != "source" {
		return bad("body.finality", "is allowed on exact-bytes and source observations only, not "+class)
	}
	fields := with(disclosures, req("content", contentObj), req("referent", anyObject()), req("capture", captureObj),
		opt("finality", finalityObj))
	if err := checkFields(body, "body", ctx, fields); err != nil {
		return err
	}
	return checkReferent(body.Members["referent"].(*canon.Object), class, ctx)
}

// checkReferent: present fields must have their type; absent class-required fields are recorded as unpinned.
func checkReferent(ref *canon.Object, class string, ctx *schemaCtx) error {
	const p = "body.referent"
	pinned := func(fields []field) error {
		for _, f := range fields {
			fv, present := ref.Get(f.name)
			if !present {
				if f.req {
					ctx.unpinned = append(ctx.unpinned, "referent."+f.name)
				}
				continue
			}
			sub := &schemaCtx{}
			if err := f.r(fv, p+"."+f.name, sub); err != nil {
				// A nested object missing a required member is unpinned too; a wrong type is malformed.
				if m, ok := missingOnly(fv, f, p); ok {
					ctx.unpinned = append(ctx.unpinned, m...)
					continue
				}
				return err
			}
		}
		return nil
	}
	switch class {
	case "none-yet":
		return nil
	case "source":
		_, batch := ref.Get("requests")
		single := false
		for _, f := range sourceOne {
			if _, ok := ref.Get(f.name); ok {
				single = true
			}
		}
		if batch && single {
			return bad(p, "carries both one request and a batch; a source referent is one or the other")
		}
		if batch {
			return pinned(sourceBatch)
		}
		return pinned(sourceOne)
	default:
		return pinned(referentFields[class])
	}
}

// missingOnly re-checks a nested referent object with its required members relaxed. If that passes, the only
// faults were absent members, which are reported as unpinned paths (C-core-30, C-core-32).
func missingOnly(v canon.Value, f field, p string) ([]string, bool) {
	o, ok := v.(*canon.Object)
	if !ok {
		return nil, false
	}
	var sub []field
	switch f.name {
	case "environment":
		sub = []field{req("image_digest", digest()), req("platform", text()), req("harness_commit", pattern(reCommit, ""))}
	case "window":
		sub = []field{req("from", ts()), req("to", ts())}
	case "requests":
		sub = []field{req("digest", digest()), req("format", text()), req("count", integer())}
	default:
		return nil, false
	}
	var missing []string
	for _, s := range sub {
		fv, present := o.Get(s.name)
		if !present {
			missing = append(missing, "referent."+f.name+"."+s.name)
			continue
		}
		if s.r(fv, p, &schemaCtx{}) != nil {
			return nil, false
		}
	}
	return missing, len(missing) > 0
}
