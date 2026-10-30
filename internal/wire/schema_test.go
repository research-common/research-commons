package wire

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

var (
	tID  = strings.Repeat("ab", 32)
	tID2 = strings.Repeat("cd", 32)
	tDig = "sha256:" + strings.Repeat("ef", 32)
	tKey = "0x" + strings.Repeat("12", 20)
	tTS  = "2026-10-15T00:00:00Z"
)

func arr(vs ...canon.Value) canon.Array { return canon.Array(vs) }
func s(x string) canon.String           { return canon.String(x) }

// minimal returns a body for kind holding every R field and no O field (§5).
func minimal(kind string) *canon.Object {
	c := content("ab", 10)
	switch kind {
	case "authored":
		return body("content", c, "type", "dataset")
	case "observed":
		return body("content", c, "class", "none-yet", "referent", body(), "capture", body("at", tTS, "evidence", "self-asserted"))
	case "holds":
		return body("content", c)
	case "describes":
		return body("about", body("content", tDig))
	case "reproduced":
		return body("of", tID, "result", "match", "content", c, "provenance", body("workflow", tDig, "inputs", arr()))
	case "corroborates":
		return body("of", tID, "result", tID2, "verdict", "supports", "model", "exact-bytes/1", "cohort", body("rule", "any"))
	case "refutes":
		return body("of", tID, "evidence", tDig)
	case "retracts":
		return body("of", tID)
	case "anchors":
		return body("covered", tID, "proof", tDig, "proof_format", "ots-detached-v1")
	case "genesis":
		return body("type", "collection", "name", "n", "controllers", arr(s(tKey)), "rule", body("any_one", canon.Bool(true)))
	case "edition":
		return body("resource", tID, "predecessors", arr(s(tID)), "contents", body())
	case "intent", "progress", "withdraw":
		return body("task", tID, "edition", tID2)
	case "submit":
		return body("task", tID, "edition", tID2, "result", tDig)
	case "decide":
		return body("task", tID, "edition", tID2, "submissions", arr(s(tID)), "verdict", "accept")
	case "withdraw_approval":
		return body("resource", tID, "edition", tID2)
	case "rotate_key":
		return body("successor", tKey)
	case "revoke_key":
		return body("reason", "superseded")
	}
	panic(kind)
}

func allKinds() []string {
	ks := []string{"observed"}
	for k := range kinds {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

func readBody(t *testing.T, kind string, b *canon.Object) (*Statement, error) {
	t.Helper()
	line, _ := Sign(Draft{Kind: kind, TS: tTS, Body: b}, testKeys("A")["A"])
	return Read(line)
}

func clone(o *canon.Object) *canon.Object {
	v, _ := canon.Parse(canon.Encode(o))
	return v.(*canon.Object)
}

func setField(o *canon.Object, k string, v canon.Value) *canon.Object {
	o = clone(o)
	if _, ok := o.Members[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.Members[k] = v
	return o
}

func dropField(o *canon.Object, k string) *canon.Object {
	o = clone(o)
	delete(o.Members, k)
	o.Keys = deleteKey(o.Keys, k)
	return o
}

// TestSchemaMinimalBodies: every kind of §5 with only its R fields is valid; adding an unknown field (top level
// or nested) changes nothing but the id (§6).
func TestSchemaMinimalBodies(t *testing.T) {
	for _, k := range allKinds() {
		st, err := readBody(t, k, minimal(k))
		if err != nil || st.Status != Valid || len(st.Unpinned) != 0 {
			t.Fatalf("%s: %v %+v", k, err, st)
		}
		if st, err := readBody(t, k, setField(minimal(k), "x_extra", canon.Null{})); err != nil || st.Status != Valid {
			t.Fatalf("%s with an unknown field: %v", k, err)
		}
	}
	nested := setField(minimal("authored"), "content", setField(content("ab", 10), "x_ext", s("v")))
	if _, err := readBody(t, "authored", nested); err != nil {
		t.Fatalf("unknown nested field refused: %v", err)
	}
}

// TestSchemaMissingRequired: dropping any R field of any kind is a malformed statement naming the field. The
// one exception (observed referent fields) is TestSchemaUnpinned.
func TestSchemaMissingRequired(t *testing.T) {
	conformance.Partial(t, "C-core-109", "one validation core: every R field is checked by Read, the only entry point; the four gates calling it (pull, hub CI, push, pre-pin) are not built")
	for _, k := range allKinds() {
		m := minimal(k)
		for _, f := range m.Keys {
			_, err := readBody(t, k, dropField(m, f))
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "body."+f+" is missing")
		}
	}
}

// TestSchemaNullAndWrongType: null is refused for every field the table defines (§1: null only where listed,
// and §5 lists it nowhere), present or added. A wrong type is refused the same way.
func TestSchemaNullAndWrongType(t *testing.T) {
	for _, k := range allKinds() {
		fields := kinds[k]
		if k == "observed" {
			fields = with(disclosures, req("content", nil), req("class", nil), req("referent", nil), req("capture", nil), opt("finality", nil))
		}
		for _, f := range fields {
			_, err := readBody(t, k, setField(minimal(k), f.name, canon.Null{}))
			if err == nil {
				t.Fatalf("%s.%s: null accepted", k, f.name)
			}
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "body."+f.name)
			_, err = readBody(t, k, setField(minimal(k), f.name, arr(canon.Bool(true))))
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "body."+f.name)
		}
	}
}

// TestSchemaRules: the table's specific type rules, one row each, every one signed validly so only §5 refuses.
func TestSchemaRules(t *testing.T) {
	m := minimal
	for _, c := range []struct {
		name, kind string
		b          *canon.Object
		detail     string
	}{
		{"digest upper case", "authored", setField(m("authored"), "content", body("digest", "sha256:"+strings.Repeat("EF", 32), "size", 1)), "content digest"},
		{"digest without prefix", "refutes", setField(m("refutes"), "evidence", s(strings.Repeat("ef", 32))), "content digest"},
		{"digest other alg", "refutes", setField(m("refutes"), "evidence", s("sha512:"+strings.Repeat("ef", 32))), "content digest"},
		{"id with a prefix", "retracts", setField(m("retracts"), "of", s("sha256:"+tID)), "statement id"},
		{"id as a 12-char alias (§3)", "retracts", setField(m("retracts"), "of", s(tID[:12])), "statement id"},
		{"holds withdrawn false", "holds", setField(m("holds"), "withdrawn", canon.Bool(false)), "is not true"},
		{"holds withdrawn with locations", "holds", setField(setField(m("holds"), "withdrawn", canon.Bool(true)), "locations", arr(s("https://x.example"))), "withdrawn"},
		{"size as a string", "holds", setField(m("holds"), "content", body("digest", tDig, "size", "10")), "size is not an integer"},
		{"type not in vocabulary", "authored", setField(m("authored"), "type", s("Dataset")), "one of"},
		{"availability without obtainable", "authored", setField(m("authored"), "availability", body("redistribution", "permitted")), "obtainable is missing"},
		{"replication unknown token", "authored", setField(m("authored"), "replication", s("exact")), "one of"},
		{"sampling without unit", "authored", setField(m("authored"), "sampling", body("n", 30)), "unit is missing"},
		{"sampling groups repeat a name", "authored", setField(m("authored"), "sampling", body("n", 2, "unit", "runs",
			"groups", arr(body("name", "a", "n", 1), body("name", "a", "n", 1)))), "names a twice"},
		{"intended_for outcome fail", "authored", setField(m("authored"), "intended_for", body("resource", tID, "edition", tID,
			"edition_applied", tID, "outcome", "fail")), "one of ok, unchecked"},
		{"pre_registration other than exploratory", "authored", setField(m("authored"), "pre_registration", s("confirmatory")), "exploratory"},
		{"licence_texts value not a string", "authored", setField(m("authored"), "licence_texts", body("LicenseRef-X", 1)), "LicenseRef-X is not a string"},
		{"harness_commit abbreviated", "authored", setField(m("authored"), "provenance", body("workflow", tDig, "inputs", arr(),
			"environment", body("harness_commit", "abc1234"))), "commit hash"},
		{"about carries two", "describes", setField(m("describes"), "about", body("content", tDig, "statement", tID)), "exactly one"},
		{"about carries none", "describes", setField(m("describes"), "about", body()), "exactly one"},
		{"link without rel", "describes", setField(m("describes"), "links", arr(body("url", "https://x.example"))), "rel is missing"},
		{"link with two targets", "describes", setField(m("describes"), "links", arr(body("rel", "related", "url", "u", "statement", tID))), "exactly one"},
		{"controllers unsorted", "genesis", setField(m("genesis"), "controllers", arr(s("0x"+strings.Repeat("ff", 20)), s(tKey))), "not sorted"},
		{"controllers duplicate", "genesis", setField(m("genesis"), "controllers", arr(s(tKey), s(tKey))), "not sorted"},
		{"controller not a key", "genesis", setField(m("genesis"), "controllers", arr(s("0x"+strings.Repeat("AB", 20)))), "is not a key"},
		{"rule with both forms", "genesis", setField(m("genesis"), "rule", body("any_one", canon.Bool(true), "k_of_n", body("k", 1))), "exactly one"},
		{"controllers empty", "genesis", setField(m("genesis"), "controllers", arr()), "is empty"},
		{"k_of_n k zero", "genesis", setField(m("genesis"), "rule", body("k_of_n", body("k", 0))), "no set of controllers"},
		{"k_of_n k above n", "genesis", setField(m("genesis"), "rule", body("k_of_n", body("k", 2))), "is 2 with 1 controllers"},
		{"rule any_one false", "genesis", setField(m("genesis"), "rule", body("any_one", canon.Bool(false))), "is not true"},
		{"predecessors empty", "edition", setField(m("edition"), "predecessors", arr()), "empty set"},
		{"predecessors unsorted", "edition", setField(m("edition"), "predecessors", arr(s(tID2), s(tID))), "not sorted"},
		{"frozen_before two units", "edition", setField(m("edition"), "contents", body("frozen_before", body("date", "2026-01-01", "height", 5))), "exactly one"},
		{"member without role", "edition", setField(m("edition"), "contents", body("members", arr(body("content", tDig)))), "role is missing"},
		{"selection unknown", "edition", setField(m("edition"), "contents", body("selection", "manual")), "one of"},
		{"cohort hand_picked false", "corroborates", setField(m("corroborates"), "cohort", body("hand_picked", canon.Bool(false))), "is not true"},
		{"verdict unknown", "decide", setField(m("decide"), "verdict", s("maybe")), "one of"},
		{"anchors proof as an object (first draft)", "anchors", setField(m("anchors"), "proof", body("scheme", "ots", "digest", tDig)), "content digest"},
		{"anchors covered as a digest", "anchors", setField(m("anchors"), "covered", s(tDig)), "statement id"},
		{"anchors without proof_format", "anchors", body("covered", tID, "proof", tDig), "proof_format is missing"},
		{"revocation reason outside the token pattern", "revoke_key", setField(m("revoke_key"), "reason", s("Affiliation Changed")), "reason token"},
		{"successor upper case", "rotate_key", setField(m("rotate_key"), "successor", s("ed25519:"+strings.Repeat("AB", 32))), "is not a key"},
		{"capture evidence unknown", "observed", setField(m("observed"), "capture", body("at", tTS, "evidence", "notarised")), "one of"},
		{"class unknown", "observed", setField(m("observed"), "class", s("exact")), "one of"},
		{"finality on phenomenon", "observed", setField(setField(m("observed"), "class", s("phenomenon")), "finality",
			body("rule", "r", "state_at_capture", body("depth", 1))), "exact-bytes and source observations only"},
		{"finality state with two units", "observed", setField(setField(m("observed"), "class", s("source")), "finality",
			body("rule", "r", "state_at_capture", body("depth", 1, "run", "R1"))), "exactly one"},
		{"source with one request and a batch", "observed", setField(setField(m("observed"), "class", s("source")), "referent",
			body("endpoint", "e", "requests", body("digest", tDig, "format", "f", "count", 1))), "one or the other"},
		{"referent field wrong type", "observed", setField(setField(m("observed"), "class", s("exact-bytes")), "referent",
			body("chain_id", "bip122:x", "block_hash", strings.Repeat("AA", 32), "depth", 3)), "block hash"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := readBody(t, c.kind, c.b)
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, c.detail)
		})
	}
}

// TestSchemaOneClass: an observed asserting two classes is malformed, and the refusal says what to do.
func TestSchemaOneClass(t *testing.T) {
	conformance.Partial(t, "C-core-35", "Read refuses (intrinsic, malformed, this statement only, says to publish separate blobs); publish pinning and appending nothing needs publish")
	_, err := readBody(t, "observed", setField(minimal("observed"), "class", arr(s("exact-bytes"), s("source"))))
	refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "publish separate blobs")
}

// TestSchemaUnpinned: an observed whose referent lacks a field its class requires is valid and admitted, with
// the missing fields named (§5, claims-model §5.3.1). A field present with the wrong type is still malformed.
func TestSchemaUnpinned(t *testing.T) {
	conformance.Partial(t, "C-core-30", "admitted and the missing block_hash named as unpinned; the agreement model not applied and corroboration unchecked need the resolver")
	obs := func(class string, ref *canon.Object) *canon.Object {
		return setField(setField(minimal("observed"), "class", s(class)), "referent", ref)
	}
	for _, c := range []struct {
		name string
		b    *canon.Object
		want []string
	}{
		{"exact-bytes with height, no hash", obs("exact-bytes", body("chain_id", "bip122:000000000019d6689c085ae165831e93", "height", 5, "depth", 3)), []string{"referent.block_hash"}},
		{"phenomenon without location", obs("phenomenon", body("instrument", "daq", "at", "2026-10-15T00:00:00Z")), []string{"referent.location"}},
		{"method without environment.platform", obs("method", body("method_edition", tID, "environment", body("image_digest", tDig, "harness_commit", strings.Repeat("a", 40)),
			"system", body("model", "m"), "window", body("from", tTS, "to", tTS))), []string{"referent.environment.platform"}},
		{"source batch without count", obs("source", body("requests", body("digest", tDig, "format", "jsonl"))), []string{"referent.requests.count"}},
		{"source single empty", obs("source", body()), []string{"referent.endpoint", "referent.parameters", "referent.response_digest"}},
		{"none-yet takes anything", obs("none-yet", body("anything", 1)), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			st, err := readBody(t, "observed", c.b)
			if err != nil || st.Status != Valid || !slices.Equal(st.Unpinned, c.want) {
				t.Fatalf("got %v, unpinned %v, want valid with %v", err, st.Unpinned, c.want)
			}
		})
	}
}

// TestSchemaUnknownKind: a validly signed statement of an unlisted kind is verified, stored as an unknown
// kind, and its body is not interpreted (C-core-13).
func TestSchemaUnknownKind(t *testing.T) {
	conformance.Partial(t, "C-core-13", "verified and marked unknown kind at the wire layer; defaults, grade, membership and verify exit unchanged need the resolver")
	st, err := readBody(t, "endorses", body("content", "not even a digest", "licence", 7, "member_of", tID))
	if err != nil || st.Status != UnknownKind || st.Why != "endorses" || !st.Verified {
		t.Fatalf("%v %+v", err, st)
	}
}

// TestMergesEnvelope: the line-local rules of §7 for merges. The rules that need the log (same key, lower
// seq, held) are package keylog's.
func TestMergesEnvelope(t *testing.T) {
	k := testKeys("A")["A"]
	mk := func(seq int64, prev string, merges ...string) Draft {
		d := authoredDraft(seq, prev)
		d.Merges = merges
		return d
	}
	line, _ := Sign(mk(2, tID, tID2), k)
	st, err := Read(line)
	if err != nil || !slices.Equal(st.Merges, []string{tID2}) {
		t.Fatalf("valid merges: %v %v", err, st)
	}
	lo, hi := strings.Repeat("11", 32), strings.Repeat("ee", 32)
	for _, c := range []struct {
		name   string
		d      Draft
		detail string
	}{
		{"names prev", mk(2, tID, tID), "contains prev"},
		{"duplicate", mk(2, tID, lo, lo), "sorted and duplicate-free"},
		{"unsorted", mk(2, tID, hi, lo), "sorted and duplicate-free"},
		{"not an id", mk(2, tID, tID2[:12]), "not a statement id"},
		{"at seq 0", mk(0, "", tID2), "merges at seq 0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			line, _ := Sign(c.d, k)
			_, err := Read(line)
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, c.detail)
		})
	}
	// An empty list is malformed too: absent and empty are different (§1, null vs absent).
	env := mk(2, tID).Envelope(k)
	env.Keys = append(env.Keys, "merges")
	env.Members["merges"] = canon.Array{}
	ss := PAE(PayloadType("authored", Major), canon.Encode(env))
	env.Keys = append(env.Keys, "sig")
	env.Members["sig"] = canon.String(k.Sign(ss))
	_, err = Read(canon.Encode(env))
	refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "non-empty list")
}

// TestRevokeReasonToken: wire-format note §5. `reason` is any bounded token, so undocumented values
// (`unspecified`, a vendor value, one a later revision adds) are well-formed and never drop the revocation; a
// value outside the pattern is malformed (C-core-143c (e)). `effective` is gone from both key events: an old
// writer's `effective` is an unknown field, retained and ignored (§6).
func TestRevokeReasonToken(t *testing.T) {
	for _, r := range []string{"key_compromise", "superseded", "cessation_of_operation", "unspecified", "x_vendor_reason", "a"} {
		if st, err := readBody(t, "revoke_key", setField(minimal("revoke_key"), "reason", s(r))); err != nil || st.Status != Valid {
			t.Fatalf("reason %q: %v", r, err)
		}
	}
	for _, r := range []string{"Key-Compromise", "", "_x", "9a", "a-b", strings.Repeat("a", 65)} {
		_, err := readBody(t, "revoke_key", setField(minimal("revoke_key"), "reason", s(r)))
		refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "reason token")
	}
	for _, k := range []string{"rotate_key", "revoke_key"} {
		if st, err := readBody(t, k, setField(minimal(k), "effective", s("not even a time"))); err != nil || st.Status != Valid {
			t.Fatalf("%s with a legacy effective: %v", k, err)
		}
	}
}

// dg is a distinct digest per name, for reference tests.
func dg(n string) string {
	h := sha256.Sum256([]byte("ref " + n))
	return "sha256:" + hex.EncodeToString(h[:])
}

// TestReferences: Statement.References lists every value the body schema types as a digest, at every depth
// the brief of the hub gate names, sorted and without repeats, and nothing else. Each fixture puts a distinct
// digest in every typed digest field it carries; the boundary is shown by the control beside it: the same
// digest in an unknown (untyped) field is not a typed reference, while ScanDigests over the line finds it.
func TestReferences(t *testing.T) {
	c := func(n string) *canon.Object { return body("digest", dg(n), "size", 1) }
	prov := body("workflow", dg("workflow"), "inputs", arr(s(dg("in1")), s(dg("in2"))), "environment", body("image_digest", dg("image")))
	cases := []struct {
		kind string
		b    *canon.Object
		want []string
	}{
		{"authored", body("content", c("content"), "type", "dataset", "provenance", prov, "supersedes", dg("sup"), "extends", dg("ext"),
			"comparator", dg("cmp")), []string{"content", "workflow", "in1", "in2", "image", "sup", "ext", "cmp"}},
		{"holds", body("content", c("held")), []string{"held"}},
		{"describes", body("about", body("content", dg("about")), "links", arr(body("content", dg("link"), "rel", "r"), body("url", "x", "rel", "r"))),
			[]string{"about", "link"}},
		{"reproduced", body("of", tID, "result", "match", "content", c("rc"), "provenance", prov, "comparator", dg("cmp"), "report", dg("rep")),
			[]string{"rc", "workflow", "in1", "in2", "image", "cmp", "rep"}},
		{"refutes", body("of", tID, "evidence", dg("ev")), []string{"ev"}},
		{"anchors", body("covered", tID, "proof", dg("proof"), "proof_format", "ots-detached-v1"), []string{"proof"}},
		{"edition", body("resource", tID, "predecessors", arr(s(tID)), "contents", body("schema", dg("schema"),
			"members", arr(body("content", dg("m1"), "role", "x"), body("statement", tID2, "role", "y")))), []string{"schema", "m1"}},
		{"submit", body("task", tID, "edition", tID2, "result", dg("result")), []string{"result"}},
		{"decide", body("task", tID, "edition", tID2, "submissions", arr(s(tID)), "verdict", "accept", "evaluations", arr(s(dg("e1")), s(dg("e2")))),
			[]string{"e1", "e2"}},
		{"observed", body("content", c("obs"), "class", "source", "capture", body("at", tTS, "evidence", "self-asserted"),
			"referent", body("endpoint", "e", "parameters", body(), "response_digest", dg("resp"))), []string{"obs", "resp"}},
		{"observed", body("content", c("obs"), "class", "source", "capture", body("at", tTS, "evidence", "self-asserted"),
			"referent", body("requests", body("digest", dg("reqlog"), "format", "f", "count", 2))), []string{"obs", "reqlog"}},
		// an unpinned batch referent still names its request log
		{"observed", body("content", c("obs"), "class", "source", "capture", body("at", tTS, "evidence", "self-asserted"),
			"referent", body("requests", body("digest", dg("reqlog"), "format", "f"))), []string{"obs", "reqlog"}},
		{"observed", body("content", c("obs"), "class", "method", "capture", body("at", tTS, "evidence", "self-asserted"),
			"referent", body("method_edition", tID, "environment", body("image_digest", dg("img"), "platform", "p", "harness_commit", strings.Repeat("a", 40)),
				"system", body(), "inputs", arr(s(dg("mi"))), "window", body("from", tTS, "to", tTS))), []string{"obs", "img", "mi"}},
		// a repeated digest is listed once
		{"authored", body("content", c("same"), "type", "dataset", "supersedes", dg("same")), []string{"same"}},
		{"retracts", body("of", tID), nil},
	}
	for _, tc := range cases {
		st, err := readBody(t, tc.kind, tc.b)
		if err != nil || st.Status != Valid {
			t.Fatalf("%s: %v %v", tc.kind, err, st)
		}
		var want []string
		for _, n := range tc.want {
			want = append(want, dg(n))
		}
		slices.Sort(want)
		want = slices.Compact(want)
		if got := st.References(); !slices.Equal(got, want) {
			t.Fatalf("%s: references %v, want %v (%v)", tc.kind, got, want, tc.want)
		}
		// every digest in these bodies sits in a typed field: the typed list equals the scan of the line
		if got := ScanDigests(st.Line()); !slices.Equal(got, want) {
			t.Fatalf("%s: scan %v, typed %v", tc.kind, got, want)
		}
		// control: the same body plus an untyped field naming another digest; the scan sees it, References does not
		u, err := readBody(t, tc.kind, setField(tc.b, "x_note", s(dg("untyped"))))
		if err != nil {
			t.Fatal(err)
		}
		if slices.Contains(u.References(), dg("untyped")) || !slices.Contains(ScanDigests(u.Line()), dg("untyped")) {
			t.Fatalf("%s: untyped field: references %v", tc.kind, u.References())
		}
	}
	// an unknown kind is not interpreted: no typed references (a caller falls back to ScanDigests)
	st, err := readBody(t, "x_custom", body("content", c("opaque")))
	if err != nil || st.Status != UnknownKind || st.References() != nil || !slices.Contains(ScanDigests(st.Line()), dg("opaque")) {
		t.Fatalf("%v %v", err, st)
	}
}

// TestReferencesCoverSchema: References is derived from the schema tables (the digest() rule records what it
// accepts), so no hand list can fall behind them. This walks the tables and requires every digest() field to
// show up in some body's References: if a field were checked by a rule that bypasses digest(), or a new
// digest() field were reachable only through code that drops the collected references, this fails.
func TestReferencesCoverSchema(t *testing.T) {
	probe := canon.String(dg("probe"))
	paths := 0
	// The tables are closures, so walk them by probing: for each kind and each top-level field, set the field
	// to a probe digest (or a list of one); where the probe validates and an ordinary string does not, the
	// schema typed that position as digest(), and the probe must be a reference. Nested digest positions are
	// pinned field by field in TestReferences.
	for _, kind := range allKinds() {
		base := minimal(kind)
		var fs []field
		if kind == "observed" {
			fs = with(disclosures, req("content", contentObj), opt("finality", finalityObj))
		} else {
			fs = kinds[kind]
		}
		valid := func(b *canon.Object) (*Statement, bool) {
			st, err := readBody(t, kind, b)
			return st, err == nil && st.Status == Valid
		}
		for _, f := range fs {
			for _, v := range [][2]canon.Value{{probe, s("not a digest")}, {arr(probe), arr(s("not a digest"))}} {
				// typed as a digest: the probe validates there and another string does not
				st, ok := valid(setField(base, f.name, v[0]))
				if _, other := valid(setField(base, f.name, v[1])); !ok || other {
					continue
				}
				paths++
				if !slices.Contains(st.References(), string(probe)) {
					t.Fatalf("%s.%s validates as a digest but is not a reference", kind, f.name)
				}
			}
		}
	}
	// supersedes, extends, comparator (×2 kinds), refutes.evidence, anchors.proof, submit.result, decide.evaluations
	if paths < 8 {
		t.Fatalf("only %d top-level digest fields found: the probe proves nothing", paths)
	}
}
