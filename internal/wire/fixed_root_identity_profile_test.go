package wire

// Candidate-only validation harness. Nothing in this file is built into a reader or
// writer. In particular this does not register crit, change Major, or resolve authority.
import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/rctime"
)

type frSchema map[string]any

func frLoad(t *testing.T, name string) frSchema {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("../../docs", name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := canon.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return frSchema(frNative(v).(map[string]any))
}

// Schemas and vectors use the same strict parser as statements. Convert only the
// already-validated AST to convenient test-interpreter containers; no second JSON parser.
func frNative(v canon.Value) any {
	switch x := v.(type) {
	case *canon.Object:
		m := map[string]any{}
		for _, k := range x.Keys {
			m[k] = frNative(x.Members[k])
		}
		return m
	case canon.Array:
		a := make([]any, len(x))
		for i, e := range x {
			a[i] = frNative(e)
		}
		return a
	case canon.String:
		return string(x)
	case canon.Int:
		return int64(x)
	case canon.Bool:
		return bool(x)
	case canon.Null:
		return nil
	default:
		panic("unexpected canonical AST value")
	}
}
func frValue(v any) canon.Value {
	switch x := v.(type) {
	case map[string]any:
		o := &canon.Object{Members: map[string]canon.Value{}}
		for k, e := range x {
			o.Keys = append(o.Keys, k)
			o.Members[k] = frValue(e)
		}
		return o
	case []any:
		a := make(canon.Array, len(x))
		for i, e := range x {
			a[i] = frValue(e)
		}
		return a
	case string:
		return canon.String(x)
	case int64:
		return canon.Int(x)
	case bool:
		return canon.Bool(x)
	case nil:
		return canon.Null{}
	default:
		panic("unexpected schema constant type")
	}
}
func frCanonical(v any) []byte { return canon.Encode(frValue(v)) }

// A deliberately small JSON Schema 2020-12 interpreter for the keywords used by
// these two schemas. Not a general-purpose JSON Schema library. Unknown executable
// keywords fail the harness; no external references, filesystem or network resolution.
func frCheck(root frSchema, raw any, v canon.Value, path string) error {
	if b, ok := raw.(bool); ok {
		if b {
			return nil
		}
		return fmt.Errorf("%s: false schema", path)
	}
	s := raw.(map[string]any)
	fail := func(m string) error { return fmt.Errorf("%s: %s", path, m) }
	for k := range s {
		switch k {
		case "$schema", "$defs", "$comment", "title", "description", "$ref", "type", "const", "enum", "allOf", "anyOf", "oneOf", "not", "if", "then", "else", "properties", "required", "additionalProperties", "dependentRequired", "items", "minItems", "maxItems", "uniqueItems", "pattern", "minimum", "maximum":
		default:
			return fail("unimplemented schema keyword " + k)
		}
	}
	if r, ok := s["$ref"].(string); ok {
		if !strings.HasPrefix(r, "#/$defs/") {
			return fail("nonlocal reference")
		}
		def, ok := root["$defs"].(map[string]any)[strings.TrimPrefix(r, "#/$defs/")]
		if !ok {
			return fail("missing definition " + r)
		}
		if err := frCheck(root, def, v, path); err != nil {
			return err
		}
	}
	if typ, ok := s["type"].(string); ok {
		good := false
		switch typ {
		case "object":
			_, good = v.(*canon.Object)
		case "array":
			_, good = v.(canon.Array)
		case "string":
			_, good = v.(canon.String)
		case "integer":
			_, good = v.(canon.Int)
		case "boolean":
			_, good = v.(canon.Bool)
		case "null":
			_, good = v.(canon.Null)
		}
		if !good {
			return fail("type " + typ)
		}
	}
	if c, ok := s["const"]; ok && !bytes.Equal(canon.Encode(v), frCanonical(c)) {
		return fail("const")
	}
	if en, ok := s["enum"].([]any); ok {
		good := false
		for _, e := range en {
			good = good || bytes.Equal(canon.Encode(v), frCanonical(e))
		}
		if !good {
			return fail("enum")
		}
	}
	for _, op := range []string{"allOf", "anyOf", "oneOf"} {
		if a, ok := s[op].([]any); ok {
			count := 0
			var detail error
			for _, sub := range a {
				if err := frCheck(root, sub, v, path); err == nil {
					count++
				} else {
					detail = err
				}
			}
			if (op == "allOf" && count != len(a)) || (op == "anyOf" && count == 0) || (op == "oneOf" && count != 1) {
				return fail(fmt.Sprintf("%s (%d/%d): %v", op, count, len(a), detail))
			}
		}
	}
	if n, ok := s["not"]; ok && frCheck(root, n, v, path) == nil {
		return fail("not")
	}
	if cond, ok := s["if"]; ok {
		branch := "else"
		if frCheck(root, cond, v, path) == nil {
			branch = "then"
		}
		if sub, ok := s[branch]; ok {
			if err := frCheck(root, sub, v, path); err != nil {
				return err
			}
		}
	}
	if o, ok := v.(*canon.Object); ok {
		if r, ok := s["required"].([]any); ok {
			for _, k := range r {
				if _, yes := o.Get(k.(string)); !yes {
					return fail("missing " + k.(string))
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		for _, k := range o.Keys {
			sub, known := props[k]
			if !known {
				sub, known = s["additionalProperties"]
			}
			if known {
				if err := frCheck(root, sub, o.Members[k], path+"."+k); err != nil {
					return err
				}
			}
		}
		if deps, ok := s["dependentRequired"].(map[string]any); ok {
			for k, rs := range deps {
				if _, yes := o.Get(k); yes {
					for _, r := range rs.([]any) {
						if _, yes := o.Get(r.(string)); !yes {
							return fail("dependentRequired " + r.(string))
						}
					}
				}
			}
		}
	}
	if a, ok := v.(canon.Array); ok {
		if n, ok := s["minItems"].(int64); ok && len(a) < int(n) {
			return fail("minItems")
		}
		if n, ok := s["maxItems"].(int64); ok && len(a) > int(n) {
			return fail("maxItems")
		}
		seen := map[string]bool{}
		for i, e := range a {
			if s["uniqueItems"] == true {
				key := string(canon.Encode(e))
				if seen[key] {
					return fail("uniqueItems")
				}
				seen[key] = true
			}
			if sub, ok := s["items"]; ok {
				if err := frCheck(root, sub, e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		}
	}
	if str, ok := v.(canon.String); ok {
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(string(str)) {
			return fail("pattern")
		}
	}
	if n, ok := v.(canon.Int); ok {
		if min, ok := s["minimum"].(int64); ok && int64(n) < min {
			return fail("minimum")
		}
		if max, ok := s["maximum"].(int64); ok && int64(n) > max {
			return fail("maximum")
		}
	}
	return nil
}

// Set comparison is UTF-16 order for strings and for the JCS text of structured
// entries. All structured sets in this profile contain only ASCII authority tokens.
func frSorted(v canon.Value, path string) error {
	a := v.(canon.Array)
	prev := ""
	for i, e := range a {
		key := string(canon.Encode(e))
		if s, ok := e.(canon.String); ok {
			key = string(s)
		}
		if i > 0 && canon.CompareKeys(prev, key) >= 0 {
			return fmt.Errorf("%s: unsorted or duplicate set", path)
		}
		prev = key
	}
	return nil
}
func frSets(o *canon.Object) error {
	// Paths are selected by schema context, not by recursively treating every field
	// named `contents` as a set (the resource body uses an object with that name).
	check := func(o *canon.Object, names ...string) error {
		for _, n := range names {
			if v, ok := o.Get(n); ok {
				if err := frSorted(v, n); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := check(o, "crit", "merges"); err != nil {
		return err
	}
	b := o.Members["body"].(*canon.Object)
	if err := check(b, "controllers", "predecessors", "permissions"); err != nil {
		return err
	}
	ext := b.Members["x_identity_v1"].(*canon.Object)
	if err := check(ext, "amends"); err != nil {
		return err
	}
	if roles, ok := ext.Members["task_roles"].(*canon.Object); ok {
		if err := check(roles, "eligible_issuers"); err != nil {
			return err
		}
	}
	if contents, ok := b.Members["contents"].(*canon.Object); ok {
		if err := check(contents, "controllers"); err != nil {
			return err
		}
	}
	if ps, ok := b.Members["permissions"].(canon.Array); ok {
		for _, p := range ps {
			if target, ok := p.(*canon.Object).Members["targets"].(*canon.Object); ok {
				if err := check(target, "contents", "statements", "resources", "tasks"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func frThreshold(b *canon.Object) error {
	controllers, ok := b.Members["controllers"].(canon.Array)
	if !ok {
		return nil
	}
	rule := b.Members["rule"].(*canon.Object)
	if kn, ok := rule.Members["k_of_n"].(*canon.Object); ok {
		if int64(kn.Members["k"].(canon.Int)) > int64(len(controllers)) {
			return fmt.Errorf("unsatisfiable typed controller threshold")
		}
	}
	return nil
}

func frValidate(schema frSchema, line []byte, signed bool) (*canon.Object, error) {
	if len(line) > MaxLine {
		return nil, fmt.Errorf("line size limit")
	}
	v, err := canon.Parse(line)
	if err != nil {
		return nil, err
	}
	entry := "draft"
	if signed {
		entry = "signed"
	}
	if err = frCheck(schema, map[string]any{"$ref": "#/$defs/" + entry}, v, "$"); err != nil {
		return nil, err
	}
	o := v.(*canon.Object)
	b := o.Members["body"].(*canon.Object)
	kind := string(o.Members["kind"].(canon.String))
	if !signed {
		if _, ok := o.Get("sig"); ok {
			return nil, fmt.Errorf("unsigned vector unexpectedly contains sig")
		}
	}
	if _, err = rctime.ParseUTC(string(o.Members["ts"].(canon.String))); err != nil {
		return nil, err
	}
	if _, err = critList(o.Members["crit"], b); err != nil {
		return nil, err
	}
	seq := int64(o.Members["seq"].(canon.Int))
	prev := ""
	if p, ok := o.Members["prev"].(canon.String); ok {
		prev = string(p)
	}
	if m, ok := o.Get("merges"); ok {
		if _, err = mergesList(m, seq, prev); err != nil {
			return nil, err
		}
	}
	if err = frSets(o); err != nil {
		return nil, err
	}
	// Reuse unchanged base schema rules. A recognized marker MUST NOT skip them.
	// rc/2 changes the controller type explicitly. Validate its new shape in the
	// schema above and all unchanged fields in place below; never rewrite signed bytes.
	switch kind {
	case "identity_inception", "identity_grant", "identity_cut":
	case "genesis":
		fields := []field{}
		for _, f := range kinds[kind] {
			if f.name != "controllers" {
				fields = append(fields, f)
			}
		}
		err = checkFields(b, "body", &schemaCtx{}, fields)
		if err == nil {
			err = frThreshold(b)
		}
	case "edition":
		// Only the optional controllers member changes type. The complete new contents
		// schema has already been validated. All other base fields are validated using
		// the base schema on a shallow validation-only view, not rehashed or signed.
		contents := b.Members["contents"].(*canon.Object)
		without := dropField(contents, "controllers")
		_, _, err = checkBody(kind, setField(b, "contents", without))
		if err == nil {
			err = frThreshold(contents)
		}
	default:
		_, _, err = checkBody(kind, b)
	}
	if err != nil {
		return nil, err
	}
	if err = checkBodyTimes(kind, b); err != nil {
		return nil, err
	}
	if kind == "identity_grant" {
		if b.Members["delegate"].(*canon.Object).Members["key"] == o.Members["signer"] {
			return nil, fmt.Errorf("root cannot grant to itself")
		}
	}
	env := o
	if signed {
		env = dropField(o, "sig")
	}
	ss := PAE(PayloadType(kind, 2), canon.Encode(env))
	if len(ss) > MaxSignedString {
		return nil, fmt.Errorf("signed-string size limit")
	}
	if signed {
		st := &Statement{Alg: string(o.Members["alg"].(canon.String)), Signer: string(o.Members["signer"].(canon.String)), SignedString: ss}
		if err = st.verify(string(o.Members["sig"].(canon.String))); err != nil {
			return nil, err
		}
	}
	return o, nil
}
func frPolicy(schema frSchema, line []byte) error {
	if len(line) > MaxLine {
		return fmt.Errorf("policy input size limit")
	}
	v, err := canon.Parse(line)
	if err != nil {
		return err
	}
	if err = frCheck(schema, map[string]any(schema), v, "$"); err != nil {
		return err
	}
	if len(canon.Encode(v)) > MaxSignedString {
		return fmt.Errorf("policy canonical size limit")
	}
	o := v.(*canon.Object)
	seen := map[string]bool{}
	for _, field := range []string{"selections", "trust"} {
		if err = frSorted(o.Members[field], field); err != nil {
			return err
		}
		for _, e := range o.Members[field].(canon.Array) {
			entry := e.(*canon.Object)
			if field == "selections" {
				key := string(canon.Encode(entry.Members["subject"]))
				if seen[key] {
					return fmt.Errorf("conflicting selection subject")
				}
				seen[key] = true
			} else {
				if err = frSorted(entry.Members["purposes"], "purposes"); err != nil {
					return err
				}
				if values, ok := entry.Members["targets"].(*canon.Object).Get("contents"); ok {
					if err = frSorted(values, "contents"); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func TestFixedRootCandidateVectors(t *testing.T) {
	schema := frLoad(t, "fixed-root-identity.schema.json")
	policy := frLoad(t, "fixed-root-identity-policy.schema.json")
	b, err := os.ReadFile("../../docs/fixed-root-identity.vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	suite, err := canon.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, cv := range suite.(*canon.Object).Members["cases"].(canon.Array) {
		c := cv.(*canon.Object)
		name := string(c.Members["name"].(canon.String))
		mode := string(c.Members["mode"].(canon.String))
		accept := bool(c.Members["accept"].(canon.Bool))
		t.Run(name, func(t *testing.T) {
			var data []byte
			if raw, ok := c.Members["raw"].(canon.String); ok {
				data = []byte(raw)
			} else {
				data = canon.Encode(c.Members["value"])
			}
			var err error
			if mode == "policy" {
				err = frPolicy(policy, data)
			} else {
				_, err = frValidate(schema, data, false)
			}
			if (err == nil) != accept {
				t.Fatalf("accept=%v, got %v", accept, err)
			}
		})
	}
}

// Optional file validation is explicitly syntax/crypto-only; it cannot print an
// authority result or confer identity eligibility. No production key is used here.
func TestFixedRootCandidateFile(t *testing.T) {
	name := os.Getenv("RC_IDENTITY_CANDIDATE_FILE")
	if name == "" {
		t.Skip("no candidate file requested")
	}
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("RC_IDENTITY_CANDIDATE_POLICY") == "1" {
		err = frPolicy(frLoad(t, "fixed-root-identity-policy.schema.json"), b)
	} else {
		_, err = frValidate(frLoad(t, "fixed-root-identity.schema.json"), b, true)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Log("candidate syntax/crypto check only; authority NOT evaluated")
}

func frDraft(t *testing.T, kind string, key Key, b *canon.Object) *canon.Object {
	t.Helper()
	return Draft{RC: "rc/2", Kind: kind, TS: tTS, Crit: []string{"x_identity_v1"}, Body: setField(b, "x_identity_v1", body())}.Envelope(key)
}
func frSign(o *canon.Object, key Key) []byte {
	ss := PAE(PayloadType(string(o.Members["kind"].(canon.String)), 2), canon.Encode(o))
	return canon.Encode(setField(o, "sig", canon.String(key.Sign(ss))))
}
func TestFixedRootCandidateCrypto(t *testing.T) {
	schema := frLoad(t, "fixed-root-identity.schema.json")
	for _, key := range []Key{Ed25519Key{Seed: bytes.Repeat([]byte{41}, 32)}, EIP191Key{Scalar: bytes.Repeat([]byte{42}, 32)}} {
		t.Run(key.Alg(), func(t *testing.T) {
			actor := body("identity", tID, "grant", tID2)
			draft := setField(frDraft(t, "authored", key, minimal("authored")), "x_actor_v1", actor)
			line := frSign(draft, key)
			if _, err := frValidate(schema, line, true); err != nil {
				t.Fatal(err)
			}
			old, err := Read(line)
			if err != nil || old.Status != Unsupported || old.Verified {
				t.Fatalf("old major: %+v %v", old, err)
			}
			tampered := setField(draft, "x_actor_v1", body("identity", tID, "grant", tID))
			tampered = setField(tampered, "sig", canon.String(key.Sign(PAE(PayloadType("authored", 2), canon.Encode(draft)))))
			if _, err := frValidate(schema, canon.Encode(tampered), true); err == nil {
				t.Fatal("tampered actor passed")
			}
			// Correctly re-signing malformed content cannot bypass the base body schema.
			malformed := setField(draft, "body", dropField(draft.Members["body"].(*canon.Object), "content"))
			if _, err := frValidate(schema, frSign(malformed, key), true); err == nil {
				t.Fatal("crit bypassed base schema")
			}
			wrongDomain := setField(draft, "sig", canon.String(key.Sign(PAE(PayloadType("authored", 1), canon.Encode(draft)))))
			if _, err := frValidate(schema, canon.Encode(wrongDomain), true); err == nil {
				t.Fatal("v1 preimage passed as v2")
			}
			stripped := dropField(draft, "crit")
			if _, err := frValidate(schema, frSign(stripped, key), true); err == nil {
				t.Fatal("actor without critical marker passed")
			}
			// Signature only claims a signer; these arbitrary I/G values do not prove authority.
		})
	}
}
func TestFixedRootCandidateSharedEdition(t *testing.T) {
	schema := frLoad(t, "fixed-root-identity.schema.json")
	k := Ed25519Key{Seed: bytes.Repeat([]byte{43}, 32)}
	b := minimal("edition")
	raw := frDraft(t, "edition", k, b)
	a := setField(raw, "x_actor_v1", body("identity", tID, "grant", tID2))
	a2 := setField(raw, "x_actor_v1", body("identity", tID2, "grant", tID))
	ids := map[string]bool{}
	edition := ""
	for _, draft := range []*canon.Object{raw, a, a2} {
		line := frSign(draft, k)
		if _, err := frValidate(schema, line, true); err != nil {
			t.Fatal(err)
		}
		ids[ID(PAE(PayloadType("edition", 2), canon.Encode(draft)))] = true
		e := ID(PAE("application/vnd.research-commons.edition-body.v2+json", canon.Encode(draft.Members["body"])))
		if edition != "" && e != edition {
			t.Fatal("actor changed shared edition id")
		}
		edition = e
	}
	if len(ids) != 3 {
		t.Fatal("actor not bound in distinct statement ids")
	}
	if edition == ID(PAE("application/vnd.research-commons.edition-body.v1+json", canon.Encode(raw.Members["body"]))) {
		t.Fatal("versioned edition domain collision")
	}
}

func TestFixedRootCandidateCanonicalization(t *testing.T) {
	schema := frLoad(t, "fixed-root-identity.schema.json")
	key := Ed25519Key{Seed: bytes.Repeat([]byte{44}, 32)}
	draft := frDraft(t, "authored", key, minimal("authored"))
	line := frSign(draft, key)
	parsed, err := canon.Parse(line)
	if err != nil {
		t.Fatal(err)
	}
	full := parsed.(*canon.Object)
	// Deliberately reverse member order and add noncanonical whitespace.
	var spaced bytes.Buffer
	spaced.WriteString("{\n")
	for i := len(full.Keys) - 1; i >= 0; i-- {
		if i < len(full.Keys)-1 {
			spaced.WriteString(",\n")
		}
		k := full.Keys[i]
		spaced.Write(canon.Encode(canon.String(k)))
		spaced.WriteString(" : ")
		spaced.Write(canon.Encode(full.Members[k]))
	}
	spaced.WriteString("\n}")
	a, err := frValidate(schema, line, true)
	if err != nil {
		t.Fatal(err)
	}
	b, err := frValidate(schema, spaced.Bytes(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canon.Encode(a), canon.Encode(b)) {
		t.Fatal("whitespace changed canonical bytes")
	}
	utf, err := canon.Parse([]byte(`{"\ue000":1,"\ud800\udc00":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(canon.Encode(utf)) != "{\"𐀀\":2,\"\":1}" {
		t.Fatal("not UTF-16 key ordering")
	}
	for _, raw := range [][]byte{[]byte(`{"a":1,"\u0061":2}`), []byte(`-0`), []byte(`1.0`), []byte(`1e0`), []byte(`9007199254740992`), []byte(`"\ud800"`), {0xff}, []byte("\xef\xbb\xbf{}"), []byte(strings.Repeat("[", 17) + "0" + strings.Repeat("]", 17))} {
		if _, err := canon.Parse(raw); err == nil {
			t.Fatalf("nonconforming JSON accepted: %q", raw)
		}
	}
	huge := setField(draft, "x_padding", canon.String(strings.Repeat("x", MaxSignedString)))
	if _, err := frValidate(schema, frSign(huge, key), true); err == nil {
		t.Fatal("oversize PAE passed")
	}
}

func TestFixedRootCandidateBaseSchemaIsNotBypassed(t *testing.T) {
	schema := frLoad(t, "fixed-root-identity.schema.json")
	key := Ed25519Key{Seed: bytes.Repeat([]byte{45}, 32)}
	for _, kind := range allKinds() {
		if kind == "rotate_key" || kind == "revoke_key" {
			continue
		} // deliberately rc/1 only
		t.Run(kind, func(t *testing.T) {
			b := minimal(kind)
			if kind == "genesis" {
				b = setField(b, "controllers", canon.Array{body("key", tKey)})
			}
			draft := frDraft(t, kind, key, b)
			if kind == "progress" || kind == "withdraw" {
				b = setField(draft.Members["body"].(*canon.Object), "x_identity_v1", body("intent", tID))
				draft = setField(draft, "body", b)
			}
			if _, err := frValidate(schema, frSign(draft, key), true); err != nil {
				t.Fatal(err)
			}
			required := []string{}
			for _, f := range kinds[kind] {
				if f.req {
					required = append(required, f.name)
				}
			}
			if kind == "observed" {
				required = []string{"content", "class", "referent", "capture"}
			}
			for _, field := range required {
				broken := setField(draft, "body", dropField(draft.Members["body"].(*canon.Object), field))
				if _, err := frValidate(schema, frSign(broken, key), true); err == nil {
					t.Fatalf("recognized critical marker bypassed required base field %s", field)
				}
			}
		})
	}
}

func TestFixedRootCandidateLegacyUnmarkedActorIsNotSafe(t *testing.T) {
	schema := frLoad(t, "fixed-root-identity.schema.json")
	key := Ed25519Key{Seed: bytes.Repeat([]byte{46}, 32)}
	draft := Draft{Kind: "authored", TS: tTS, Body: minimal("authored")}.Envelope(key)
	draft = setField(draft, "x_actor_v1", body("identity", tID, "grant", tID2))
	ss := PAE(PayloadType("authored", 1), canon.Encode(draft))
	line := canon.Encode(setField(draft, "sig", canon.String(key.Sign(ss))))
	old, err := Read(line)
	if err != nil || old.Status != Valid || !old.Verified {
		t.Fatalf("baseline behavior changed: %+v %v", old, err)
	}
	if _, err := frValidate(schema, line, true); err == nil {
		t.Fatal("candidate silently reinterpreted rc/1 actor")
	}
	// This signed but nonconforming profile statement is why new writers cannot
	// rely on an ignored envelope header for downgrade protection. No claim that
	// an old reader can enforce future profile rules is made.
}
