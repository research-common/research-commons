package wire

import (
	"bytes"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

func testReader(t *testing.T, validators map[string]ExtensionValidator) *Reader {
	t.Helper()
	r, err := NewReader(validators)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func extensionDraft(names ...string) Draft {
	d := authoredDraft(0, "")
	d.Crit = names
	for _, name := range names {
		d.Body = setField(d.Body, name, canon.String("test value"))
	}
	return d
}

func TestReaderEmptyCompatibility(t *testing.T) {
	k := testKeys("A")["A"]
	drafts := []Draft{
		authoredDraft(0, ""),
		extensionDraft("x_a", "x_z"),
		{Kind: "future_kind", TS: tTS, Body: body()},
		{Kind: "authored", TS: tTS, Body: body()},
		{Kind: "authored", TS: tTS, Crit: []string{"x_absent"}, Body: body()},
		{RC: "rc/2", Kind: "authored", TS: "not a time", Body: body()},
	}
	readers := []*Reader{{}, testReader(t, nil), testReader(t, map[string]ExtensionValidator{})}
	for _, d := range drafts {
		line, _ := Sign(d, k)
		want, wantErr := Read(line)
		for _, r := range readers {
			got, err := r.Read(line)
			if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(err, wantErr) {
				t.Fatalf("empty registry differs from Read: got %+v, %v; want %+v, %v", got, err, want, wantErr)
			}
			if got != nil && !bytes.Equal(got.Line(), want.Line()) {
				t.Fatal("empty registry changed stored bytes")
			}
		}
	}
}

func TestReaderRegistrationValidation(t *testing.T) {
	accept := func(*canon.Object) error { return nil }
	for _, name := range []string{"", "crit", "content", "X_test"} {
		if r, err := NewReader(map[string]ExtensionValidator{name: accept}); err == nil || r != nil {
			t.Fatalf("invalid name %q: reader=%v error=%v", name, r, err)
		}
	}
	if r, err := NewReader(map[string]ExtensionValidator{"x_test": nil}); err == nil || r != nil {
		t.Fatalf("nil validator: reader=%v error=%v", r, err)
	}
	// Match the existing wire prefix rule, not a newly invented extension-name grammar.
	for _, name := range []string{"x_", "x_😀", "x_ｱ"} {
		r := testReader(t, map[string]ExtensionValidator{name: accept})
		line, _ := Sign(extensionDraft(name), testKeys("A")["A"])
		if st, err := r.Read(line); err != nil || st.Status != Valid {
			t.Fatalf("existing extension name %q: %+v %v", name, st, err)
		}
	}
}

func TestReaderRegisteredEnvelopeContext(t *testing.T) {
	for _, k := range testKeys("A", "B") {
		t.Run(k.Alg(), func(t *testing.T) {
			d := extensionDraft("x_test")
			d.Seq, d.Prev, d.Merges = 2, tID, []string{tID2}
			d.Body = setField(d.Body, "x_test", body("limit", 7))
			wantEnvelope := canon.Encode(d.Envelope(k))
			calls := 0
			r := testReader(t, map[string]ExtensionValidator{"x_test": func(env *canon.Object) error {
				calls++
				if !bytes.Equal(canon.Encode(env), wantEnvelope) {
					t.Fatal("validator did not receive the complete signed envelope without sig")
				}
				value := env.Members["body"].(*canon.Object).Members["x_test"].(*canon.Object)
				if value.Members["limit"] != canon.Int(7) || env.Members["kind"] != canon.String("authored") {
					return errors.New("invalid extension value or envelope context")
				}
				return nil
			}})
			line, id := Sign(d, k)
			st, err := r.Read(line)
			if err != nil || st.Status != Valid || !st.Verified || calls != 1 || st.ID != id || st.Why != "" {
				t.Fatalf("registered extension: %+v %v; calls=%d", st, err, calls)
			}
			if !bytes.Equal(st.Line(), line) || !bytes.Equal(st.SignedString, PAE(PayloadType(d.Kind, Major), wantEnvelope)) {
				t.Fatal("registration changed the wire bytes or signed string")
			}
			plain, err := Read(line)
			if err != nil || plain.Status != Unsupported || plain.Why != "crit x_test" || !plain.Verified || plain.ID != id {
				t.Fatalf("registration leaked into default reader: %+v %v", plain, err)
			}
		})
	}
}

func TestReaderAllKnownStillValidatesBaseKinds(t *testing.T) {
	k := testKeys("A")["A"]
	for _, kind := range allKinds() {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			r := testReader(t, map[string]ExtensionValidator{"x_test": func(*canon.Object) error { calls++; return nil }})
			b := minimal(kind)
			d := Draft{Kind: kind, TS: tTS, Crit: []string{"x_test"}, Body: setField(b, "x_test", canon.Bool(true))}
			line, _ := Sign(d, k)
			st, err := r.Read(line)
			if err != nil || st.Status != Valid || !st.Verified || calls != 1 {
				t.Fatalf("valid base kind with extension: %+v %v; calls=%d", st, err, calls)
			}
			// Every minimal fixture starts with a required field. A known extension must not bypass it.
			d.Body = dropField(d.Body, b.Keys[0])
			line, _ = Sign(d, k)
			st, err = r.Read(line)
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "missing")
			if st != nil || calls != 1 {
				t.Fatal("base failure returned a statement or called extension code")
			}
		})
	}
}

func TestReaderValidatorRejectsValueAndContext(t *testing.T) {
	r := testReader(t, map[string]ExtensionValidator{"x_test": func(env *canon.Object) error {
		b := env.Members["body"].(*canon.Object)
		if b.Members["x_test"] != canon.String("test value") {
			return errors.New("unexpected extension value")
		}
		if env.Members["kind"] != canon.String("authored") {
			return errors.New("unexpected envelope kind")
		}
		return nil
	}})
	for _, context := range []bool{false, true} {
		d := extensionDraft("x_test")
		detail := "unexpected extension value"
		if context {
			d.Kind = "holds" // content is valid for this base kind; only the validator refuses it.
			detail = "unexpected envelope kind"
		} else {
			d.Body = setField(d.Body, "x_test", canon.Null{})
		}
		line, _ := Sign(d, testKeys("A")["A"])
		st, err := r.Read(line)
		refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, detail)
		if st != nil {
			t.Fatal("invalid extension returned a statement")
		}
	}
}

func TestReaderPreservesBaseFailureOrdering(t *testing.T) {
	calls := 0
	r := testReader(t, map[string]ExtensionValidator{"x_test": func(*canon.Object) error { calls++; return nil }})
	d := extensionDraft("x_test")
	d.Body = dropField(d.Body, "content")
	line, _ := Sign(d, testKeys("A")["A"])
	// Both the base schema and signature are wrong. The historical schema-first refusal still wins.
	line = bytes.Replace(line, []byte("test value"), []byte("bad value"), 1)
	st, err := r.Read(line)
	refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "body.content is missing")
	if st != nil || calls != 0 {
		t.Fatal("failed base schema reached a validator or returned a statement")
	}
}

func TestReaderAllKnownStillValidatesBodyTimesAndTypes(t *testing.T) {
	cases := []struct {
		name, kind, detail string
		b                  *canon.Object
	}{
		{"base type", "authored", "not an object", setField(minimal("authored"), "content", canon.String("wrong"))},
		{"capture", "observed", "trailing zero", setField(minimal("observed"), "capture", body("at", "2026-10-15T00:00:00.10Z", "evidence", "self-asserted"))},
		{"sampling", "authored", "offset other than Z", setField(minimal("authored"), "sampling", body("n", 1, "unit", "test", "window", body("from", "2026-10-15T00:00:00+00:00", "to", tTS)))},
		{"timescale", "observed", "FITS", setField(minimal("observed"), "referent", body("timescale", "GMT", "at", tTS))},
		{"date", "edition", "no such date", setField(minimal("edition"), "contents", body("frozen_before", body("date", "2026-02-30")))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			r := testReader(t, map[string]ExtensionValidator{"x_test": func(*canon.Object) error { calls++; return nil }})
			line, _ := Sign(Draft{Kind: c.kind, TS: tTS, Crit: []string{"x_test"}, Body: setField(c.b, "x_test", canon.Bool(true))}, testKeys("A")["A"])
			st, err := r.Read(line)
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, c.detail)
			if st != nil || calls != 0 {
				t.Fatal("base-body failure reached extension validator or returned a statement")
			}
		})
	}
	// Schema output is preserved, not just schema acceptance.
	b := setField(minimal("observed"), "class", canon.String("source"))
	plain, err := readBody(t, "observed", b)
	if err != nil || len(plain.Unpinned) == 0 {
		t.Fatalf("unpinned fixture: %+v %v", plain, err)
	}
	r := testReader(t, map[string]ExtensionValidator{"x_test": func(*canon.Object) error { return nil }})
	line, _ := Sign(Draft{Kind: "observed", TS: tTS, Crit: []string{"x_test"}, Body: setField(b, "x_test", canon.Bool(true))}, testKeys("A")["A"])
	st, err := r.Read(line)
	if err != nil || !reflect.DeepEqual(st.Unpinned, plain.Unpinned) {
		t.Fatalf("extension lost unpinned fields: %+v %v; want %v", st, err, plain.Unpinned)
	}
}

func TestReaderUnsupportedMixtureNeverPartiallyValidates(t *testing.T) {
	for _, known := range []string{"x_a", "x_z"} {
		t.Run(known, func(t *testing.T) {
			calls := 0
			r := testReader(t, map[string]ExtensionValidator{known: func(*canon.Object) error {
				calls++
				return errors.New("must not run")
			}})
			// Invalid base schema and time remain uninterpreted when any crit name is unknown.
			d := Draft{Kind: "observed", TS: tTS, Crit: []string{"x_a", "x_z"}, Body: body("x_a", 1, "x_z", 1, "capture", body("at", "whenever"))}
			line, id := Sign(d, testKeys("A")["A"])
			st, err := r.Read(line)
			if err != nil || st.Status != Unsupported || st.Why != "crit x_a,x_z" || !st.Verified || st.ID != id || calls != 0 {
				t.Fatalf("unsupported mixture: %+v %v; calls=%d", st, err, calls)
			}
			if !bytes.Equal(st.Line(), line) || len(st.Unpinned) != 0 {
				t.Fatal("unsupported body was rewritten or interpreted")
			}
			bad := bytes.Replace(line, []byte(`"x_a":1`), []byte(`"x_a":2`), 1)
			st, err = r.Read(bad)
			refused(t, err, refusal.Intrinsic, refusal.BadSignature, "")
			if st != nil || calls != 0 {
				t.Fatal("bad signature in mixed crit was not refused before any callback")
			}
		})
	}
}

func TestReaderExtensionFailuresFailClosed(t *testing.T) {
	for _, failure := range []error{errors.New("wrong value"), refusal.Malformed("wrong context"), &refusal.Refusal{Class: refusal.Policy, Reason: "test rejection"}} {
		t.Run(failure.Error(), func(t *testing.T) {
			var called []string
			validators := map[string]ExtensionValidator{}
			for _, name := range []string{"x_a", "x_b", "x_c"} {
				validators[name] = func(*canon.Object) error {
					called = append(called, name)
					if name == "x_b" {
						return failure
					}
					return nil
				}
			}
			r := testReader(t, validators)
			line, _ := Sign(extensionDraft("x_a", "x_b", "x_c"), testKeys("A")["A"])
			st, err := r.Read(line)
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, `crit "x_b"`)
			if st != nil || !slices.Equal(called, []string{"x_a", "x_b"}) {
				t.Fatalf("failed validator did not stop evaluation: %+v, calls=%v", st, called)
			}
		})
	}
}

func TestReaderBadSignatureNeverCallsValidators(t *testing.T) {
	for _, k := range testKeys("A", "B") {
		t.Run(k.Alg(), func(t *testing.T) {
			calls := 0
			r := testReader(t, map[string]ExtensionValidator{"x_test": func(*canon.Object) error { calls++; return nil }})
			line, _ := Sign(extensionDraft("x_test"), k)
			bad := bytes.Replace(line, []byte("test value"), []byte("bad value"), 1)
			st, err := r.Read(bad)
			refused(t, err, refusal.Intrinsic, refusal.BadSignature, "")
			if st != nil || calls != 0 {
				t.Fatal("unverified input reached a validator")
			}
		})
	}
}

func TestReaderUnknownKindRemainsUnknown(t *testing.T) {
	calls := 0
	r := testReader(t, map[string]ExtensionValidator{"x_test": func(*canon.Object) error { calls++; return nil }})
	d := extensionDraft("x_test")
	d.Kind, d.Body = "future_kind", body("x_test", 7, "capture", "not a known body schema")
	line, _ := Sign(d, testKeys("A")["A"])
	st, err := r.Read(line)
	if err != nil || st.Status != UnknownKind || st.Why != d.Kind || !st.Verified || calls != 1 {
		t.Fatalf("registered extension promoted an unknown kind: %+v %v; calls=%d", st, err, calls)
	}
	// Known extension validation still fails closed; it never grants meaning to an unknown kind.
	r = testReader(t, map[string]ExtensionValidator{"x_test": func(*canon.Object) error { return errors.New("invalid value") }})
	st, err = r.Read(line)
	refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "invalid value")
	if st != nil {
		t.Fatal("invalid extension returned an unknown-kind statement")
	}
}

func TestReaderCritStructureUnchanged(t *testing.T) {
	cases := []struct {
		name, detail string
		crit         canon.Value
	}{
		{"null", "non-empty list", canon.Null{}},
		{"string", "non-empty list", canon.String("x_a")},
		{"empty", "non-empty list", canon.Array{}},
		{"non-string", "not a string", canon.Array{canon.Int(1)}},
		{"duplicate", "sorted", canon.Array{canon.String("x_a"), canon.String("x_a")}},
		{"unsorted", "sorted", canon.Array{canon.String("x_z"), canon.String("x_a")}},
		{"base field", "not an extension name", canon.Array{canon.String("content")}},
		{"missing body member", "not in the body", canon.Array{canon.String("x_missing")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			validators := map[string]ExtensionValidator{}
			for _, name := range []string{"x_a", "x_z", "x_missing"} {
				validators[name] = func(*canon.Object) error { calls++; return nil }
			}
			r := testReader(t, validators)
			k := testKeys("A")["A"]
			env := extensionDraft("x_a", "x_z").Envelope(k)
			env.Members["crit"] = c.crit
			ss := PAE(PayloadType("authored", Major), canon.Encode(env))
			env.Keys = append(env.Keys, "sig")
			env.Members["sig"] = canon.String(k.Sign(ss))
			st, err := r.Read(canon.Encode(env))
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, c.detail)
			if st != nil || calls != 0 {
				t.Fatal("malformed crit reached a callback")
			}
		})
	}
}

func TestReaderDoesNotValidateNonCriticalOrUnsupportedEnvelopes(t *testing.T) {
	calls := 0
	r := testReader(t, map[string]ExtensionValidator{"x_test": func(*canon.Object) error { calls++; return errors.New("must not run") }})
	k := testKeys("A")["A"]
	d := extensionDraft("x_test")
	d.Crit = nil // crit is optional; merely receiving a registered body member never invokes a handler.
	line, _ := Sign(d, k)
	if st, err := r.Read(line); err != nil || st.Status != Valid {
		t.Fatalf("non-critical extension: %+v %v", st, err)
	}
	d = extensionDraft("x_test")
	d.RC, d.TS = "rc/2", "not a time"
	line, _ = Sign(d, k)
	if st, err := r.Read(line); err != nil || st.Status != Unsupported || st.Verified {
		t.Fatalf("unknown major: %+v %v", st, err)
	}
	env := extensionDraft("x_test").Envelope(k)
	env.Members["alg"] = canon.String("test-unknown-alg")
	env.Keys = append(env.Keys, "sig")
	env.Members["sig"] = canon.String("not a signature")
	if st, err := r.Read(canon.Encode(env)); err != nil || st.Status != Unsupported || st.Verified {
		t.Fatalf("unknown algorithm: %+v %v", st, err)
	}
	if calls != 0 {
		t.Fatal("non-critical/unsupported input invoked a validator")
	}
}

func TestReaderRegistryIsLocalAndCopied(t *testing.T) {
	accept := func(*canon.Object) error { return nil }
	validators := map[string]ExtensionValidator{"x_a": accept}
	r := testReader(t, validators)
	validators["x_a"] = func(*canon.Object) error { return errors.New("replacement") }
	validators["x_b"] = accept
	for _, name := range []string{"x_a", "x_b"} {
		line, _ := Sign(extensionDraft(name), testKeys("A")["A"])
		st, err := r.Read(line)
		want := Valid
		if name == "x_b" {
			want = Unsupported
		}
		if err != nil || st.Status != want {
			t.Fatalf("caller map changed registry for %s: %+v %v", name, st, err)
		}
		plain, err := Read(line)
		if err != nil || plain.Status != Unsupported {
			t.Fatalf("registry leaked globally: %+v %v", plain, err)
		}
	}
	delete(validators, "x_a")
	// Received objects that look like registrations remain inert data, even after repeated reads.
	d := extensionDraft("x_b")
	d.Body = setField(d.Body, "x_registry", body("x_b", "accept"))
	line, _ := Sign(d, testKeys("A")["A"])
	for range 2 {
		if st, err := r.Read(line); err != nil || st.Status != Unsupported {
			t.Fatalf("data installed a handler: %+v %v", st, err)
		}
	}
}

func TestReaderValidatorCopiesAreIsolated(t *testing.T) {
	d := extensionDraft("x_a", "x_b")
	d.Body = setField(d.Body, "x_a", body("items", canon.Array{body("value", "original")}))
	k := testKeys("A")["A"]
	want := canon.Encode(d.Envelope(k))
	var retained *canon.Object
	r := testReader(t, map[string]ExtensionValidator{
		"x_a": func(env *canon.Object) error {
			retained = env
			env.Keys[0] = "changed"
			env.Members["kind"] = canon.String("future_kind")
			env.Members["crit"].(canon.Array)[0] = canon.String("x_changed")
			b := env.Members["body"].(*canon.Object)
			b.Members["content"].(*canon.Object).Members["size"] = canon.Int(999)
			x := b.Members["x_a"].(*canon.Object)
			x.Members["items"].(canon.Array)[0].(*canon.Object).Members["value"] = canon.String("changed")
			delete(b.Members, "x_b")
			return nil
		},
		"x_b": func(env *canon.Object) error {
			if !bytes.Equal(canon.Encode(env), want) {
				return errors.New("another validator changed this snapshot")
			}
			return nil
		},
	})
	line, id := Sign(d, k)
	st, err := r.Read(line)
	if err != nil || st.Status != Valid || st.Kind != d.Kind || st.ID != id || !bytes.Equal(st.Line(), line) {
		t.Fatalf("validator changed returned statement: %+v %v", st, err)
	}
	retained.Members["body"] = body()
	if !bytes.Equal(st.Line(), line) || !bytes.Equal(canon.Encode(st.Body), canon.Encode(d.Body)) {
		t.Fatal("retained callback input aliases returned statement")
	}
}

func TestReaderConcurrentUse(t *testing.T) {
	r := testReader(t, map[string]ExtensionValidator{"x_test": func(env *canon.Object) error {
		if env.Members["kind"] != canon.String("authored") {
			return errors.New("unexpected kind")
		}
		return nil
	}})
	line, id := Sign(extensionDraft("x_test"), testKeys("A")["A"])
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 4 {
				st, err := r.Read(line)
				if err != nil || st.Status != Valid || st.ID != id {
					t.Errorf("concurrent read: %+v %v", st, err)
				}
			}
		})
	}
	wg.Wait()
}

func TestReaderValidatorsFollowCritUTF16Order(t *testing.T) {
	// These names sort oppositely under UTF-8 byte order and the wire's UTF-16 key order.
	names := []string{"x_😀", "x_ｱ"}
	var calls []string
	validators := map[string]ExtensionValidator{}
	for _, name := range names {
		validators[name] = func(*canon.Object) error { calls = append(calls, name); return nil }
	}
	r := testReader(t, validators)
	line, _ := Sign(extensionDraft(names...), testKeys("A")["A"])
	if st, err := r.Read(line); err != nil || st.Status != Valid || !slices.Equal(calls, names) {
		t.Fatalf("crit execution order %s: %+v %v", strings.Join(calls, ","), st, err)
	}
}
