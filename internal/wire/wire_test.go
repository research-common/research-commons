package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/sig"
)

// Disposable keys minted for the run from public strings (CONFORMANCE.md: tests never touch a real key).
func testKeys(names ...string) map[string]Key {
	out := map[string]Key{}
	for i, n := range names {
		h := sha256.Sum256([]byte("research-commons go test key " + n))
		if i%2 == 0 {
			out[n] = Ed25519Key{Seed: h[:]}
		} else {
			out[n] = EIP191Key{Scalar: h[:]}
		}
	}
	return out
}

func body(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		var v canon.Value
		switch x := kv[i+1].(type) {
		case string:
			v = canon.String(x)
		case int:
			v = canon.Int(x)
		case canon.Value:
			v = x
		}
		o.Keys = append(o.Keys, k)
		o.Members[k] = v
	}
	return o
}

func content(hexByte string, size int) *canon.Object {
	return body("digest", "sha256:"+strings.Repeat(hexByte, 32), "size", size)
}

func authoredDraft(seq int64, prev string, extra ...any) Draft {
	b := body(append([]any{"content", content("ab", 10), "type", "dataset"}, extra...)...)
	return Draft{Kind: "authored", Seq: seq, Prev: prev, TS: "2026-10-15T00:00:00Z", Body: b}
}

func refused(t *testing.T, err error, class refusal.Class, reason, detail string) {
	t.Helper()
	var r *refusal.Refusal
	if !errors.As(err, &r) || r.Class != class || r.Reason != reason || !strings.Contains(r.Detail, detail) {
		t.Fatalf("got %v, want %s: %s …%s…", err, class, reason, detail)
	}
}

// TestOneFieldTwoIDs: two statements from one key that differ in one field (a reason, an unknown extension,
// a later authored on the same blob) have two ids; one body signed twice is one id.
func TestOneFieldTwoIDs(t *testing.T) {
	conformance.Partial(t, "C-core-02a", "ids only; display needs the resolver")
	conformance.Partial(t, "C-core-11", "two ids and both verify; retention in the log and the amendment display need steps 5+ and the resolver")
	for _, k := range testKeys("A", "B") {
		base := authoredDraft(0, "")
		variants := []Draft{base, authoredDraft(0, "", "description", "x"), authoredDraft(0, "", "x_ttl", 7)}
		later := authoredDraft(1, "")
		seen := map[string]bool{}
		for _, d := range variants {
			_, id := Sign(d, k)
			if seen[id] {
				t.Fatalf("%s: two different bodies share id %s", k.Alg(), id)
			}
			seen[id] = true
		}
		_, id0 := Sign(base, k)
		line, _ := Sign(base, k)
		st, err := Read(line)
		if err != nil || st.ID != id0 {
			t.Fatalf("%s: %v", k.Alg(), err)
		}
		lineL, idL := Sign(Draft{Kind: later.Kind, Seq: 1, Prev: id0, TS: later.TS, Body: later.Body}, k)
		if idL == id0 {
			t.Fatal("amendment shares the first statement's id")
		}
		if _, err := Read(lineL); err != nil {
			t.Fatal(err)
		}
	}
}

// TestFlipEveryByte: flipping any one byte of a stored line either breaks parsing, breaks a field rule, or
// breaks the signature. No flip yields a valid statement that differs from the original.
func TestFlipEveryByte(t *testing.T) {
	conformance.Partial(t, "C-core-09", "every byte at the wire layer; the case's delivery at pull with the parsed digest logged needs pull")
	k := testKeys("A")["A"]
	line, id := Sign(authoredDraft(0, "", "licence", "CC-BY-4.0", "x_ext", "v",
		"provenance", body("workflow", "sha256:"+strings.Repeat("c0", 32), "inputs", canon.Array{canon.String("sha256:" + strings.Repeat("11", 32))})), k)
	accepted, unverified := 0, 0
	for i := range line {
		for _, mask := range []byte{0x01, 0x20} {
			m := bytes.Clone(line)
			m[i] ^= mask
			st, err := Read(m)
			if err != nil {
				var r *refusal.Refusal
				if !errors.As(err, &r) {
					t.Fatalf("byte %d: untyped error %v", i, err)
				}
				continue
			}
			// A flip that renames alg to one this reader lacks is retained unverified as unsupported (§4); it
			// is never valid and grants nothing. Anything accepted as valid must be the same statement.
			if st.Status == Unsupported && !st.Verified {
				unverified++
				continue
			}
			if st.ID != id || st.Status != Valid {
				t.Fatalf("byte %d mask %#x: accepted as a different statement %s (%s)", i, mask, st.ID, st.Status)
			}
			accepted++
		}
	}
	t.Logf("%d of %d single-byte flips accepted as the same statement, %d retained unverified (unknown alg)", accepted, 2*len(line), unverified)
	if accepted != 0 {
		t.Fatal("a canonical line has no insignificant bytes; no flip should verify")
	}
}

// TestEnvelopeRules: each envelope rule of §2, §4 and §6, one row per rule, signed validly so only the rule
// can refuse.
func TestEnvelopeRules(t *testing.T) {
	keys := testKeys("A", "B")
	ed, eip := keys["A"], keys["B"]
	id := strings.Repeat("ab", 32)
	for _, c := range []struct {
		name   string
		d      Draft
		k      Key
		detail string
	}{
		{"prev null after seq 0", authoredDraft(3, ""), ed, "prev null at seq 3"},
		{"prev at seq 0", authoredDraft(0, id), ed, "prev set at seq 0"},
		{"prev not an id", authoredDraft(1, "ABCD"), ed, "not a statement id"},
		{"short prev", authoredDraft(1, id[:12]), ed, "not a statement id"},
		{"negative seq", authoredDraft(-1, ""), eip, "seq is not a non-negative integer"},
		{"bad kind", Draft{Kind: "Authored", TS: "2026-10-15T00:00:00Z", Body: body()}, ed, "kind"},
		{"rc malformed", Draft{RC: "rc/01", Kind: "authored", TS: "2026-10-15T00:00:00Z", Body: body()}, ed, "rc/<positive integer>"},
		{"rc malformed 2", Draft{RC: "RC/1", Kind: "authored", TS: "2026-10-15T00:00:00Z", Body: body()}, ed, "rc/<positive integer>"},
		{"ts offset", Draft{Kind: "authored", TS: "2026-10-15T00:00:00+00:00", Body: body()}, ed, "offset other than Z"},
		{"crit unsorted", Draft{Kind: "authored", TS: "2026-10-15T00:00:00Z", Crit: []string{"x_b", "x_a"}, Body: body("x_a", 1, "x_b", 1)}, ed, "sorted"},
		{"crit duplicate", Draft{Kind: "authored", TS: "2026-10-15T00:00:00Z", Crit: []string{"x_a", "x_a"}, Body: body("x_a", 1)}, ed, "sorted"},
		{"crit absent from body", Draft{Kind: "authored", TS: "2026-10-15T00:00:00Z", Crit: []string{"x_a"}, Body: body()}, ed, "not in the body"},
		{"crit names a defined field", Draft{Kind: "authored", TS: "2026-10-15T00:00:00Z", Crit: []string{"licence"}, Body: body("licence", "MIT")}, ed, "not an extension name"},
		{"capture.at not canonical", Draft{Kind: "observed", TS: "2026-10-15T00:00:00Z", Body: setField(minimal("observed"), "capture", body("at", "2026-10-15T00:00:00.10Z", "evidence", "self-asserted"))}, ed, "trailing zero"},
		{"bad timescale", Draft{Kind: "observed", TS: "2026-10-15T00:00:00Z", Body: setField(minimal("observed"), "referent", body("timescale", "GMT", "at", "2026-10-15T00:00:00"))}, ed, "FITS"},
		{"window to in TAI with Z", Draft{Kind: "observed", TS: "2026-10-15T00:00:00Z", Body: setField(minimal("observed"), "referent", body("timescale", "TAI", "window", body("from", "2026-10-15T00:00:00", "to", "2026-10-15T01:00:00Z")))}, ed, "Z asserts UTC"},
		{"effective not UTC", Draft{Kind: "rotate_key", TS: "2026-10-15T00:00:00Z", Body: setField(minimal("rotate_key"), "effective", s("2026-10-15T00:00:00"))}, ed, "missing Z"},
		{"frozen_before not a date", Draft{Kind: "edition", TS: "2026-10-15T00:00:00Z", Body: setField(minimal("edition"), "contents", body("frozen_before", body("date", "2026-02-30")))}, ed, "no such date"},
	} {
		t.Run(c.name, func(t *testing.T) {
			line, _ := Sign(c.d, c.k)
			_, err := Read(line)
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, c.detail)
		})
	}
}

// TestEnvelopeShape: missing fields, wrong types, signer/sig spellings (§2, §4).
func TestEnvelopeShape(t *testing.T) {
	k := testKeys("A", "B")["B"] // eip191
	line, _ := Sign(authoredDraft(0, ""), k)
	base, _ := canon.Parse(line)
	mutate := func(f func(o *canon.Object)) []byte {
		v, _ := canon.Parse(canon.Encode(base))
		o := v.(*canon.Object)
		f(o)
		return canon.Encode(o)
	}
	drop := func(k string) func(*canon.Object) {
		return func(o *canon.Object) { delete(o.Members, k); o.Keys = deleteKey(o.Keys, k) }
	}
	for _, f := range envFields {
		_, err := Read(mutate(drop(f)))
		refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "missing")
	}
	_, err := Read(mutate(drop("sig")))
	refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "missing sig")
	for name, c := range map[string]struct {
		f      func(*canon.Object)
		detail string
	}{
		"uppercase signer": {func(o *canon.Object) {
			o.Members["signer"] = canon.String(strings.ToUpper(string(o.Members["signer"].(canon.String))))
		}, "neither"},
		"EIP-55 signer": {func(o *canon.Object) {
			s := []byte(o.Members["signer"].(canon.String))
			s[2] = 'F'
			o.Members["signer"] = canon.String(s)
		}, "neither"},
		"uppercase sig": {func(o *canon.Object) {
			o.Members["sig"] = canon.String("0x" + strings.ToUpper(string(o.Members["sig"].(canon.String))[2:]))
		}, "lowercase hex"},
		"sig without 0x":     {func(o *canon.Object) { o.Members["sig"] = canon.String(string(o.Members["sig"].(canon.String))[2:]) }, "lowercase hex"},
		"body not object":    {func(o *canon.Object) { o.Members["body"] = canon.Array{} }, "body is not an object"},
		"seq as string":      {func(o *canon.Object) { o.Members["seq"] = canon.String("0") }, "seq"},
		"ts as int":          {func(o *canon.Object) { o.Members["ts"] = canon.Int(0) }, "ts is not a string"},
		"prev as int":        {func(o *canon.Object) { o.Members["prev"] = canon.Int(0) }, "prev"},
		"ed alg addr signer": {func(o *canon.Object) { o.Members["alg"] = canon.String(AlgEd25519) }, "alg ed25519 with signer 0x"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Read(mutate(c.f))
			refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, c.detail)
		})
	}
	if _, err := Read([]byte(`[1]`)); err == nil {
		t.Fatal("a non-object top level was accepted")
	}
}

func deleteKey(keys []string, k string) []string {
	out := keys[:0:0]
	for _, x := range keys {
		if x != k {
			out = append(out, x)
		}
	}
	return out
}

// TestUnsupported: an unknown rc major, an unknown alg and an unimplemented crit are retained, never refused
// and never evaluated (§4, §6).
func TestUnsupported(t *testing.T) {
	ed := testKeys("A")["A"]
	line, _ := Sign(Draft{RC: "rc/2", Kind: "authored", TS: "not even a time", Body: body()}, ed)
	st, err := Read(line)
	if err != nil || st.Status != Unsupported || st.Why != "rc/2" || st.Verified {
		t.Fatalf("rc/2: %+v %v", st, err)
	}
	// Unknown alg: a well-formed envelope under an algorithm this reader lacks.
	d := authoredDraft(0, "")
	env := d.Envelope(ed)
	env.Members["alg"] = canon.String("ml-dsa-65")
	env.Keys = append(env.Keys, "sig")
	env.Members["sig"] = canon.String("00")
	st, err = Read(canon.Encode(env))
	if err != nil || st.Status != Unsupported || st.Why != "alg ml-dsa-65" || st.Verified || st.ID == "" {
		t.Fatalf("unknown alg: %+v %v", st, err)
	}
	// crit with a valid signature: verified, unsupported, and the body is not read (a bad time inside an
	// unimplemented extension's statement is not this reader's business).
	line, _ = Sign(Draft{Kind: "observed", TS: "2026-10-15T00:00:00Z", Crit: []string{"x_new"},
		Body: body("x_new", 1, "capture", body("at", "whenever"))}, ed)
	st, err = Read(line)
	if err != nil || st.Status != Unsupported || st.Why != "crit x_new" || !st.Verified {
		t.Fatalf("crit: %+v %v", st, err)
	}
	// crit with a bad signature is still refused: unsupported is for valid lines.
	b := bytes.Replace(line, []byte(`"x_new":1`), []byte(`"x_new":2`), 1)
	_, err = Read(b)
	refused(t, err, refusal.Intrinsic, refusal.BadSignature, "")
}

// TestSizeLimit: a signed string of exactly 65 536 bytes passes; one byte more is an operational refusal.
func TestSizeLimit(t *testing.T) {
	k := testKeys("A")["A"]
	mk := func(n int) Draft { return authoredDraft(0, "", "x_pad", strings.Repeat("a", n)) }
	_, _ = Sign(mk(0), k)
	ss := func(d Draft) int { return len(PAE(PayloadType("authored", 1), canon.Encode(d.Envelope(k)))) }
	pad := MaxSignedString - ss(mk(0))
	// the body length field gains digits as the body grows; search the exact boundary
	for ss(mk(pad)) > MaxSignedString {
		pad--
	}
	for ss(mk(pad+1)) <= MaxSignedString {
		pad++
	}
	line, _ := Sign(mk(pad), k)
	if _, err := Read(line); err != nil {
		t.Fatalf("signed string of %d bytes refused: %v", ss(mk(pad)), err)
	}
	line, _ = Sign(mk(pad+1), k)
	_, err := Read(line)
	refused(t, err, refusal.Operational, refusal.SizeLimit, "size limit 65536")
}

// TestSizePrecheck: a line far beyond any signed string the bound admits is refused (operational: size limit)
// before it is parsed: even one that would not parse is refused for size, not for its syntax.
func TestSizePrecheck(t *testing.T) {
	huge := append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), MaxLine)...)
	_, err := Read(huge) // unterminated: a parser would refuse it as malformed
	refused(t, err, refusal.Operational, refusal.SizeLimit, "refused before parsing")
	// A line just under MaxLine is parsed (and here refused for what it is).
	_, err = Read(huge[:MaxLine])
	refused(t, err, refusal.Intrinsic, refusal.MalformedStatement, "")
}

// TestFutureTimestamp: the writer refuses a ts more than 300 s ahead of its clock and accepts 299 s.
func TestFutureTimestamp(t *testing.T) {
	conformance.Covers(t, "C-core-105")
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	k := testKeys("A")["A"]
	at := func(d time.Duration) Draft {
		x := authoredDraft(0, "")
		x.TS = now.Add(d).Format("2006-01-02T15:04:05Z")
		return x
	}
	_, err := Write(at(time.Hour), k, now)
	refused(t, err, refusal.Policy, "future timestamp", "writer policy: max future skew 300 s")
	if _, err := Write(at(299*time.Second), k, now); err != nil {
		t.Fatalf("299 s ahead refused: %v", err)
	}
	if _, err := Write(at(300*time.Second), k, now); err != nil {
		t.Fatalf("300 s ahead refused (the bound is more than 300 s): %v", err)
	}
	_, err = Write(at(301*time.Second), k, now)
	refused(t, err, refusal.Policy, "future timestamp", "")
}

// TestNonCanonicalInputStoredCanonical: a received line with whitespace and reordered keys is admitted when
// its canonical form verifies, and is stored canonical (§1).
func TestNonCanonicalInputStoredCanonical(t *testing.T) {
	v, _ := conformance.LoadVectors()
	x := v.Positive[3] // V4: escapes and raw UTF-8
	canonical := lineFor(t, x.SignedString, x.Sig)
	o, _ := canon.Parse(canonical)
	obj := o.(*canon.Object)
	// reverse key order, add whitespace, escape é as \u00e9 and / as \/
	var b strings.Builder
	b.WriteString("{ ")
	for i := len(obj.Keys) - 1; i >= 0; i-- {
		k := obj.Keys[i]
		fmt.Fprintf(&b, "%q : %s", k, canon.Encode(obj.Members[k]))
		if i > 0 {
			b.WriteString(" ,\n ")
		}
	}
	b.WriteString(" }")
	messy := strings.Replace(b.String(), "météo", `m\u00e9t\u00e9o`, 1)
	st, err := Read([]byte(messy))
	if err != nil {
		t.Fatal(err)
	}
	if st.ID != x.ID || !bytes.Equal(st.Line(), canonical) {
		t.Fatalf("stored %s", st.Line())
	}
}

// TestPropertyOneIDPerBody (P-02 at the wire layer): over generated statement sets, delivering each line
// twice, permuted, and once more with every equivalent EIP-191 signature encoding yields exactly the set of
// ids the writer computed, and one stored line per id.
func TestPropertyOneIDPerBody(t *testing.T) {
	keys := testKeys("A", "B", "C")
	fixture.Check(t, 1, 200, fixture.Default, func(f fixture.Fixture) string {
		want := map[string][]byte{}
		var lines [][]byte
		prev := map[string]string{}
		for _, s := range f.Statements {
			k := keys[s.Signer]
			d := Draft{Kind: s.Kind, Seq: int64(s.Seq), Prev: prev[s.Signer],
				TS: time.Unix(1_790_000_000+int64(s.Time), 0).UTC().Format("2006-01-02T15:04:05Z"), Body: fixtureBody(s)}
			line, id := Sign(d, k)
			prev[s.Signer] = id
			want[id] = line
			lines = append(lines, line, line)
			if k.Alg() == AlgEIP191 {
				st, err := Read(line)
				if err != nil {
					return "writer output refused: " + err.Error()
				}
				raw, _ := hex.DecodeString(st.Sig[2:])
				for _, e := range sig.Equivalents(raw) {
					o, _ := canon.Parse(line)
					o.(*canon.Object).Members["sig"] = canon.String("0x" + hex.EncodeToString(e))
					lines = append(lines, canon.Encode(o))
				}
			}
		}
		got := map[string][]byte{}
		for _, i := range permutation(f.Seed, len(lines)) {
			st, err := Read(lines[i])
			if err != nil {
				return "delivered line refused: " + err.Error()
			}
			if old, dup := got[st.ID]; dup && !bytes.Equal(old, st.Line()) {
				return "one id, two stored forms: " + st.ID
			}
			got[st.ID] = st.Line()
		}
		if len(got) != len(want) {
			return fmt.Sprintf("%d ids from %d bodies", len(got), len(want))
		}
		for id, line := range want {
			if !bytes.Equal(got[id], line) {
				return "stored form differs from the writer's for " + id
			}
		}
		return ""
	})
}

// fixtureBody concretizes an abstract fixture statement into a body that passes §5 for its kind.
func fixtureBody(s fixture.Statement) *canon.Object {
	c := content(fmt.Sprintf("%02x", s.Blob[0]), 10)
	var fields []any
	switch s.Kind {
	case "authored":
		fields = []any{"content", c, "type", "dataset"}
	case "observed":
		fields = []any{"content", c, "class", "none-yet", "referent", body(),
			"capture", body("at", "2026-10-15T00:00:00Z", "evidence", "self-asserted")}
	case "holds":
		fields = []any{"content", c}
	case "describes":
		fields = []any{"about", body("content", c.Members["digest"])}
	}
	if s.Kind == "authored" || s.Kind == "observed" {
		for fk, fv := range s.Fields {
			fields = append(fields, fk, fv)
		}
	}
	return body(fields...)
}

func permutation(seed uint64, n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	x := seed*6364136223846793005 + 1442695040888963407
	for i := n - 1; i > 0; i-- {
		x = x*6364136223846793005 + 1442695040888963407
		j := int((x >> 33) % uint64(i+1))
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// FuzzRead: Read never panics, returns only typed refusals, and anything it accepts as Valid re-reads from
// its stored line to the same id and the same stored line.
func FuzzRead(f *testing.F) {
	v, err := conformance.LoadVectors()
	if err != nil {
		f.Fatal(err)
	}
	for _, x := range append(append([]conformance.Vector{}, v.Positive...), v.EdPositive...) {
		parts := strings.SplitN(x.SignedString, " ", 5)
		f.Add([]byte(parts[4][:len(parts[4])-1] + `,"sig":"` + x.Sig + `"}`))
	}
	for _, x := range v.Negative {
		if x.Delivered != "" {
			f.Add([]byte(x.Delivered))
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		st, err := Read(b)
		if err != nil {
			var r *refusal.Refusal
			if !errors.As(err, &r) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		if st.Status != Valid {
			return
		}
		again, err := Read(st.Line())
		if err != nil || again.ID != st.ID || !bytes.Equal(again.Line(), st.Line()) {
			t.Fatalf("accepted line does not round-trip: %v", err)
		}
	})
}
