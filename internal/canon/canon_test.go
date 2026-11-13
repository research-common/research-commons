package canon_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

func refusedAs(t *testing.T, in string, class refusal.Class, detail string) {
	t.Helper()
	_, err := canon.Parse([]byte(in))
	var r *refusal.Refusal
	if !errors.As(err, &r) || r.Class != class || !strings.Contains(r.Detail, detail) {
		t.Errorf("canon.Parse(%.40q) = %v, want %s …%s…", in, err, class, detail)
	}
}

// TestParseRefuses covers the input rules of wire-format note §1 one by one (the case, delivered through pull: internal/cli TestPullParserRefusals, C-core-12).
func TestParseRefuses(t *testing.T) {
	in := refusal.Intrinsic
	for _, c := range []struct{ in, detail string }{
		{`{"a":1,"a":2}`, `duplicate key "a"`},
		{`{"a":{"b":1,"b":1}}`, `duplicate key "b"`},
		{`{"\u0061":1,"a":2}`, `duplicate key "a"`}, // escapes decode before comparison
		{`{"a":NaN}`, "non-finite"},
		{`{"a":Infinity}`, "non-finite"},
		{`{"a":-Infinity}`, "non-finite"},
		{`{"a":1.0}`, "non-integer"},
		{`{"a":1e3}`, "non-integer"},
		{`{"a":1E+0}`, "non-integer"},
		{`{"a":-0}`, "negative zero"},
		{`{"a":01}`, "leading zero"},
		{`{"a":9007199254740992}`, "out of range"},
		{`{"a":-9007199254740992}`, "out of range"},
		{`{"a":"\ud800"}`, "lone surrogate"},
		{`{"a":"\udc00"}`, "lone surrogate"},
		{`{"a":"\ud800\u0041"}`, "lone surrogate"},
		{"{\"a\":\"\xff\"}", "invalid UTF-8"},
		{"{\"a\":\"\xed\xa0\x80\"}", "invalid UTF-8"}, // a surrogate encoded directly in UTF-8
		{"\xef\xbb\xbf{}", "byte order mark"},
		{"{\"a\":\"x\ny\"}", "raw control character"},
		{`{"a":1}x`, "trailing data"},
		{`{"a":1,}`, "expected object key"},
		{`[1,]`, "unexpected character"},
		{`{"a":"\x"}`, "invalid escape"},
		{``, "unexpected end"},
	} {
		refusedAs(t, c.in, in, c.detail)
	}
}

func TestParseAccepts(t *testing.T) {
	for in, want := range map[string]string{
		` { "b" : [ 1 , -2 , true , false , null ] , "a" : "x" } `: `{"a":"x","b":[1,-2,true,false,null]}`,
		`{"a":9007199254740991,"b":-9007199254740991}`:             `{"a":9007199254740991,"b":-9007199254740991}`,
		`"\u00e9\/\ud83d\ude00"`:                                   `"é/😀"`,
		`{"e\u0301":1,"\u00e9":2}`:                                 "{\"e\u0301\":1,\"é\":2}", // no normalisation: two keys
		`"\u001f\u0001\b\f\n\r\t\"\\"`:                             `"\u001f\u0001\b\f\n\r\t\"\\"`,
		`[]`:                                                       `[]`,
		`{}`:                                                       `{}`,
		`0`:                                                        `0`,
	} {
		v, err := canon.Parse([]byte(in))
		if err != nil {
			t.Errorf("canon.Parse(%q): %v", in, err)
			continue
		}
		if got := string(canon.Encode(v)); got != want {
			t.Errorf("canon.Encode(canon.Parse(%q)) = %s, want %s", in, got, want)
		}
	}
}

// TestDepth: the outermost value is depth 1; 16 nested containers pass, 17 is an operational refusal.
func TestDepth(t *testing.T) {
	nest := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	if _, err := canon.Parse([]byte(nest(canon.MaxDepth))); err != nil {
		t.Fatalf("depth %d refused: %v", canon.MaxDepth, err)
	}
	refusedAs(t, nest(canon.MaxDepth+1), refusal.Operational, "depth limit 16")
}

// TestKeyOrderUTF16 pins RFC 8785 §3.2.3: U+1F600 (surrogate 0xD83D) sorts before U+FF71.
func TestKeyOrderUTF16(t *testing.T) {
	v, _ := canon.Parse([]byte(`{"x_ｱ":1,"x_😀":2,"b":3,"a":4,"":5}`))
	if got := string(canon.Encode(v)); got != `{"":5,"a":4,"b":3,"x_😀":2,"x_ｱ":1}` {
		t.Fatal(got)
	}
}

// FuzzParse: anything Parse accepts re-encodes to a fixed point that re-parses to the same bytes, and the
// encoding is valid UTF-8 with no whitespace outside strings. Anything it refuses is a *refusal.Refusal.
func FuzzParse(f *testing.F) {
	for _, s := range []string{`{"a":1}`, `[1,"x",{"b":null}]`, `{"a":1,"a":2}`, `{"a":1.0}`, `"\ud83d\ude00"`,
		`{"x_ｱ":1,"x_😀":2}`, `{"a":"\u0000"}`, `-0`, `[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := canon.Parse(b)
		if err != nil {
			var r *refusal.Refusal
			if !errors.As(err, &r) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		enc := canon.Encode(v)
		if !utf8.Valid(enc) {
			t.Fatal("encoding is not UTF-8")
		}
		v2, err := canon.Parse(enc)
		if err != nil {
			t.Fatalf("canonical form %q does not re-parse: %v", enc, err)
		}
		if !bytes.Equal(canon.Encode(v2), enc) {
			t.Fatalf("not a fixed point: %q", enc)
		}
	})
}

// TestParseData: captured data is read as I-JSON, not as the signed-body subset. A fraction, an exponent, -0 and an
// integer past 2^53-1 are kept as Number (Parse refuses each, the control); everything else Parse refuses is still
// refused, and a number past the double range is refused.
func TestParseData(t *testing.T) {
	for in, want := range map[string]canon.Value{
		`1.5`:                    canon.Number("1.5"),
		`-0`:                     canon.Number("-0"),
		`1e3`:                    canon.Number("1e3"),
		`9007199254740992`:       canon.Number("9007199254740992"),
		`9007199254740991`:       canon.Int(9007199254740991),
		`-12`:                    canon.Int(-12),
		`"RF"`:                   canon.String("RF"),
		`1.7976931348623157e308`: canon.Number("1.7976931348623157e308"),
	} {
		v, err := canon.ParseData([]byte(in))
		if err != nil || v != want {
			t.Errorf("ParseData(%s) = %#v, %v; want %#v", in, v, err, want)
		}
		if _, err := canon.Parse([]byte(in)); (err == nil) != (want == canon.Int(-12) || want == canon.Int(9007199254740991) || want == canon.String("RF")) {
			t.Errorf("Parse(%s): err %v (control: the signed-body subset)", in, err)
		}
	}
	for _, c := range []struct{ in, detail string }{
		{`{"a":1,"a":2}`, `duplicate key "a"`},
		{`{"a":1e400}`, "IEEE 754 double range"},
		{`{"a":01.5}`, "leading zero"},
		{`{"a":NaN}`, "non-finite"},
		{`{"a":"\ud800"}`, "lone surrogate"},
		{"\xef\xbb\xbf{}", "byte order mark"},
		{`{"a":1.}`, "malformed number"},
	} {
		_, err := canon.ParseData([]byte(c.in))
		rf, ok := err.(*refusal.Refusal)
		if !ok || rf.Class != refusal.Intrinsic || !strings.Contains(rf.Detail, c.detail) {
			t.Errorf("ParseData(%q): %v, want intrinsic %q", c.in, err, c.detail)
		}
	}
	if _, err := canon.ParseData([]byte(strings.Repeat("[", canon.MaxDepth+1) + strings.Repeat("]", canon.MaxDepth+1))); err == nil {
		t.Error("ParseData: depth limit not applied")
	}
}
