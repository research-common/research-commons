// Package canon is the strict JSON reader and the RFC 8785 (JCS) writer of the wire-format note §1.
//
// Received bytes are never parsed with encoding/json. Its defaults break the format: struct fields match
// case-insensitively, the last duplicate key wins, invalid UTF-8 becomes U+FFFD, and every number is a float.
// This reader refuses instead of repairing, in the I-JSON subset the note allows:
//
//   - UTF-8 only, no BOM, no invalid sequences, no lone surrogates (raw or escaped);
//   - integers only, -?(0|[1-9][0-9]*), magnitude at most 2^53-1, no -0;
//   - no duplicate object keys (compared as decoded strings, with no Unicode normalisation);
//   - nesting depth at most MaxDepth (the outermost value is depth 1).
//
// Whitespace outside strings and any valid JSON string escape are accepted on input; Encode writes the one
// canonical form.
package canon

import (
	"strconv"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/research-common/research-commons/internal/refusal"
)

// MaxDepth is the nesting limit of wire-format note §1. Exceeding it is an operational refusal.
const MaxDepth = 16

// MaxInt is the largest magnitude an integer may have (I-JSON, RFC 7493 §2.2).
const MaxInt = 1<<53 - 1

// Value is one parsed JSON value: Object, Array, String, Int, Bool or Null.
type Value interface{ isValue() }

// Object keeps its members and the order they arrived in (for diagnostics only; Encode sorts).
type Object struct {
	Keys    []string
	Members map[string]Value
}

// Array is an ordered list. Order is significant.
type Array []Value

// String is a decoded JSON string, exactly as the signer wrote it.
type String string

// Int is an integer in the I-JSON range.
type Int int64

// Bool is true or false.
type Bool bool

// Null is the JSON null.
type Null struct{}

func (*Object) isValue() {}
func (Array) isValue()   {}
func (String) isValue()  {}
func (Int) isValue()     {}
func (Bool) isValue()    {}
func (Null) isValue()    {}

// Get returns the member named k and whether it is present.
func (o *Object) Get(k string) (Value, bool) {
	v, ok := o.Members[k]
	return v, ok
}

// Parse reads exactly one JSON value from b under the rules above. Trailing non-whitespace is malformed.
func Parse(b []byte) (Value, error) {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return nil, refusal.Malformed("byte order mark")
	}
	if !utf8.Valid(b) {
		return nil, refusal.Malformed("invalid UTF-8")
	}
	p := &parser{b: b}
	p.ws()
	v, err := p.value(1)
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.b) {
		return nil, p.fail("trailing data")
	}
	return v, nil
}

type parser struct {
	b []byte
	i int
}

func (p *parser) fail(what string) error {
	return refusal.Malformed("%s at byte %d", what, p.i)
}

func (p *parser) ws() {
	for p.i < len(p.b) {
		switch p.b[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) value(depth int) (Value, error) {
	if p.i >= len(p.b) {
		return nil, p.fail("unexpected end of input")
	}
	switch c := p.b[p.i]; {
	case c == '{' || c == '[':
		if depth > MaxDepth {
			return nil, &refusal.Refusal{Class: refusal.Operational, Reason: refusal.DepthLimit,
				Detail: "depth limit " + strconv.Itoa(MaxDepth) + ", scope this object"}
		}
		if c == '{' {
			return p.object(depth)
		}
		return p.array(depth)
	case c == '"':
		s, err := p.str()
		return String(s), err
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case p.lit("true"):
		return Bool(true), nil
	case p.lit("false"):
		return Bool(false), nil
	case p.lit("null"):
		return Null{}, nil
	case p.lit("NaN") || p.lit("Infinity"):
		return nil, refusal.Malformed("non-finite number")
	default:
		return nil, p.fail("unexpected character")
	}
}

func (p *parser) lit(s string) bool {
	if len(p.b)-p.i >= len(s) && string(p.b[p.i:p.i+len(s)]) == s {
		p.i += len(s)
		return true
	}
	return false
}

func (p *parser) object(depth int) (Value, error) {
	p.i++ // {
	o := &Object{Members: map[string]Value{}}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == '}' {
		p.i++
		return o, nil
	}
	for {
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != '"' {
			return nil, p.fail("expected object key")
		}
		k, err := p.str()
		if err != nil {
			return nil, err
		}
		if _, dup := o.Members[k]; dup {
			return nil, refusal.Malformed("duplicate key %q", k)
		}
		p.ws()
		if p.i >= len(p.b) || p.b[p.i] != ':' {
			return nil, p.fail("expected ':'")
		}
		p.i++
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		o.Keys = append(o.Keys, k)
		o.Members[k] = v
		p.ws()
		if p.i >= len(p.b) {
			return nil, p.fail("unterminated object")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return o, nil
		default:
			return nil, p.fail("expected ',' or '}'")
		}
	}
}

func (p *parser) array(depth int) (Value, error) {
	p.i++ // [
	a := Array{}
	p.ws()
	if p.i < len(p.b) && p.b[p.i] == ']' {
		p.i++
		return a, nil
	}
	for {
		p.ws()
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		a = append(a, v)
		p.ws()
		if p.i >= len(p.b) {
			return nil, p.fail("unterminated array")
		}
		switch p.b[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return a, nil
		default:
			return nil, p.fail("expected ',' or ']'")
		}
	}
}

// number accepts the full JSON number grammar so that it can name what is wrong with a fraction or an
// exponent, then refuses everything but an in-range integer.
func (p *parser) number() (Value, error) {
	start := p.i
	if p.b[p.i] == '-' {
		p.i++
	}
	if p.lit("Infinity") {
		return nil, refusal.Malformed("non-finite number")
	}
	digits := p.i
	for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
		p.i++
	}
	if p.i == digits {
		return nil, p.fail("malformed number")
	}
	intPart := string(p.b[digits:p.i])
	frac := false
	if p.i < len(p.b) && p.b[p.i] == '.' {
		frac = true
		p.i++
		d := p.i
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
		if p.i == d {
			return nil, p.fail("malformed number")
		}
	}
	if p.i < len(p.b) && (p.b[p.i] == 'e' || p.b[p.i] == 'E') {
		frac = true
		p.i++
		if p.i < len(p.b) && (p.b[p.i] == '+' || p.b[p.i] == '-') {
			p.i++
		}
		d := p.i
		for p.i < len(p.b) && p.b[p.i] >= '0' && p.b[p.i] <= '9' {
			p.i++
		}
		if p.i == d {
			return nil, p.fail("malformed number")
		}
	}
	text := string(p.b[start:p.i])
	if frac {
		return nil, refusal.Malformed("non-integer number %s", text)
	}
	if len(intPart) > 1 && intPart[0] == '0' {
		return nil, refusal.Malformed("leading zero in number %s", text)
	}
	if text == "-0" {
		return nil, refusal.Malformed("negative zero")
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n > MaxInt || n < -MaxInt {
		return nil, refusal.Malformed("integer out of range %s", text)
	}
	return Int(n), nil
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var out []byte
	for {
		if p.i >= len(p.b) {
			return "", p.fail("unterminated string")
		}
		c := p.b[p.i]
		switch {
		case c == '"':
			p.i++
			return string(out), nil
		case c < 0x20:
			return "", p.fail("raw control character in string")
		case c == '\\':
			p.i++
			if p.i >= len(p.b) {
				return "", p.fail("unterminated escape")
			}
			e := p.b[p.i]
			p.i++
			switch e {
			case '"', '\\', '/':
				out = append(out, e)
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'u':
				r, err := p.hex4()
				if err != nil {
					return "", err
				}
				if utf16.IsSurrogate(r) {
					if r >= 0xDC00 || !p.lit(`\u`) {
						return "", refusal.Malformed("lone surrogate in string")
					}
					r2, err := p.hex4()
					if err != nil {
						return "", err
					}
					if r2 < 0xDC00 || r2 > 0xDFFF {
						return "", refusal.Malformed("lone surrogate in string")
					}
					r = utf16.DecodeRune(r, r2)
				}
				out = utf8.AppendRune(out, r)
			default:
				return "", p.fail("invalid escape")
			}
		default:
			// utf8.Valid on the whole input already refused invalid sequences and encoded surrogates.
			out = append(out, c)
			p.i++
		}
	}
}

func (p *parser) hex4() (rune, error) {
	if len(p.b)-p.i < 4 {
		return 0, p.fail("short \\u escape")
	}
	n, err := strconv.ParseUint(string(p.b[p.i:p.i+4]), 16, 32)
	if err != nil {
		return 0, p.fail("invalid \\u escape")
	}
	p.i += 4
	return rune(n), nil
}
