package canon

import (
	"slices"
	"strconv"
	"unicode/utf16"
)

// Encode writes v in the canonical form of wire-format note §1 (RFC 8785 restricted to integers): no
// whitespace, object keys sorted by UTF-16 code units, strings escaped per RFC 8785 §3.2.2.2.
func Encode(v Value) []byte {
	return appendValue(nil, v)
}

func appendValue(b []byte, v Value) []byte {
	switch x := v.(type) {
	case *Object:
		b = append(b, '{')
		for i, k := range SortedKeys(x) {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendString(b, k)
			b = append(b, ':')
			b = appendValue(b, x.Members[k])
		}
		return append(b, '}')
	case Array:
		b = append(b, '[')
		for i, e := range x {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendValue(b, e)
		}
		return append(b, ']')
	case String:
		return appendString(b, string(x))
	case Int:
		return strconv.AppendInt(b, int64(x), 10)
	case Bool:
		return strconv.AppendBool(b, bool(x))
	case Null:
		return append(b, "null"...)
	}
	panic("canon: unknown value type")
}

// SortedKeys returns o's keys in RFC 8785 §3.2.3 order.
func SortedKeys(o *Object) []string {
	keys := slices.Clone(o.Keys)
	slices.SortFunc(keys, CompareKeys)
	return keys
}

// CompareKeys orders two keys by their UTF-16 code units compared as unsigned integers (RFC 8785 §3.2.3).
// This differs from byte or code-point order only for characters above U+FFFF (vector V10).
func CompareKeys(a, b string) int {
	return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(b)))
}

const hexDigits = "0123456789abcdef"

func appendString(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			b = append(b, '\\', '"')
		case '\\':
			b = append(b, '\\', '\\')
		case '\b':
			b = append(b, '\\', 'b')
		case '\t':
			b = append(b, '\\', 't')
		case '\n':
			b = append(b, '\\', 'n')
		case '\f':
			b = append(b, '\\', 'f')
		case '\r':
			b = append(b, '\\', 'r')
		default:
			if c < 0x20 {
				b = append(b, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xF])
			} else {
				b = append(b, c) // every other byte raw, including multi-byte UTF-8 and '/'
			}
		}
	}
	return append(b, '"')
}
