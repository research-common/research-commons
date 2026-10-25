package cli

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/research-common/research-commons/internal/canon"
)

// Every command builds one result tree of typed values, and both surfaces are rendered from it: the JSON
// surface through canon, the human surface through human(). Because both come from one tree, a state token
// cannot differ between them (C-core-134), and the type of each leaf decides how it is rendered:
//
//   - tokV: a word of the closed vocabulary, checked at construction (tok);
//   - textV: the tool's own words (labels, explanations); never carries peer text;
//   - refV: an id, digest or key, shape-checked by the caller; printed in full;
//   - peerV: text a peer signed or a user typed; rendered inert and quoted on the human surface, and a JSON
//     string (or a JSON value) on the JSON surface, never interpolated into the tool's own text (C-core-122);
//   - rawV: a peer-supplied JSON value (a single-party field); embedded as JSON, shown as inert canonical text.

type value interface{ isValue() }

type (
	tokV  string
	textV string
	refV  string
	peerV string
	intV  int64
	boolV bool
	rawV  struct{ v canon.Value }
	listV []value
)

// Obj is an ordered object: insertion order on the human surface, canonical order in JSON.
type Obj struct {
	keys []string
	vals map[string]value
}

func (tokV) isValue()  {}
func (textV) isValue() {}
func (refV) isValue()  {}
func (peerV) isValue() {}
func (intV) isValue()  {}
func (boolV) isValue() {}
func (rawV) isValue()  {}
func (listV) isValue() {}
func (*Obj) isValue()  {}

func newObj() *Obj { return &Obj{vals: map[string]value{}} }

// set adds or replaces a member; a nil value is skipped.
func (o *Obj) set(k string, v value) *Obj {
	if v == nil {
		return o
	}
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *Obj) get(k string) value { return o.vals[k] }

func tokens(ws ...string) listV {
	l := listV{}
	for _, w := range ws {
		l = append(l, tokV(tok(w)))
	}
	return l
}

func refs(ss ...string) listV {
	l := listV{}
	for _, s := range ss {
		l = append(l, refV(s))
	}
	return l
}

func texts(ss ...string) listV {
	l := listV{}
	for _, s := range ss {
		l = append(l, textV(s))
	}
	return l
}

// --- JSON surface ------------------------------------------------------------------------------------------

func toCanon(v value) canon.Value {
	switch x := v.(type) {
	case tokV:
		return canon.String(x)
	case textV:
		return canon.String(x)
	case refV:
		return canon.String(x)
	case peerV:
		return canon.String(x)
	case intV:
		return canon.Int(x)
	case boolV:
		return canon.Bool(x)
	case rawV:
		return x.v
	case listV:
		a := canon.Array{}
		for _, e := range x {
			a = append(a, toCanon(e))
		}
		return a
	case *Obj:
		o := &canon.Object{Members: map[string]canon.Value{}}
		for _, k := range x.keys {
			o.Keys = append(o.Keys, k)
			o.Members[k] = toCanon(x.vals[k])
		}
		return o
	}
	panic("cli: unknown value type")
}

// encodeJSON is the JSON surface: canonical JSON, one object, newline-terminated. canon escapes the C0
// controls; every other code point that is not graphic (C1 controls, bidirectional overrides, zero-width
// joiners, unassigned) is escaped here too, so the bytes on stdout carry no control sequence even when a
// consumer prints them raw. The JSON value is unchanged: \uXXXX is the same string.
func encodeJSON(v value) []byte {
	return append(inertJSON(canon.Encode(toCanon(v))), '\n')
}

func inertJSON(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r < utf8.RuneSelf || unicode.IsGraphic(r) && r != '\u2028' && r != '\u2029' {
			out = append(out, b[i:i+n]...)
		} else if r > 0xFFFF {
			r1, r2 := utf16Pair(r)
			out = append(out, `\u`+hex4(r1)+`\u`+hex4(r2)...)
		} else {
			out = append(out, `\u`+hex4(r)...)
		}
		i += n
	}
	return out
}

func utf16Pair(r rune) (rune, rune) {
	r -= 0x10000
	return 0xD800 + (r>>10)&0x3FF, 0xDC00 + r&0x3FF
}

func hex4(r rune) string {
	s := strconv.FormatInt(int64(r), 16)
	return strings.Repeat("0", 4-len(s)) + s
}

// --- human surface -----------------------------------------------------------------------------------------

// inert makes any string safe to print on a terminal: every rune that is not graphic (C0 and C1 controls,
// ESC, bidirectional overrides, line separators) is shown as an escape, and nothing else is changed. HTML and
// shell metacharacters are printable and stay as they are: on a terminal they are text, and no code path of
// this tool interprets output.
func inert(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == utf8.RuneError:
			b.WriteString(`\ufffd`)
		case unicode.IsGraphic(r) && r != '\u2028' && r != '\u2029' && !unicode.Is(unicode.Bidi_Control, r):
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x100:
			b.WriteString(`\x` + hex4(r)[2:])
		case r > 0xFFFF:
			b.WriteString(`\U` + strings.Repeat("0", 8-len(strconv.FormatInt(int64(r), 16))) + strconv.FormatInt(int64(r), 16))
		default:
			b.WriteString(`\u` + hex4(r))
		}
	}
	return b.String()
}

// quoteGraphic is peer text on the human surface: inert, inside double quotes with quotes and backslashes
// escaped, so where the peer's text starts and ends is never ambiguous.
func quoteGraphic(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + inert(s) + `"`
}

func scalar(v value) (string, bool) {
	switch x := v.(type) {
	case tokV:
		return string(x), true
	case textV:
		return inert(string(x)), true
	case refV:
		return inert(string(x)), true
	case peerV:
		return quoteGraphic(string(x)), true
	case intV:
		return strconv.FormatInt(int64(x), 10), true
	case boolV:
		if x {
			return "yes", true
		}
		return "no", true
	case rawV:
		return inert(string(canon.Encode(x.v))), true
	}
	return "", false
}

func human(o *Obj) string {
	var b strings.Builder
	writeObj(&b, o, "")
	return b.String()
}

func writeObj(b *strings.Builder, o *Obj, ind string) {
	for _, k := range o.keys {
		writeMember(b, k, o.vals[k], ind)
	}
}

func writeMember(b *strings.Builder, k string, v value, ind string) {
	label := strings.ReplaceAll(k, "_", " ")
	if s, ok := scalar(v); ok {
		b.WriteString(ind + label + ": " + s + "\n")
		return
	}
	switch x := v.(type) {
	case listV:
		if len(x) == 0 {
			b.WriteString(ind + label + ": (none)\n")
			return
		}
		allScalar := true
		var parts []string
		for _, e := range x {
			s, ok := scalar(e)
			allScalar = allScalar && ok
			parts = append(parts, s)
		}
		if allScalar {
			b.WriteString(ind + label + ": " + strings.Join(parts, ", ") + "\n")
			return
		}
		b.WriteString(ind + label + ":\n")
		for _, e := range x {
			if s, ok := scalar(e); ok {
				b.WriteString(ind + "  - " + s + "\n")
				continue
			}
			if eo, ok := e.(*Obj); ok {
				var sub strings.Builder
				writeObj(&sub, eo, ind+"    ")
				s := sub.String()
				b.WriteString(ind + "  - " + strings.TrimPrefix(s, ind+"    "))
			}
		}
	case *Obj:
		b.WriteString(ind + label + ":\n")
		writeObj(b, x, ind+"  ")
	}
}
