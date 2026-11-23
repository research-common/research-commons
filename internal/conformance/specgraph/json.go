package specgraph

import (
	"strconv"

	"github.com/research-common/research-commons/internal/canon"
)

// The two files this package writes are JSON for people and scripts to read, never signed and never read
// back as a statement, so they are written here with a fixed member order rather than in canonical form.

// member is one name and value of an object; object keeps its members in the order given.
type member struct {
	k string
	v any
}
type object []member

// appendJSON writes v on one line. v is a string, an int, a []string, a []any or an object.
func appendJSON(b []byte, v any) []byte {
	switch x := v.(type) {
	case string:
		return append(b, canon.Encode(canon.String(x))...)
	case int:
		return strconv.AppendInt(b, int64(x), 10)
	case []string:
		b = append(b, '[')
		for i, e := range x {
			if i > 0 {
				b = append(b, ", "...)
			}
			b = appendJSON(b, e)
		}
		return append(b, ']')
	case []any:
		b = append(b, '[')
		for i, e := range x {
			if i > 0 {
				b = append(b, ", "...)
			}
			b = appendJSON(b, e)
		}
		return append(b, ']')
	case object:
		b = append(b, '{')
		for i, m := range x {
			if i > 0 {
				b = append(b, ", "...)
			}
			b = appendJSON(b, m.k)
			b = append(b, ": "...)
			b = appendJSON(b, m.v)
		}
		return append(b, '}')
	}
	panic("specgraph: value of a type the writer does not know")
}

// document writes a top-level object: one member per line, and a member that is a list of objects one object
// per line, so a change to one case is a change to one line.
func document(top object) []byte {
	b := []byte("{\n")
	for i, m := range top {
		b = append(b, "  "...)
		b = appendJSON(b, m.k)
		b = append(b, ": "...)
		if list, ok := m.v.([]any); ok && len(list) > 0 {
			b = append(b, "[\n"...)
			for j, e := range list {
				b = append(b, "    "...)
				b = appendJSON(b, e)
				if j+1 < len(list) {
					b = append(b, ',')
				}
				b = append(b, '\n')
			}
			b = append(b, "  ]"...)
		} else {
			b = appendJSON(b, m.v)
		}
		if i+1 < len(top) {
			b = append(b, ',')
		}
		b = append(b, '\n')
	}
	return append(b, "}\n"...)
}
