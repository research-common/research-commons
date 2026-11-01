package identitymodel

import (
	"reflect"
	"strconv"
	"strings"
)

// modelKey is an unambiguous, length-framed encoding of the model's fixed Go
// value schema, solely for deterministic model digests and explanation ordering.
// It is NOT JSON, wire canonicalization, a statement ID, or a signing preimage.
// Struct fields are encoded in declaration order; changing this schema requires
// an EvaluatorVersion change. No caller-supplied interfaces or maps enter it.
func modelKey(value any) string {
	var b strings.Builder
	var encode func(reflect.Value)
	encode = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			b.WriteByte('s')
			b.WriteString(strconv.Itoa(v.Len()))
			b.WriteByte(':')
			b.WriteString(v.String())
		case reflect.Uint8, reflect.Uint64:
			b.WriteByte('u')
			b.WriteString(strconv.FormatUint(v.Uint(), 10))
			b.WriteByte(';')
		case reflect.Bool:
			if v.Bool() {
				b.WriteString("b1")
			} else {
				b.WriteString("b0")
			}
		case reflect.Pointer:
			if v.IsNil() {
				b.WriteByte('n')
			} else {
				b.WriteByte('p')
				encode(v.Elem())
			}
		case reflect.Slice:
			b.WriteByte('a')
			b.WriteString(strconv.Itoa(v.Len()))
			b.WriteByte(':')
			for i := 0; i < v.Len(); i++ {
				encode(v.Index(i))
			}
		case reflect.Struct:
			b.WriteByte('r')
			b.WriteString(strconv.Itoa(v.NumField()))
			b.WriteByte(':')
			for i := 0; i < v.NumField(); i++ {
				encode(v.Field(i))
			}
		default:
			panic("identitymodel: unsupported internal digest schema type: " + v.Kind().String())
		}
	}
	encode(reflect.ValueOf(value))
	return b.String()
}
