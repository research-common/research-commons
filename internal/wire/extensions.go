package wire

import (
	"fmt"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

// ExtensionValidator checks a critical body extension and its envelope context. It receives a private
// deep copy of the verified envelope without sig; the named extension is in its body object. A nil error
// accepts the extension; any non-nil error refuses the whole statement as malformed. The validator cannot
// replace the statement, alter its signed bytes, or promote an unknown kind to Valid.
//
// Validators are trusted local code, not received data. They must be deterministic, side-effect-free and
// safe for concurrent calls. They run in crit order, only after every crit name is registered, the base
// kind schema and body times pass, and the signature verifies. No validator runs for an unlisted extension,
// an unsupported major or algorithm, or a crit list containing even one unsupported name.
type ExtensionValidator func(envelope *canon.Object) error

// Reader is a wire reader with a fixed registry of critical-extension validators. Its zero value has no
// extensions and behaves exactly like Read. There are no built-in registrations or global registration
// hooks. A Reader is safe for concurrent use if its validators obey the ExtensionValidator contract.
type Reader struct {
	extensions map[string]ExtensionValidator
}

// NewReader copies a local registry. Names follow the existing crit rule (the x_ prefix); nil validators
// and non-extension names are configuration errors. Changing the supplied map later does not change the
// reader. Registration opts into validation, not new base kinds or resolver semantics.
func NewReader(extensions map[string]ExtensionValidator) (*Reader, error) {
	r := &Reader{extensions: make(map[string]ExtensionValidator, len(extensions))}
	names := make([]string, 0, len(extensions))
	for name := range extensions {
		names = append(names, name)
	}
	slices.Sort(names) // stable diagnostics if several registrations are invalid
	for _, name := range names {
		if !strings.HasPrefix(name, "x_") {
			return nil, fmt.Errorf("extension registry: %q is not an extension name", name)
		}
		if extensions[name] == nil {
			return nil, fmt.Errorf("extension registry: %q has a nil validator", name)
		}
		r.extensions[name] = extensions[name]
	}
	return r, nil
}

// supports preflights the entire list before any body interpretation or callback. In particular, a known
// prefix of a mixed known/unknown crit list must never partially execute.
func (r *Reader) supports(crit []string) bool {
	for _, name := range crit {
		if r.extensions[name] == nil {
			return false
		}
	}
	return true
}

func (r *Reader) validateExtensions(crit []string, env *canon.Object) error {
	for _, name := range crit {
		// Each validator gets its own copy, so even accidental mutation cannot affect later validators,
		// the returned Body, Line, ID or signed string. No caller-owned result is committed on failure.
		if err := r.extensions[name](copyExtensionValue(env).(*canon.Object)); err != nil {
			return refusal.Malformed("crit %q: %v", name, err)
		}
	}
	return nil
}

// copyExtensionValue copies the mutable parts of an already parsed value; scalar values are immutable.
func copyExtensionValue(v canon.Value) canon.Value {
	switch v := v.(type) {
	case *canon.Object:
		o := &canon.Object{Keys: slices.Clone(v.Keys), Members: make(map[string]canon.Value, len(v.Members))}
		for k, value := range v.Members {
			o.Members[k] = copyExtensionValue(value)
		}
		return o
	case canon.Array:
		a := make(canon.Array, len(v))
		for i, value := range v {
			a[i] = copyExtensionValue(value)
		}
		return a
	default:
		return v
	}
}
