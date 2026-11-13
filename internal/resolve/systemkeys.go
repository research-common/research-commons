package resolve

import (
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Method system keys (claims-model note §5.3.1; wire-format note §5 `edition.contents.system_keys`).
//
// A method edition may declare the `referent.system` keys every method-class observation under it must pin. The
// declaration that governs an observation is the one in the edition its `referent.method_edition` names, read
// only once the reader holds that edition as an authorized edition of its resource: a pending, contested,
// invalid or unauthorized proposal declares nothing, and a later edition of the same method never changes how an
// earlier observation reads (§8, "bindings are to editions"). A declared key the observation lacks leaves its
// referent `unpinned`, naming `referent.system.<key>`. A present key counts as pinned unless its value is the
// empty string: that identifies nothing, so it reads as absent (the statement stays admissible; it is never a
// schema refusal).
//
// While the pinned edition is not held as authorized, the reader cannot tell whether a declaration exists: no
// key is marked `unpinned` on that account, and comparability with another method-class observation is
// `unchecked` (I4), never `comparable`.
//
// Every answer is a function of the held statements (the edition's state comes from Resource), so delivery
// order never changes it (I14). The answer is cached per resolver: the resolver is a snapshot.

// Unread reasons for a method edition's declaration, beside the edition states of resource.go.
const (
	// DeclNotHeld: no edition body with that edition id is held, or its resource's genesis is not.
	DeclNotHeld = "not held"
)

// methodDecl is what the reader knows of one method edition's system_keys declaration.
type methodDecl struct {
	Edition string
	// Unread is "" when the edition is held and authorized, so its declaration was read; otherwise why it could
	// not be: DeclNotHeld or the edition's state ("pending", "contested", …).
	Unread string
	// Keys is the declared set when read; nil when the edition declares none (or was not read).
	Keys []string
}

func (d methodDecl) read() bool { return d.Unread == "" }

// history is the one explain line about the declaration, citing the edition.
func (d methodDecl) history(missing []string) string {
	ed := "method edition " + keylog.Short(d.Edition)
	switch {
	case !d.read():
		return ed + " " + d.Unread + ": whether it declares system_keys cannot be read; comparability with other method-class observations is unchecked (claims §5.3.1)"
	case d.Keys == nil:
		return ed + " (authorized) declares no system_keys: comparable with another observation only when both pin the same system keys (claims §5.3.1)"
	case len(missing) > 0:
		return ed + " (authorized) declares system_keys " + strings.Join(d.Keys, ", ") + ": this referent lacks " +
			strings.Join(missing, ", ") + ", so it is unpinned (claims §5.3.1)"
	}
	return ed + " (authorized) declares system_keys " + strings.Join(d.Keys, ", ") + ": every one is pinned"
}

// methodDecl resolves the declaration of edition id ed, once per resolver.
func (r *Resolver) methodDecl(ed string) methodDecl {
	r.sysMu.Lock()
	if d, ok := r.sysDecl[ed]; ok {
		r.sysMu.Unlock()
		return d
	}
	if r.edResource == nil {
		// edition id -> resource, over every held edition body. An edition id is a digest of the whole body,
		// resource included, so it names at most one resource.
		r.edResource = map[string]string{}
		for _, p := range r.byKind["edition"] {
			r.edResource[EditionIDOf(p.St)] = str(p.St.Body, "resource")
		}
	}
	res := r.edResource[ed]
	r.sysMu.Unlock()

	d := methodDecl{Edition: ed, Unread: DeclNotHeld}
	if res != "" {
		if rs, ok := r.Resource(res); ok {
			for _, e := range rs.Editions {
				if e.ID != ed { // an approval's statement id names no edition (wire §3)
					continue
				}
				d.Unread = ""
				if e.State != Authorized {
					d.Unread = string(e.State)
					break
				}
				d.Keys = declaredSystemKeys(e.Body)
			}
		}
	}
	r.sysMu.Lock()
	if r.sysDecl == nil {
		r.sysDecl = map[string]methodDecl{}
	}
	r.sysDecl[ed] = d
	r.sysMu.Unlock()
	return d
}

// declaredSystemKeys reads contents.system_keys from an authorized edition's body; the schema has already
// checked it is a non-empty sorted set of strings. nil when absent.
func declaredSystemKeys(body *canon.Object) []string {
	c := object(body, "contents")
	if c == nil {
		return nil
	}
	v, ok := c.Get("system_keys")
	if !ok {
		return nil
	}
	a, _ := v.(canon.Array)
	var out []string
	for _, x := range a {
		if s, ok := x.(canon.String); ok {
			out = append(out, string(s))
		}
	}
	return out
}

// methodPins is a method-class statement's declaration and its unpinned fields: the schema's (st.Unpinned) plus
// each declared system key it lacks, as `referent.system.<key>`. The result is a fresh slice: the statement's
// own slice is shared by every view and is never mutated.
func (r *Resolver) methodPins(st *wire.Statement) (d methodDecl, unpinned, declMissing []string) {
	ref := object(st.Body, "referent")
	d = r.methodDecl(str(ref, "method_edition"))
	have := pinnedKeys(object(ref, "system"))
	for _, k := range d.Keys {
		if !slices.Contains(have, k) {
			declMissing = append(declMissing, "referent.system."+k)
		}
	}
	unpinned = append(slices.Clone(st.Unpinned), declMissing...)
	if len(unpinned) == 0 {
		unpinned = nil
	}
	return d, unpinned, declMissing
}
