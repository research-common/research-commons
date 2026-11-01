// Package policy is the reader's local policy, `reader-policy-v1` (fixed-root identity note §6 and its linked
// schema `docs/fixed-root-identity-policy.schema.json`).
//
// A policy is a local file the reader writes. Received objects never install or modify it (claims-model I9,
// "data never carries control"). It holds two separate things, never merged into one:
//
//   - selections: for one (content digest, role), either an exact statement pin (`statement: S`) or a
//     principal to follow (`principal: {key: K}` or `principal: {identity: I}`);
//   - trust: a principal trusted for a set of purposes (`attestation`, `corroboration`, `admission`) over a
//     content target (`any_content`, or an explicit set of digests).
//
// Parse is strict and closed: the strict JSON reader (package canon), the schema's shapes and enums, at most
// 256 entries per array, entries sorted by their canonical (JCS) text, purposes and explicit contents sorted as
// string sets, one selection per (content, role) even when the two selections differ, identical trust entries
// refused, and at most 65,536 canonical bytes. Every failure happens before any evaluation and is an *Error,
// which a command maps to exit 2 (claims-model §13, C-core-133a).
//
// The digest of a policy is `sha256:` + SHA-256(JCS(policy)), version included. Every resolver answer a policy
// changes cites it, so two readers that differ only by policy see which policy made the difference (P-11).
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// Version is the only policy version this reader understands.
const Version = "reader-policy-v1"

// Limits (note §6; the input bound reuses the wire format's preparse line bound, note §2.2).
const (
	MaxEntries   = 256
	MaxCanonical = wire.MaxSignedString
	MaxInput     = wire.MaxLine
)

// Selection roles (note §6 table).
const (
	RoleAuthorship  = "authorship-declaration"  // an `authored` of that exact content digest
	RoleWorkflow    = "workflow-declaration"    // an `authored` of that digest with type "workflow"
	RoleObservation = "observation-declaration" // an `observed` of that exact digest
)

// Trust purposes (note §6). A purpose matches only itself.
const (
	PurposeAttestation   = "attestation"
	PurposeCorroboration = "corroboration"
	PurposeAdmission     = "admission"
)

var (
	roles    = []string{RoleAuthorship, RoleWorkflow, RoleObservation}
	purposes = []string{PurposeAttestation, PurposeCorroboration, PurposeAdmission}
	reID     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reKey    = regexp.MustCompile(`^(ed25519:[0-9a-f]{64}|0x[0-9a-f]{40})$`)
)

// ErrInvalid is matched (errors.Is) by every policy parse or validation failure.
var ErrInvalid = errors.New("invalid reader policy")

// Error is a policy that cannot be used: malformed, over a limit, an unknown token, unsorted, a duplicate or a
// conflicting selection. It is an invocation error, raised before any evaluation (exit 2, C-core-133a).
type Error struct {
	Path   string // JSON path of the offending value ("$" for the whole document)
	Reason string
	Err    error // the underlying strict-reader refusal, when there is one
}

func (e *Error) Error() string { return "reader policy: " + e.Path + ": " + e.Reason }

// Unwrap returns the strict reader's refusal, when there is one.
func (e *Error) Unwrap() error { return e.Err }

// Is makes errors.Is(err, ErrInvalid) true for every policy error.
func (e *Error) Is(target error) bool { return target == ErrInvalid }

// ExitCode is the command exit for an unusable policy: 2, an invocation error, before any work (claims §13).
func (e *Error) ExitCode() int { return 2 }

func fail(path, format string, args ...any) *Error {
	return &Error{Path: path, Reason: fmt.Sprintf(format, args...)}
}

// Principal is a typed principal: exactly one of Key (a bare signing key) or Identity (an identity id of the
// fixed-root profile, which this reader does not activate).
type Principal struct {
	Key, Identity string
}

func (p Principal) String() string {
	if p.Key != "" {
		return "key " + p.Key
	}
	return "identity " + p.Identity
}

// Selection is one selection entry: the subject (Content, Role) and exactly one of Statement or Principal.
type Selection struct {
	Content, Role string
	Statement     string
	Principal     *Principal
	text          string // canonical JCS text of the entry
}

// String is the entry's canonical text: a stable name for it in explanations and diffs.
func (s Selection) String() string { return s.text }

// Trust is one trust entry: Principal is trusted for Purposes over the content target (AnyContent, or
// Contents).
type Trust struct {
	Principal  Principal
	Purposes   []string
	AnyContent bool
	Contents   []string
	text       string
}

// String is the entry's canonical text.
func (t Trust) String() string { return t.text }

// Policy is a parsed, validated reader policy. The zero of *Policy (nil) is "no policy configured": every
// method answers for that case, and the resolver behaves exactly as it does without one.
type Policy struct {
	Selections []Selection
	Trust      []Trust
	// Digest is "sha256:" + SHA-256 of Canonical.
	Digest string
	// Canonical is JCS(policy).
	Canonical []byte
}

// Parse reads and validates a policy. Any failure is an *Error.
func Parse(b []byte) (*Policy, error) {
	if len(b) > MaxInput {
		return nil, fail("$", "input size limit (%d bytes > %d)", len(b), MaxInput)
	}
	v, err := canon.Parse(b)
	if err != nil {
		return nil, &Error{Path: "$", Reason: err.Error(), Err: err}
	}
	enc := canon.Encode(v)
	if len(enc) > MaxCanonical {
		return nil, fail("$", "canonical size limit (%d bytes > %d)", len(enc), MaxCanonical)
	}
	root, err := closed(v, "$", []string{"version", "selections", "trust"}, nil)
	if err != nil {
		return nil, err
	}
	if s, ok := root.Members["version"].(canon.String); !ok || string(s) != Version {
		return nil, fail("$.version", "unknown policy version (want %q)", Version)
	}
	p := &Policy{Canonical: enc}
	sum := sha256.Sum256(enc)
	p.Digest = "sha256:" + hex.EncodeToString(sum[:])

	sels, err := entries(root.Members["selections"], "$.selections")
	if err != nil {
		return nil, err
	}
	subjects := map[string]int{}
	for i, e := range sels {
		path := fmt.Sprintf("$.selections[%d]", i)
		s, err := selection(e, path)
		if err != nil {
			return nil, err
		}
		key := s.Content + "\x00" + s.Role
		if j, dup := subjects[key]; dup {
			return nil, fail(path, "a second selection for content %s role %s (first at $.selections[%d]); one selection per content and role, even when they differ", s.Content, s.Role, j)
		}
		subjects[key] = i
		p.Selections = append(p.Selections, s)
	}
	trusts, err := entries(root.Members["trust"], "$.trust")
	if err != nil {
		return nil, err
	}
	for i, e := range trusts {
		t, err := trust(e, fmt.Sprintf("$.trust[%d]", i))
		if err != nil {
			return nil, err
		}
		p.Trust = append(p.Trust, t)
	}
	return p, nil
}

// entries checks an entry array: at most MaxEntries, each entry's canonical text strictly after the previous
// one's (sorted, and no identical entries).
func entries(v canon.Value, path string) ([]canon.Value, error) {
	a, ok := v.(canon.Array)
	if !ok {
		return nil, fail(path, "not an array")
	}
	if len(a) > MaxEntries {
		return nil, fail(path, "%d entries (at most %d)", len(a), MaxEntries)
	}
	prev := ""
	for i, e := range a {
		t := string(canon.Encode(e))
		if i > 0 {
			switch c := canon.CompareKeys(prev, t); {
			case c == 0:
				return nil, fail(fmt.Sprintf("%s[%d]", path, i), "identical to the previous entry (identical entries are refused)")
			case c > 0:
				return nil, fail(fmt.Sprintf("%s[%d]", path, i), "entries are not sorted by their canonical (JCS) text")
			}
		}
		prev = t
	}
	return a, nil
}

// closed checks that v is an object whose members are exactly the required ones plus any of the optional ones.
func closed(v canon.Value, path string, required, optional []string) (*canon.Object, error) {
	o, ok := v.(*canon.Object)
	if !ok {
		return nil, fail(path, "not an object")
	}
	for _, k := range o.Keys {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return nil, fail(path, "unknown member %q", k)
		}
	}
	for _, k := range required {
		if _, ok := o.Members[k]; !ok {
			return nil, fail(path, "missing member %q", k)
		}
	}
	return o, nil
}

func pattern(v canon.Value, path string, re *regexp.Regexp, what string) (string, error) {
	s, ok := v.(canon.String)
	if !ok || !re.MatchString(string(s)) {
		return "", fail(path, "not a %s", what)
	}
	return string(s), nil
}

func selection(v canon.Value, path string) (Selection, error) {
	o, err := closed(v, path, []string{"subject"}, []string{"statement", "principal"})
	if err != nil {
		return Selection{}, err
	}
	_, hasS := o.Members["statement"]
	_, hasP := o.Members["principal"]
	if hasS == hasP {
		return Selection{}, fail(path, "exactly one of statement or principal")
	}
	subj, err := closed(o.Members["subject"], path+".subject", []string{"content", "role"}, nil)
	if err != nil {
		return Selection{}, err
	}
	s := Selection{text: string(canon.Encode(o))}
	if s.Content, err = pattern(subj.Members["content"], path+".subject.content", reDigest, "content digest"); err != nil {
		return Selection{}, err
	}
	role, ok := subj.Members["role"].(canon.String)
	if !ok || !slices.Contains(roles, string(role)) {
		return Selection{}, fail(path+".subject.role", "unknown role")
	}
	s.Role = string(role)
	if hasS {
		if s.Statement, err = pattern(o.Members["statement"], path+".statement", reID, "statement id"); err != nil {
			return Selection{}, err
		}
		return s, nil
	}
	pr, err := principal(o.Members["principal"], path+".principal")
	if err != nil {
		return Selection{}, err
	}
	s.Principal = &pr
	return s, nil
}

func principal(v canon.Value, path string) (Principal, error) {
	o, err := closed(v, path, nil, []string{"key", "identity"})
	if err != nil {
		return Principal{}, err
	}
	if len(o.Keys) != 1 {
		return Principal{}, fail(path, "exactly one of key or identity")
	}
	var p Principal
	if k, ok := o.Members["key"]; ok {
		p.Key, err = pattern(k, path+".key", reKey, "signing key")
	} else {
		p.Identity, err = pattern(o.Members["identity"], path+".identity", reID, "identity id")
	}
	return p, err
}

func trust(v canon.Value, path string) (Trust, error) {
	o, err := closed(v, path, []string{"principal", "purposes", "targets"}, nil)
	if err != nil {
		return Trust{}, err
	}
	t := Trust{text: string(canon.Encode(o))}
	if t.Principal, err = principal(o.Members["principal"], path+".principal"); err != nil {
		return Trust{}, err
	}
	if t.Purposes, err = stringSet(o.Members["purposes"], path+".purposes", 3, func(s string) bool { return slices.Contains(purposes, s) }, "unknown purpose"); err != nil {
		return Trust{}, err
	}
	tg, err := closed(o.Members["targets"], path+".targets", nil, []string{"any_content", "contents"})
	if err != nil {
		return Trust{}, err
	}
	if len(tg.Keys) != 1 {
		return Trust{}, fail(path+".targets", "exactly one of any_content or contents")
	}
	if a, ok := tg.Members["any_content"]; ok {
		if b, ok := a.(canon.Bool); !ok || !bool(b) {
			return Trust{}, fail(path+".targets.any_content", "must be true")
		}
		t.AnyContent = true
		return t, nil
	}
	t.Contents, err = stringSet(tg.Members["contents"], path+".targets.contents", MaxEntries, reDigest.MatchString, "not a content digest")
	return t, err
}

// stringSet reads a nonempty array of strings, at most max, each accepted by ok, sorted (UTF-16 order, as the
// note's string sets) with no repeats.
func stringSet(v canon.Value, path string, max int, ok func(string) bool, bad string) ([]string, error) {
	a, isArr := v.(canon.Array)
	if !isArr || len(a) == 0 {
		return nil, fail(path, "not a nonempty array")
	}
	if len(a) > max {
		return nil, fail(path, "%d items (at most %d)", len(a), max)
	}
	var out []string
	for i, e := range a {
		s, isStr := e.(canon.String)
		if !isStr || !ok(string(s)) {
			return nil, fail(fmt.Sprintf("%s[%d]", path, i), "%s", bad)
		}
		if i > 0 && canon.CompareKeys(out[i-1], string(s)) >= 0 {
			return nil, fail(fmt.Sprintf("%s[%d]", path, i), "set is not sorted or repeats an item")
		}
		out = append(out, string(s))
	}
	return out, nil
}

// Configured reports whether a policy is configured.
func (p *Policy) Configured() bool { return p != nil }

// Select returns the selection for (content, role), if the policy has one.
func (p *Policy) Select(content, role string) (Selection, bool) {
	if p == nil {
		return Selection{}, false
	}
	for _, s := range p.Selections {
		if s.Content == content && s.Role == role {
			return s, true
		}
	}
	return Selection{}, false
}

// Diff names every entry one policy has and the other lacks, by its canonical text: the named policy change
// behind two differing answers (P-08). Empty when the digests are equal.
func Diff(a, b *Policy) []string {
	if a.digest() == b.digest() {
		return nil
	}
	out := []string{fmt.Sprintf("policy %s -> %s", a.digest(), b.digest())}
	texts := func(p *Policy) (sel, tr []string) {
		if p == nil {
			return nil, nil
		}
		for _, s := range p.Selections {
			sel = append(sel, s.text)
		}
		for _, t := range p.Trust {
			tr = append(tr, t.text)
		}
		return sel, tr
	}
	as, at := texts(a)
	bs, bt := texts(b)
	for _, d := range []struct {
		what   string
		from   []string
		absent []string
		sign   string
	}{{"selection", as, bs, "-"}, {"selection", bs, as, "+"}, {"trust", at, bt, "-"}, {"trust", bt, at, "+"}} {
		for _, x := range d.from {
			if !slices.Contains(d.absent, x) {
				out = append(out, d.sign+" "+d.what+" "+x)
			}
		}
	}
	return out
}

func (p *Policy) digest() string {
	if p == nil {
		return "(none)"
	}
	return p.Digest
}
