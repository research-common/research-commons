package gate

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// Limit names this tool documents (storage note §8: every limit has a name and a value, read from the reader's
// policy and printed with a refusal). A hub policy may set only these names.
const (
	// LimitBlobBytes bounds one blob's size in a package.
	LimitBlobBytes = "blob_bytes"
	// LimitStatementBytes bounds one statement file's size. It can only lower the format's own bound: a line
	// longer than wire.MaxLine is refused by wire.ReadStored whatever this is.
	LimitStatementBytes = "statement_bytes"
)

// DefaultLimits are the tool's defaults, printed by `status --limits`. Project-wide size policy is open; these
// are this implementation's documented values, not the format's.
var DefaultLimits = map[string]int64{
	LimitBlobBytes:      1 << 30,
	LimitStatementBytes: wire.MaxLine,
}

// IntendedForMode is what a receiver does with its own re-application of a statement's intended_for.
type IntendedForMode int

const (
	// ShowIntendedFor labels the statement with the named and current editions' outcomes side by side (a hub
	// gate, H-36; C-core-98). A failing rule does not refuse: the field confers nothing either way (I7).
	ShowIntendedFor IntendedForMode = iota
	// RefuseOnFail refuses, under reader policy, a statement whose named or current edition's rules fail. This
	// is the publisher's own policy at the pre-pin check (claims-model note §8).
	RefuseOnFail
)

// StatementHook is a reader-policy check on one placed statement. A refusal it returns must be class
// reader policy. With Label true, the hook's refusal is shown as a label and the statement admitted
// ("admitted and labelled, per the reader's policy", C-core-111).
type StatementHook interface {
	CheckStatement(st *wire.Statement) *refusal.Refusal
	Label() bool
}

// KeyFloor is the minimal trust floor: a set of keys whose statements this reader does not admit (or labels).
// It names keys, never identities: an identity-aware floor waits for the reader-policy track.
type KeyFloor struct {
	Excluded  map[string]bool
	LabelOnly bool
}

func (f KeyFloor) Label() bool { return f.LabelOnly }

func (f KeyFloor) CheckStatement(st *wire.Statement) *refusal.Refusal {
	if !f.Excluded[st.Signer] {
		return nil
	}
	return &refusal.Refusal{Class: refusal.Policy, Reason: TrustFloor,
		Detail: "signer " + st.Signer + " is excluded by this reader's trust floor; scope that key's objects"}
}

// Policy is the receiver's admission policy: everything a gate applies beyond the format's own validity.
type Policy struct {
	// Name says whose policy this is and where it came from ("hub-policy.json at <rev>", "reader policy").
	Name string
	// Digest is "sha256:<hex>" of the policy file's bytes, or of the canonical defaults when there is no file.
	Digest string

	ExternalOnly bool
	// NotServed maps a blob digest to the maintainers' reason (possibly "").
	NotServed map[string]string
	// Limits is every documented limit with its effective value.
	Limits map[string]int64
	// Freeze is the series freeze policy (C-core-104); nil means none.
	Freeze resolve.FreezePolicy
	// SourceProfiles are the source profile digests the policy pins (`series.source_profiles`, claims-model note
	// §5.3.1a), in file order. The policy names them; whoever applies the policy loads the blobs from what it held
	// where it read the policy (a hub: the base revision) and refuses to start when one is not held there.
	SourceProfiles []string
	// RefuseIncomplete refuses a resource edition whose completeness claim this receiver's own check finds
	// failed (`selection.refuse_incomplete`); a claim it cannot check is could not check. False means off.
	RefuseIncomplete bool
	// IntendedFor is what the receiver does with intended_for.
	IntendedFor IntendedForMode
	// Hooks are further reader-policy checks (a trust floor).
	Hooks []StatementHook
	// ControlPlane lists the non-data paths this receiver reviews instead of refusing outright (a hub's own
	// files: exact paths, or prefixes ending in "/"): for a hub, HubControlPlane merged with the policy
	// file's `control_plane` member. A local reader has none: every non-data path of an incoming tree is
	// outside the surface.
	ControlPlane []string
	// Resolver carries the receiver's resolver configuration (rule dialects, content reader, segment re-check)
	// used to re-apply edition rules and series boundaries.
	Resolver []resolve.Option
}

// DefaultPolicy is the tool's default reader policy: no hub rules, the default limits, no control plane.
func DefaultPolicy() *Policy {
	p := &Policy{Name: "defaults", NotServed: map[string]string{}, Limits: map[string]int64{}}
	for k, v := range DefaultLimits {
		p.Limits[k] = v
	}
	p.Digest = digest(canon.Encode(policyObject(p)))
	return p
}

// HubControlPlane is the control plane of a hub repository (hub template contract §2.2): the paths the
// template ships. A hub policy's `control_plane` member adds the paths its maintainers add; it never removes
// one of these.
var HubControlPlane = []string{"hub-policy.json", "rc-store", "README.md", "LICENSE", "CONTRIBUTING.md", "docs/", ".github/", ".gitignore", ".gitattributes"}

// MaxSourceProfiles bounds the entries of a hub policy's `series.source_profiles` member.
const MaxSourceProfiles = 64

// MaxControlPlane bounds the entries of a hub policy's `control_plane` member.
const MaxControlPlane = 256

// sourceProfiles reads `series.source_profiles`: at most MaxSourceProfiles objects, each exactly {digest}, the
// digest in content-digest form, no repeats. The reason names the entry.
func sourceProfiles(v canon.Value) ([]string, string) {
	arr, ok := v.(canon.Array)
	if !ok {
		return nil, "series.source_profiles is not an array"
	}
	if len(arr) > MaxSourceProfiles {
		return nil, fmt.Sprintf("series.source_profiles has %d entries, more than %d", len(arr), MaxSourceProfiles)
	}
	var out []string
	for i, e := range arr {
		eo, ok := e.(*canon.Object)
		if !ok {
			return nil, fmt.Sprintf("series.source_profiles[%d] is not an object", i)
		}
		var d string
		for _, k := range eo.Keys {
			s, ok := eo.Members[k].(canon.String)
			switch {
			case k != "digest":
				return nil, fmt.Sprintf("series.source_profiles[%d] carries undefined field %q", i, inert(k))
			case !ok || !reDigest.MatchString(string(s)):
				return nil, fmt.Sprintf("series.source_profiles[%d].digest is not a sha256:<64 hex> digest", i)
			}
			d = string(s)
		}
		if d == "" {
			return nil, fmt.Sprintf("series.source_profiles[%d] has no digest", i)
		}
		if slices.Contains(out, d) {
			return nil, fmt.Sprintf("series.source_profiles[%d] %s repeats an entry", i, d)
		}
		out = append(out, d)
	}
	return out, ""
}

// LoadSourceProfiles loads the source profiles a policy pins. get returns a blob's bytes as held where the policy
// was read (nil when not held there); each must hash to its digest and parse as a profile. The response layouts a
// profile cites in its documents are read through the same get (resolve.SourceProfile.AttachLayouts); a cited
// layout that is not held or not valid leaves that profile's layout reads unchecked and stops nothing. Any failure stops
// before anything is evaluated (*DidNotStart, naming the entry): a pin the receiver cannot honour is never
// skipped. No digests, no profiles (nil). scope names the policy file, at names where it was read.
func LoadSourceProfiles(digests []string, get func(d string) ([]byte, error), scope, at string) (*resolve.ProfileRules, error) {
	if len(digests) == 0 {
		return nil, nil
	}
	var ps []*resolve.SourceProfile
	for i, d := range digests {
		bad := func(why string) error {
			return &DidNotStart{Title: "hub policy file unusable", Detail: fmt.Sprintf("series.source_profiles[%d] %s %s", i, d, why), Scope: scope,
				Next: "hold the profile blob where the policy is read (for a hub: merge it through its own reviewed change first), then pin it; or fix the policy file through its own review"}
		}
		b, err := get(d)
		switch {
		case err != nil:
			return nil, bad("is not readable at " + at + ": " + err.Error())
		case b == nil:
			return nil, bad("is not held at " + at)
		case digest(b) != d:
			return nil, bad("is held corrupt at " + at + " (its bytes hash elsewhere)")
		}
		p, err := resolve.ParseSourceProfile(b)
		if err != nil {
			return nil, bad("is not a " + resolve.SourceProfileTag + " profile: " + err.Error())
		}
		// the response layouts the profile cites in its documents, read where the profile was read (a change cannot
		// bring the layout that judges it); a layout that cannot be used reads unchecked, it does not stop the read
		p.AttachLayouts(func(d string) ([]byte, error) {
			b, err := get(d)
			var r *refusal.Refusal
			switch {
			case errors.As(err, &r) && r.Reason == store.CorruptBlob, err == nil && b != nil && digest(b) != d:
				// a held copy that hashes elsewhere is named, not skipped: the profile's layout cannot be read
				return nil, resolve.ErrHeldCorrupt
			case err != nil || b == nil:
				return nil, err
			}
			return b, nil
		})
		ps = append(ps, p)
	}
	pr := resolve.NewProfileRules(ps...)
	return &pr, nil
}

// controlPlaneEntry names why s cannot be a `control_plane` entry, or "". An entry is a relative path (an
// exact file) or a prefix ending in "/" (a directory and everything under it), with the same path rules the
// gate applies to package paths, and it may not name or cover the data surface (`blobs/`, `statements/`) or
// the layout marker: data never becomes control (I9).
func controlPlaneEntry(s string) string {
	switch {
	case s == "":
		return "is empty"
	case strings.HasPrefix(s, "/"):
		return "is an absolute path"
	case strings.ContainsRune(s, '\\'):
		return "contains a backslash"
	case strings.ContainsRune(s, 0):
		return "contains NUL"
	}
	for _, seg := range strings.Split(strings.TrimSuffix(s, "/"), "/") {
		switch seg {
		case "..":
			return "has a `..` segment"
		case ".", "":
			return "has an empty or `.` segment"
		}
	}
	top := strings.SplitN(s, "/", 2)[0]
	switch {
	case top == "blobs" || top == "statements":
		return "names or covers the data surface (" + top + "/)"
	case s == "rc-store" || top == "rc-store":
		return "names the layout marker rc-store"
	}
	return ""
}

func (p *Policy) isControlPlane(path string) bool {
	for _, c := range p.ControlPlane {
		if path == c || (strings.HasSuffix(c, "/") && strings.HasPrefix(path, c)) {
			return true
		}
	}
	return false
}

// DidNotStart is an error for an invocation or configuration the gate cannot act on (claims-model note §13,
// exit 2): nothing was evaluated and nothing committed. It carries the problem-details members.
type DidNotStart struct {
	Title, Detail string
	// Scope is what could not be used ("policy file hub-policy.json at <rev>").
	Scope string
	Next  string
}

func (e *DidNotStart) Error() string {
	s := "did not start: " + e.Title
	if e.Detail != "" {
		s += " (" + e.Detail + ")"
	}
	return s
}

// Class is the problem-details class of a did-not-start error: the reader's own configuration.
func (e *DidNotStart) Class() refusal.Class { return refusal.Policy }

// Committed is always false: exit 2 never accompanies partial results.
func (e *DidNotStart) Committed() bool { return false }

// HubPolicyTag is the format tag of the hub policy file.
const HubPolicyTag = "rc-hub-policy/1"

var reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var reLimitName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// ParseHubPolicy reads a hub policy file (`rc-hub-policy/1`) strictly: canon's parser (duplicate keys and
// non-integers refused), every field typed, no field the format does not define, limit names only from the
// documented list. data == nil means the file is absent: every default. Any problem is *DidNotStart. source
// names where the bytes came from (a revision), for the policy name and the error scope.
func ParseHubPolicy(data []byte, source string) (*Policy, error) {
	p := DefaultPolicy()
	p.ControlPlane = slices.Clone(HubControlPlane)
	if data == nil {
		p.Name = "hub-policy.json absent at " + source + ": defaults"
		return p, nil
	}
	p.Name = "hub-policy.json at " + source
	p.Digest = digest(data)
	fail := func(f string, a ...any) error {
		return &DidNotStart{Title: "hub policy file unusable", Detail: fmt.Sprintf(f, a...),
			Scope: "policy file hub-policy.json at " + source, Next: "fix hub-policy.json through the repository's own review"}
	}
	v, err := canon.Parse(data)
	if err != nil {
		return nil, fail("%v", err)
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return nil, fail("top level is not an object")
	}
	tag, ok := o.Get("policy")
	if !ok {
		return nil, fail("missing required field \"policy\"")
	}
	if s, ok := tag.(canon.String); !ok || string(s) != HubPolicyTag {
		return nil, fail("policy is not %q", HubPolicyTag)
	}
	for _, k := range o.Keys {
		val := o.Members[k]
		switch k {
		case "policy":
		case "blobs":
			s, ok := val.(canon.String)
			if !ok || (s != "stored" && s != "external-only") {
				return nil, fail("blobs is neither \"stored\" nor \"external-only\"")
			}
			p.ExternalOnly = s == "external-only"
		case "limits":
			lo, ok := val.(*canon.Object)
			if !ok {
				return nil, fail("limits is not an object")
			}
			for _, name := range lo.Keys {
				if !reLimitName.MatchString(name) {
					return nil, fail("limit name %q", name)
				}
				if _, known := DefaultLimits[name]; !known {
					return nil, fail("limit %q is not a limit this tool documents (%s)", name, strings.Join(limitNames(), ", "))
				}
				n, ok := lo.Members[name].(canon.Int)
				if !ok || n < 0 {
					return nil, fail("limit %q is not a non-negative integer", name)
				}
				p.Limits[name] = int64(n)
			}
		case "not_served":
			arr, ok := val.(canon.Array)
			if !ok {
				return nil, fail("not_served is not an array")
			}
			seen := map[string]bool{}
			for i, e := range arr {
				eo, ok := e.(*canon.Object)
				if !ok {
					return nil, fail("not_served[%d] is not an object", i)
				}
				enc := string(canon.Encode(eo))
				if seen[enc] {
					return nil, fail("not_served[%d] repeats an entry", i)
				}
				seen[enc] = true
				var d, reason string
				for _, ek := range eo.Keys {
					s, ok := eo.Members[ek].(canon.String)
					switch {
					case ek == "digest" && ok && reDigest.MatchString(string(s)):
						d = string(s)
					case ek == "reason" && ok:
						reason = string(s)
					case ek == "digest" || ek == "reason":
						return nil, fail("not_served[%d].%s has the wrong type or shape", i, ek)
					default:
						return nil, fail("not_served[%d] carries undefined field %q", i, ek)
					}
				}
				if d == "" {
					return nil, fail("not_served[%d] has no digest", i)
				}
				p.NotServed[d] = reason
			}
		case "control_plane":
			arr, ok := val.(canon.Array)
			if !ok {
				return nil, fail("control_plane is not an array")
			}
			if len(arr) > MaxControlPlane {
				return nil, fail("control_plane has %d entries, more than %d", len(arr), MaxControlPlane)
			}
			seen := map[string]bool{}
			for i, e := range arr {
				es, ok := e.(canon.String)
				if !ok {
					return nil, fail("control_plane[%d] is not a string", i)
				}
				entry := string(es)
				if why := controlPlaneEntry(entry); why != "" {
					return nil, fail("control_plane[%d] %q %s", i, inert(entry), why)
				}
				if seen[entry] {
					return nil, fail("control_plane[%d] %q repeats an entry", i, inert(entry))
				}
				seen[entry] = true
				if !slices.Contains(p.ControlPlane, entry) {
					p.ControlPlane = append(p.ControlPlane, entry)
				}
			}
		case "series":
			so, ok := val.(*canon.Object)
			if !ok {
				return nil, fail("series is not an object")
			}
			for _, sk := range so.Keys {
				switch sk {
				case "refuse_premature_freeze":
					b, ok := so.Members[sk].(canon.Bool)
					if !ok {
						return nil, fail("series.refuse_premature_freeze is not a boolean")
					}
					if b {
						p.Freeze = resolve.RequireDeclaredNotAfterComputed{}
					}
				case "source_profiles":
					ds, err := sourceProfiles(so.Members[sk])
					if err != "" {
						return nil, fail("%s", err)
					}
					p.SourceProfiles = ds
				default:
					return nil, fail("series carries undefined field %q", sk)
				}
			}
		case "selection":
			so, ok := val.(*canon.Object)
			if !ok {
				return nil, fail("selection is not an object")
			}
			for _, sk := range so.Keys {
				if sk != "refuse_incomplete" {
					return nil, fail("selection carries undefined field %q", sk)
				}
				b, ok := so.Members[sk].(canon.Bool)
				if !ok {
					return nil, fail("selection.refuse_incomplete is not a boolean")
				}
				p.RefuseIncomplete = bool(b)
			}
		default:
			return nil, fail("undefined field %q", k)
		}
	}
	return p, nil
}

func limitNames() []string {
	var ns []string
	for k := range DefaultLimits {
		ns = append(ns, k)
	}
	slices.Sort(ns)
	return ns
}

// policyObject is the canonical form of a policy's file-expressible fields, for the digest of the defaults.
func policyObject(p *Policy) *canon.Object {
	lim := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range limitNames() {
		lim.Keys = append(lim.Keys, k)
		lim.Members[k] = canon.Int(p.Limits[k])
	}
	blobs := "stored"
	if p.ExternalOnly {
		blobs = "external-only"
	}
	return &canon.Object{Keys: []string{"blobs", "limits", "policy"}, Members: map[string]canon.Value{
		"blobs": canon.String(blobs), "limits": lim, "policy": canon.String(HubPolicyTag)}}
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
