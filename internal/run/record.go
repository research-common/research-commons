package run

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

// The environment record (execution note §4). Every run writes one; it rides unchanged on the `authored` of a
// first derivation, on every `reproduced`, and on the `observed` of an acquisition.
//
// Encoding. The wire note fixes three members of `provenance.environment` (wire §5): `image_digest`,
// `platform`, `harness_commit`. The other fields of the §4 table have no wire name yet; this file writes them
// under their §4 names, flat (`image.reference` as `image_reference`, beside the wire's `image_digest`). A wire
// reader retains them as unknown fields. Until the wire note lists them, nothing a resolver computes may read
// them, so the comparison below (environment_match) is the execution layer's own.

// Profiles.
const (
	Sandbox = "sandbox"
	Native  = "native"
)

// Unmeasured is the value of a field the implementation could not measure (§4: never zero, never the spec's
// number). Allowed for peak_rss_bytes under `native` only.
const Unmeasured = "unmeasured"

var (
	rePlatform = regexp.MustCompile(`^[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?$`)
	reCommit   = regexp.MustCompile(`^([0-9a-f]{40}|[0-9a-f]{64})$`)
)

// Record is one environment record.
type Record struct {
	Profile        string
	ImageReference string // sandbox
	ImageDigest    string // sandbox: the per-platform manifest digest actually run
	Platform       string // <os>/<arch>[/<variant>]
	HarnessCommit  string // "" when the harness is not a repository
	Runtime        string // container runtime name and version (sandbox); interpreter (native)
	Interpreter    string // as reported inside the environment
	DeclaredDeps   canon.Value
	// Caps are the cap values in force; Declared, for a run below the declared profile, the spec's value for
	// each lowered cap. Advisory is true under native (best effort, §2).
	Caps     Resources
	Declared Resources
	Advisory bool
	// Network is nil for `none`, else the granted endpoints. NetworkEnforced, with a granted network, is how it
	// was confined: EnforcedAll (opened as a whole) or EnforcedPerEndpoint (§6).
	Network         []string
	NetworkEnforced string
	// Grants are the names (never values) of policy grants that crossed the boundary (§6).
	Grants []string
	// PeakRSS is nil when unmeasured (native only).
	PeakRSS    *int64
	WallTimeMs int64
	// ExitStatus is the step's exit code as a decimal, or "killed: <cap>"; "" when the step never started.
	ExitStatus   string
	Result       string // the run result token (§5.2)
	StagingCheck string // "ok" or the refusal that stopped the run
	// Boundary names the sandbox boundary ("sandbox: oci, image <digest>"), so C-exec-12's "the run record names
	// the sandbox boundary" is a field (§2.1). Cleanup records the post-kill check (§2.2): the container gone
	// and no process left in its cgroup.
	Boundary string
	Cleanup  string
}

// ErrSandboxUnmeasured is returned for a sandbox record without a measured peak RSS: a conformance failure of
// the sandbox profile, never a record with `unmeasured` (§4, §11 decided 5; C-exec-16).
var ErrSandboxUnmeasured = &refusal.Refusal{Class: refusal.Operational, Reason: "sandbox profile not conformant",
	Detail: "peak_rss_bytes could not be read from the container cgroup; the sandbox profile requires it, so no record is written"}

func badRecord(format string, args ...any) *refusal.Refusal {
	r := refusal.Malformed(format, args...)
	r.Reason = "malformed environment record"
	return r
}

// Validate checks the record against §4: required fields per profile, the standard forms of digest, platform
// and commit, and `unmeasured` peak RSS under native only.
func (r *Record) Validate() error {
	switch r.Profile {
	case Sandbox:
		if r.PeakRSS == nil {
			return ErrSandboxUnmeasured
		}
		if !IsDigest(r.ImageDigest) {
			return badRecord("image_digest %q is not an OCI digest (sandbox requires the digest actually run)", r.ImageDigest)
		}
		if r.ImageReference == "" {
			return badRecord("image_reference is missing (sandbox)")
		}
		if r.Advisory {
			return badRecord("caps are advisory under sandbox: the kernel enforces them (§2.2)")
		}
	case Native:
		if r.ImageDigest != "" && !IsDigest(r.ImageDigest) {
			return badRecord("image_digest %q is not an OCI digest", r.ImageDigest)
		}
		if !r.Advisory {
			return badRecord("caps under native are advisory and the record says so (§2)")
		}
	default:
		return badRecord("profile %q is neither sandbox nor native", r.Profile)
	}
	if !rePlatform.MatchString(r.Platform) {
		return badRecord("platform %q is not <os>/<arch>[/<variant>]", r.Platform)
	}
	if r.HarnessCommit != "" && !reCommit.MatchString(r.HarnessCommit) {
		return badRecord("harness_commit %q is not a full lowercase commit hash", r.HarnessCommit)
	}
	if r.PeakRSS != nil && *r.PeakRSS < 0 {
		return badRecord("peak_rss_bytes is negative")
	}
	for k := range r.Declared {
		if _, ok := r.Caps[k]; !ok {
			return badRecord("caps.declared.%s names a cap not in force", k)
		}
	}
	switch {
	case r.Network == nil && r.NetworkEnforced != "":
		return badRecord("network.enforced %q without a granted network", r.NetworkEnforced)
	case r.Network != nil && r.NetworkEnforced != EnforcedAll && r.NetworkEnforced != EnforcedPerEndpoint:
		return badRecord("network.enforced %q is neither %q nor %q", r.NetworkEnforced, EnforcedAll, EnforcedPerEndpoint)
	}
	if !slices.IsSorted(r.Grants) {
		return badRecord("grants are not sorted")
	}
	return nil
}

// Object encodes the record as the `environment` object (canonical member order is the encoder's).
func (r *Record) Object() *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	set := func(k string, v canon.Value) {
		o.Keys = append(o.Keys, k)
		o.Members[k] = v
	}
	set("profile", canon.String(r.Profile))
	if r.ImageDigest != "" {
		set("image_digest", canon.String(r.ImageDigest))
	}
	if r.ImageReference != "" {
		set("image_reference", canon.String(r.ImageReference))
	}
	set("platform", canon.String(r.Platform))
	if r.HarnessCommit != "" {
		set("harness_commit", canon.String(r.HarnessCommit))
	}
	if r.Runtime != "" {
		set("runtime", canon.String(r.Runtime))
	}
	if r.Interpreter != "" {
		set("interpreter", canon.String(r.Interpreter))
	}
	if r.DeclaredDeps != nil {
		set("declared_deps", r.DeclaredDeps)
	}
	caps := resourcesObject(r.Caps)
	if len(r.Declared) > 0 {
		caps.Keys = append(caps.Keys, "declared")
		caps.Members["declared"] = resourcesObject(r.Declared)
	}
	if r.Advisory {
		caps.Keys = append(caps.Keys, "advisory")
		caps.Members["advisory"] = canon.Bool(true)
	}
	set("caps", caps)
	if r.Network == nil {
		set("network", canon.String("none"))
	} else {
		set("network", &canon.Object{Keys: []string{"enforced", "granted"}, Members: map[string]canon.Value{
			"enforced": canon.String(r.NetworkEnforced), "granted": strings2array(r.Network)}})
	}
	set("grants", strings2array(r.Grants))
	if r.PeakRSS == nil {
		set("peak_rss_bytes", canon.String(Unmeasured))
	} else {
		set("peak_rss_bytes", canon.Int(*r.PeakRSS))
	}
	set("wall_time_ms", canon.Int(r.WallTimeMs))
	if r.ExitStatus != "" {
		if n, err := strconv.Atoi(r.ExitStatus); err == nil {
			set("exit_status", canon.Int(n))
		} else {
			set("exit_status", canon.String(r.ExitStatus))
		}
	}
	set("result", canon.String(r.Result))
	set("staging_check", canon.String(r.StagingCheck))
	if r.Boundary != "" {
		set("boundary", canon.String(r.Boundary))
	}
	if r.Cleanup != "" {
		set("cleanup", canon.String(r.Cleanup))
	}
	slices.SortFunc(o.Keys, canon.CompareKeys)
	return o
}

func resourcesObject(res Resources) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range CapNames {
		if v, ok := res[k]; ok {
			o.Keys = append(o.Keys, k)
			o.Members[k] = canon.Int(v)
		}
	}
	return o
}

func strings2array(s []string) canon.Array {
	a := canon.Array{}
	for _, x := range s {
		a = append(a, canon.String(x))
	}
	return a
}

// NetworkLine is the record's network as displayed (execution §6): `network none`, `network granted (limited to
// the declared endpoints)`, or, for a network opened as a whole, `network granted (not limited to the declared
// endpoints)`.
func (r *Record) NetworkLine() string {
	switch {
	case r.Network == nil:
		return "network none"
	case r.NetworkEnforced == EnforcedPerEndpoint:
		return "network granted (limited to the declared endpoints)"
	}
	return "network granted (not limited to the declared endpoints)"
}

// Fields reads a received environment object as field name → canonical JSON of the value, for comparison by
// name. It reads any object: a pin written before the full record existed (the wire note's three members only)
// compares on the fields it has, and a field it lacks is a difference when environment_match names it.
func Fields(env *canon.Object) map[string]string {
	out := map[string]string{}
	if env == nil {
		return out
	}
	for _, k := range env.Keys {
		out[k] = string(canon.Encode(env.Members[k]))
	}
	return out
}

// DefaultMatch is the environment_match a workflow gets when its `authored` names none (§1 table): image digest
// and platform for `bytes`, nothing for every other mode.
func DefaultMatch(mode string) []string {
	if mode == "bytes" {
		return []string{"image_digest", "platform"}
	}
	return nil
}

// Mismatch is the outcome of comparing a re-run's record with its pin.
type Mismatch struct {
	// Fields are the environment_match fields that differ (or that one side lacks), in match order.
	Fields []string
	// Profile is set when the two records' profiles differ ("profile native ≠ sandbox").
	Profile string
	// ProfileAccepted is true when the reader's policy accepts native records, so a profile difference is
	// named and the comparison proceeds (§2.4).
	ProfileAccepted bool
	// Side lists every field that differs and is not named, shown side by side, never exit 5 (§4).
	Side []string
}

// Mismatched reports whether the comparison is an environment mismatch (exit 5).
func (m Mismatch) Mismatched() bool {
	return len(m.Fields) > 0 || (m.Profile != "" && !m.ProfileAccepted)
}

// Token is the mismatch as a result token.
func (m Mismatch) Token() Token {
	f := slices.Clone(m.Fields)
	if m.Profile != "" && !m.ProfileAccepted {
		f = append([]string{m.Profile}, f...)
	}
	return Token{Kind: EnvMismatch, Fields: f}
}

// Compare compares a re-run's record with the pinned one on the fields match names (§4 "Comparison"). A
// profile difference is always named: a native record re-run under sandbox (or the reverse) exits 5 unless the
// reader's policy accepts native records (§2.4). Fields not named are listed in Side and never cause exit 5.
func Compare(pin, rerun map[string]string, match []string, acceptNative bool) Mismatch {
	var m Mismatch
	for _, f := range match {
		pv, pok := pin[f]
		rv, rok := rerun[f]
		if !pok || !rok || pv != rv {
			m.Fields = append(m.Fields, f)
		}
	}
	pp, rp := unquote(pin["profile"]), unquote(rerun["profile"])
	if pp == "" {
		// a pin with no profile field is read as sandbox when it names an image digest; otherwise unknown
		if _, ok := pin["image_digest"]; ok {
			pp = Sandbox
		}
	}
	if pp != "" && rp != "" && pp != rp && !slices.Contains(match, "profile") {
		m.Profile = fmt.Sprintf("profile %s ≠ %s", pp, rp)
		m.ProfileAccepted = acceptNative
	}
	keys := map[string]bool{}
	for k := range pin {
		keys[k] = true
	}
	for k := range rerun {
		keys[k] = true
	}
	for _, k := range sortedKeys(keys) {
		if slices.Contains(match, k) || k == "profile" || measuredPerRun[k] {
			continue
		}
		if pin[k] != rerun[k] {
			m.Side = append(m.Side, k)
		}
	}
	return m
}

// measuredPerRun are the record fields that describe one run rather than its environment: they differ between
// any two runs and are never listed as an environment difference.
var measuredPerRun = map[string]bool{"peak_rss_bytes": true, "wall_time_ms": true, "exit_status": true,
	"result": true, "staging_check": true, "cleanup": true}

func unquote(s string) string { return strings.Trim(s, `"`) }

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
