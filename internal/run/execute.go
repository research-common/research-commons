package run

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/research-common/research-commons/internal/refusal"
)

// Attachment is a peer-supplied file staged into the input directory under a name the peer chose. With Tar set,
// Data is a tar archive extracted member by member (§3, archive members).
type Attachment struct {
	Name string
	Data []byte
	Tar  bool
}

// Invocation is one `run`.
type Invocation struct {
	Request
	// Blobs supplies the bytes of the code and of every input, keyed by the reference the spec writes (a digest
	// for a pinned input).
	Blobs       map[string][]byte
	Attachments []Attachment
	// Secrets holds the values of granted names; only names the policy grants this workflow cross (§6).
	Secrets map[string]string
	// HarnessCommit is the commit of the harness that launched the run, when it is a repository.
	HarnessCommit string
	// StagingRoot is where the per-run staging directory is created ("" = the OS temp directory).
	StagingRoot string
	// ReadLimit bounds each output read back (0 = no limit beyond the disk cap).
	ReadLimit int64
}

// OutputBlob is one output read back after the step.
type OutputBlob struct {
	Name, Digest string
	Bytes        []byte
}

// Result is a run that started (or whose pinned environment was not available). A refusal before the step
// starts is returned as an error instead, with no Result and no record (§5.2).
type Result struct {
	// Token is the run result before any comparison with a pin: a stop token (failed, cap, timeout, incomplete
	// output), an environment mismatch when the pinned image is not available, or Unchecked for a step that
	// completed (nothing has been compared yet; see Compare).
	Token   Token
	Record  *Record // nil when the step never started (the pinned image not available here)
	Outputs []OutputBlob
	// Unsafe lists the output names whose read-back the confinement function refused.
	Unsafe  []*PathRefusal
	Explain []string
	// StagingRemoved records that the per-run staging directory is gone (§2.2: staging is removed after any run).
	StagingRemoved bool
}

// Completed reports whether the step ran to its own exit 0 and every declared output was read back.
func (r *Result) Completed() bool { return r.Record != nil && r.Token.Kind == Unchecked }

// Output returns the named output.
func (r *Result) Output(name string) (OutputBlob, bool) {
	for _, o := range r.Outputs {
		if o.Name == name {
			return o, true
		}
	}
	return OutputBlob{}, false
}

// Execute is the one path of `run` (execution note §2–§5): admission and runner checks before staging,
// confined staging with input hashes verified, the step under its caps, confined read-back of the declared
// outputs, and the environment record. It never changes the profile and never falls back (§2.4).
func Execute(ctx context.Context, p *Policy, rn Runner, inv Invocation) (*Result, error) {
	s := inv.Spec
	adm, err := p.Admit(inv.Request)
	if err != nil {
		return nil, err
	}
	scope := "workflow " + s.Digest
	if rn == nil || rn.Profile() != adm.Profile {
		return nil, unavailable(adm.Profile, "no "+adm.Profile+" runner is configured", scope)
	}
	if err := rn.Available(ctx); err != nil {
		return nil, unavailable(adm.Profile, err.Error(), scope)
	}
	// names first: one bad name refuses the whole staging with nothing written (§3)
	names := []string{codeName}
	for _, in := range s.Inputs {
		names = append(names, in.Name)
	}
	for _, a := range inv.Attachments {
		names = append(names, a.Name)
	}
	if err := CheckNames(names, scope); err != nil {
		return nil, err
	}
	for _, in := range s.Inputs {
		if in.Name == codeName {
			return nil, unsafePath(PathMalformed, in.Name, scope+" (the name \"code\" is the workflow's own code)")
		}
	}
	res := &Result{}
	if adm.Profile == Sandbox {
		dg, _, err := rn.Image(ctx, *s.Image)
		switch {
		case errors.Is(err, ErrImageUnavailable):
			// the declared environment is not available in the one that would run: exit 5, not a refusal
			res.Token = Token{Kind: EnvMismatch, Fields: []string{"image_digest"}}
			res.Explain = append(res.Explain, "the pinned image "+s.Image.Reference+"@"+s.Image.Digest+" is not available to this runtime; next step: run where the pinned environment exists")
			res.StagingRemoved = true
			return res, nil
		case err != nil:
			return nil, unavailable(Sandbox, err.Error(), scope)
		case dg != s.Image.Digest:
			return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: ReasonImageDigest,
				Detail: "image digest " + dg + " pulled for " + s.Image.Reference + " is not the pinned " + s.Image.Digest + "; " + scope}
		}
	}

	root, err := os.MkdirTemp(inv.StagingRoot, "rc-run-")
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = os.RemoveAll(root)
		_, statErr := os.Lstat(root)
		res.StagingRemoved = errors.Is(statErr, fs.ErrNotExist)
	}()
	in, out, scratch := filepath.Join(root, "in"), filepath.Join(root, "out"), filepath.Join(root, "scratch")
	for _, d := range []string{in, out, scratch} {
		if err := os.Mkdir(d, 0o755); err != nil {
			return nil, err
		}
	}
	if err := stage(in, s, inv, scope); err != nil {
		return nil, err
	}
	env := map[string]string{}
	for k, v := range s.Env {
		env[k] = v
	}
	for _, g := range adm.Grants {
		if v, ok := inv.Secrets[g]; ok {
			env[g] = v
		}
	}
	o, err := rn.Run(ctx, Job{Spec: s, InDir: in, OutDir: out, Scratch: scratch, Caps: adm.Caps, Network: adm.Network, Env: env})
	if err != nil {
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: "runner failure", Detail: err.Error() + "; " + scope}
	}
	if adm.Profile == Sandbox && o.PeakRSS == nil {
		return nil, ErrSandboxUnmeasured
	}

	rec := &Record{Profile: adm.Profile, ImageReference: o.ImageReference, ImageDigest: o.ImageDigest, Platform: o.Platform,
		HarnessCommit: inv.HarnessCommit, Runtime: o.Runtime, Interpreter: o.Interp, DeclaredDeps: s.Deps,
		Caps: adm.Caps, Declared: adm.Declared, Advisory: adm.Profile == Native, Network: adm.Network,
		Grants: adm.Grants, PeakRSS: o.PeakRSS, WallTimeMs: o.WallTimeMs, StagingCheck: "ok", Boundary: o.Boundary, Cleanup: o.Cleanup}
	if rec.Grants == nil {
		rec.Grants = []string{}
	}
	switch {
	case o.Killed != "":
		res.Token = Token{Kind: FailedCap, Cap: o.Killed}
		if o.Killed == CapWallTime {
			res.Token = Token{Kind: Timeout}
		}
		_, res.Token.Below = adm.Declared[o.Killed]
		rec.ExitStatus = "killed: " + o.Killed
		res.Explain = append(res.Explain, "resources used up to the kill: wall_time_ms "+strconv.FormatInt(o.WallTimeMs, 10)+
			", peak_rss_bytes "+rssString(o.PeakRSS)+", pids_peak "+strconv.FormatInt(o.PidsPeak, 10)+", bytes_written "+strconv.FormatInt(o.Bytes, 10))
		if res.Token.Below {
			res.Explain = append(res.Explain, o.Killed+" in force "+strconv.FormatInt(adm.Caps[o.Killed], 10)+
				" below the declared "+strconv.FormatInt(adm.Declared[o.Killed], 10)+"; next step: run where the declared "+o.Killed+" of "+
				strconv.FormatInt(adm.Declared[o.Killed], 10)+" is available")
		}
		// after a cap trips no output is read back (§2.2)
	case o.ExitCode != 0:
		res.Token = Token{Kind: FailedExit, ExitStatus: o.ExitCode}
		rec.ExitStatus = strconv.Itoa(o.ExitCode)
	default:
		rec.ExitStatus = "0"
		res.Token = Token{Kind: Unchecked}
		for _, d := range s.Outputs {
			b, err := ReadRegular(out, d.File, scope+", output "+strconv.Quote(d.Name), inv.ReadLimit)
			var pr *PathRefusal
			switch {
			case errors.As(err, &pr):
				res.Unsafe = append(res.Unsafe, pr)
				res.Token = Token{Kind: IncompleteOutput}
				res.Explain = append(res.Explain, "output "+strconv.Quote(d.Name)+" refused at read-back: "+pr.Detail)
			case errors.Is(err, fs.ErrNotExist):
				res.Token = Token{Kind: IncompleteOutput}
				res.Explain = append(res.Explain, "declared output "+strconv.Quote(d.Name)+" ("+strconv.Quote(d.File)+") is missing")
			case err != nil:
				res.Token = Token{Kind: IncompleteOutput}
				res.Explain = append(res.Explain, "output "+strconv.Quote(d.Name)+": "+err.Error())
			default:
				res.Outputs = append(res.Outputs, OutputBlob{Name: d.Name, Digest: Digest(b), Bytes: b})
			}
		}
		if res.Token.Kind == IncompleteOutput {
			res.Outputs = nil // nothing is hashed or published from an incomplete run (§3)
		}
	}
	rec.Result = res.Token.String()
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	res.Record = rec
	return res, nil
}

// codeName is the input-directory name the workflow's own code is staged under (§2.1).
const codeName = "code"

func unavailable(profile, why, scope string) *refusal.Refusal {
	reason := ReasonRuntime
	if profile == Native {
		reason = "native runtime unavailable"
	}
	return &refusal.Refusal{Class: refusal.Operational, Reason: reason, Detail: why + "; nothing was spawned; " + scope}
}

func rssString(p *int64) string {
	if p == nil {
		return Unmeasured
	}
	return strconv.FormatInt(*p, 10)
}

// stage writes the code, every input and every attachment into the input directory through the confinement
// function, then re-reads each pinned input and checks its hash before the step starts (§3: inputs are
// read-only and verified after staging).
func stage(in string, s *Spec, inv Invocation, scope string) error {
	code, ok := inv.Blobs[s.Code]
	if !ok {
		return &refusal.Refusal{Class: refusal.Operational, Reason: "blob not held", Detail: "code " + s.Code + "; " + scope}
	}
	if Digest(code) != s.Code {
		return &refusal.Refusal{Class: refusal.Intrinsic, Reason: ReasonImageDigest, Detail: "code bytes do not hash to " + s.Code + "; " + scope}
	}
	if err := WriteNew(in, codeName, scope, code, 0o555); err != nil {
		return stagingErr(err, codeName, scope)
	}
	for _, x := range s.Inputs {
		b, ok := inv.Blobs[x.Ref]
		if !ok {
			return &refusal.Refusal{Class: refusal.Operational, Reason: "blob not held", Detail: "input " + strconv.Quote(x.Name) + " (" + x.Ref + "); " + scope}
		}
		if err := WriteNew(in, x.Name, scope, b, 0o444); err != nil {
			return stagingErr(err, x.Name, scope)
		}
	}
	for _, a := range inv.Attachments {
		var err error
		if a.Tar {
			dir, jerr := Join(in, a.Name, scope)
			if jerr != nil {
				return jerr
			}
			if err = os.MkdirAll(dir, 0o755); err == nil {
				err = ExtractTar(dir, a.Data, scope+", attachment "+strconv.Quote(a.Name))
			}
		} else {
			err = WriteNew(in, a.Name, scope, a.Data, 0o444)
		}
		if err != nil {
			return stagingErr(err, a.Name, scope)
		}
	}
	for _, x := range s.Inputs {
		if !x.Pinned() {
			continue
		}
		b, err := ReadRegular(in, x.Name, scope, 0)
		if err != nil {
			return stagingErr(err, x.Name, scope)
		}
		if Digest(b) != x.Ref {
			return &refusal.Refusal{Class: refusal.Intrinsic, Reason: ReasonImageDigest,
				Detail: "staged input " + strconv.Quote(x.Name) + " does not hash to " + x.Ref + "; " + scope}
		}
	}
	return nil
}

func stagingErr(err error, name, scope string) error {
	var r *refusal.Refusal
	if errors.As(err, &r) {
		return err
	}
	if errors.Is(err, fs.ErrExist) {
		return unsafePath(PathOutside, name, scope+" (the name is staged twice)")
	}
	return err
}

// Rerun is a re-run's comparison with its pin: Execute, then Decide.
func Rerun(ctx context.Context, p *Policy, rn Runner, inv Invocation, pin Pin, cmp Comparator) (*Result, Decision, error) {
	res, err := Execute(ctx, p, rn, inv)
	if err != nil {
		return nil, Decision{}, err
	}
	if res.Record == nil {
		// the pinned environment is not available: nothing ran, nothing to compare
		return res, Decision{Token: res.Token, Explain: slices.Clone(res.Explain)}, nil
	}
	var stopped *Token
	got := ""
	if !res.Completed() {
		t := res.Token
		stopped = &t
	} else {
		name := pin.Output
		if name == "" && len(res.Outputs) == 1 {
			name = res.Outputs[0].Name
		}
		o, ok := res.Output(name)
		if !ok {
			t := Token{Kind: IncompleteOutput}
			stopped = &t
		}
		got = o.Digest
	}
	d := Decide(pin, Fields(res.Record.Object()), stopped, got, cmp, p.AcceptNative)
	d.Explain = append(slices.Clone(res.Explain), d.Explain...)
	res.Record.Result = d.Token.String()
	return res, d, nil
}
