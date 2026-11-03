package run

import (
	"context"
	"errors"
	"sync"
)

// Runner is one execution mechanism: the OCI sandbox, the host (native), or a test double. Execute drives it;
// a Runner never decides policy, never stages and never reads outputs back (§3: the host-side joins are the
// caller's, through the one confinement function).
type Runner interface {
	// Profile is the profile this runner implements: Sandbox or Native.
	Profile() string
	// Available reports whether the mechanism can run at all (a reachable container runtime). A non-nil error
	// refuses the run (operational: sandbox runtime unavailable); there is no fallback (§2.4).
	Available(ctx context.Context) error
	// Image resolves a pinned image to the per-platform manifest digest the runtime holds and the platform it
	// runs. ErrImageUnavailable means the image is not available here: an environment mismatch (exit 5,
	// C-exec-13a), not a refusal.
	Image(ctx context.Context, img Image) (digest, platform string, err error)
	// Run runs one staged step under the job's caps and returns what was measured. It must enforce the caps
	// during execution and, on any kill, remove the container and every descendant before returning.
	Run(ctx context.Context, j Job) (Outcome, error)
}

// ErrImageUnavailable is returned by Runner.Image when the pinned image is not available to the runtime.
var ErrImageUnavailable = errors.New("pinned image not available")

// Job is one staged step.
type Job struct {
	Spec *Spec
	// InDir is read-only to the step (inputs and the workflow's code, under their spec names); OutDir is
	// writable; Scratch is a size-capped tmpfs (sandbox) or a fresh directory (native).
	InDir, OutDir, Scratch string
	Caps                   Resources
	Network                []string
	// Env is everything the step sees: the spec's declared env, IN_<name>, OUT_DIR, and granted names with
	// their values (§6). Nothing else from the host crosses.
	Env map[string]string
}

// Outcome is what a runner measured. Every field is measured, never copied from the spec (§4).
type Outcome struct {
	// ExitCode is the step's exit code when it exited; Killed names the cap that stopped it ("memory", "pids",
	// "disk", "wall_time"), "" when it ran to its own exit.
	ExitCode int
	Killed   string
	// PeakRSS is nil when the runner could not read it (allowed under native only).
	PeakRSS                     *int64
	WallTimeMs, PidsPeak, Bytes int64
	ImageReference, ImageDigest string
	Platform, Runtime, Interp   string
	Boundary                    string
	// Cleanup is the post-run check: the container no longer exists and no process remains in its cgroup.
	Cleanup string
	// NetworkEnforced is how a granted network was confined (execution §6): EnforcedPerEndpoint when egress was
	// limited to the spec's declared endpoints, EnforcedAll when the network was opened as a whole. "" when no
	// network was granted; a runner that leaves it "" for a granted network is recorded as EnforcedAll.
	NetworkEnforced string
}

// Network enforcement values of the environment record's `network.enforced` (execution §6).
const (
	EnforcedAll         = "all"
	EnforcedPerEndpoint = "per-endpoint"
)

// Step is an in-process step for the Fake runner: it reads its inputs from in, writes outputs to out, and
// reports the resources it would have used, so the fake can trip caps deterministically.
type Step func(ctx context.Context, in, out string, env map[string]string) (exit int, used Resources)

// Fake is an in-process Runner for tests. It runs Steps keyed by the spec's code digest, enforces caps by
// comparing the step's reported use with the job's caps (a cap is tripped when use exceeds it), and counts
// every Run call (the process audit for tests that require nothing spawned).
type Fake struct {
	Prof     string
	Down     error             // returned by Available
	Images   map[string]string // reference digest → platform the fake holds; absent = unavailable
	Steps    map[string]Step   // code digest → step
	NoRSS    bool              // the fake cannot read peak RSS (C-exec-16)
	Platform string
	mu       sync.Mutex
	Spawned  int
	Jobs     []Job
}

func (f *Fake) Profile() string {
	if f.Prof == "" {
		return Sandbox
	}
	return f.Prof
}

func (f *Fake) Available(context.Context) error { return f.Down }

func (f *Fake) Image(_ context.Context, img Image) (string, string, error) {
	p, ok := f.Images[img.Digest]
	if !ok {
		return "", "", ErrImageUnavailable
	}
	return img.Digest, p, nil
}

func (f *Fake) Run(ctx context.Context, j Job) (Outcome, error) {
	f.mu.Lock()
	f.Spawned++
	f.Jobs = append(f.Jobs, j)
	f.mu.Unlock()
	step, ok := f.Steps[j.Spec.Code]
	if !ok {
		return Outcome{}, errors.New("fake: no step for code " + j.Spec.Code)
	}
	exit, used := step(ctx, j.InDir, j.OutDir, j.Env)
	o := Outcome{ExitCode: exit, WallTimeMs: used[CapWallTime], Runtime: "fake/1", Interp: j.Spec.Interpreter,
		Cleanup: "ok: no container remains; no process in its cgroup"}
	if !f.NoRSS {
		rss := used[CapMemory]
		o.PeakRSS = &rss
	}
	o.PidsPeak, o.Bytes = used[CapPids], used[CapDisk]
	if j.Spec.Image != nil && f.Profile() == Sandbox {
		o.ImageReference, o.ImageDigest = j.Spec.Image.Reference, j.Spec.Image.Digest
		o.Platform = f.Images[j.Spec.Image.Digest]
		o.Boundary = "sandbox: fake, image " + j.Spec.Image.Digest
	} else {
		o.Platform = f.Platform
		if o.Platform == "" {
			o.Platform = "linux/amd64"
		}
	}
	// cap order: the first cap in CapNames order that the step's use exceeds stops it (cpus throttles, never kills)
	for _, c := range CapNames {
		if c == CapCPUs {
			continue
		}
		if lim, ok := j.Caps[c]; ok && used[c] > lim {
			o.Killed = c
			if c == CapWallTime {
				o.WallTimeMs = lim
			}
			break
		}
	}
	return o, nil
}
