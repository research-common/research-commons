package run

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// OCI is the sandbox profile on an OCI container runtime driven through its Docker-compatible CLI (execution
// note §2.1, §2.2). It adds no dependency: it runs the CLI named by Bin.
//
// One run is one container:
//
//   - created from the image by its immutable id, root filesystem read-only, every capability dropped,
//     no-new-privileges, an unprivileged user, an init process that reaps descendants;
//   - network mode `none` unless the job carries a granted network;
//   - three mounts only: the input directory read-only at /in, a size-capped tmpfs at /out (the disk cap), a
//     size-capped scratch tmpfs at /tmp; no host path, socket or device beyond those;
//   - cgroup caps applied at creation: memory (no swap), pids, cpus;
//   - a keepalive process (the image's `sleep`) holds the container's cgroup open while the step runs through
//     `exec`, so peak RSS, the pid peak and the cap events are read from the host's view of the cgroup after
//     the step ends and before the container is removed (§4: measured, not copied).
//
// On the wall-time cap the timer kills the container, not the client, after reading its counters. Outputs are
// copied out as a tar stream and written into the host output directory through the confinement function;
// symlinks the step made are recreated as symlinks (never followed), so the read-back refuses them by name
// (§3). After removal it checks that the container no longer exists, that its cgroup is gone, and that none of
// the PIDs seen in it is alive, and records the check.
//
// Read-back runs the image's `tar` inside the container (a container runtime's copy command cannot read a tmpfs
// mount); the disk cap is classified from the image's `du` of /out: at or within 64 KiB of the cap after a
// failed step, while the step runs (checked every 200 ms; the container is then killed), or when the wall-time
// cap fires, is `failed: operational: disk`.
//
// Limits of this backend (reported, not hidden): the image must provide `sleep` (keepalive), `tar` (read-back) and `du` (disk classification); the image is
// never pulled (a pinned image the runtime does not hold is unavailable: exit 5); a granted network is the
// runtime's default bridge, so the declared endpoint list is recorded but not enforced per endpoint; the disk
// cap is classified from the filesystem's fill level, not from a kernel event; processes the step left running
// are still alive during read-back (they are killed with the container).
type OCI struct {
	// Bin is the CLI ("docker" when empty).
	Bin string
	// CgroupRoot is where the host's cgroup v2 hierarchy is mounted ("/sys/fs/cgroup" when empty).
	CgroupRoot string
	// User is the unprivileged uid:gid the step runs as ("65534:65534" when empty).
	User string
	// ScratchBytes caps the scratch tmpfs (1 MiB when 0).
	ScratchBytes int64
	// Observe, when set, is called with the host PIDs seen in the container's cgroup while the step runs (the
	// test's process audit for C-exec-10 and C-exec-11).
	Observe func(pids []int)
}

func (o *OCI) bin() string {
	if o.Bin == "" {
		return "docker"
	}
	return o.Bin
}

func (o *OCI) cgroot() string {
	if o.CgroupRoot == "" {
		return "/sys/fs/cgroup"
	}
	return o.CgroupRoot
}

func (o *OCI) user() string {
	if o.User == "" {
		return "65534:65534"
	}
	return o.User
}

// outUsage is the bytes in use on the output tmpfs, from the image's `du` (0, false when it cannot tell).
func (o *OCI) outUsage(ctx context.Context, id string) (int64, bool) {
	v, err := o.cli(ctx, "exec", "--user", o.user(), id, "du", "-s", "-k", "/out")
	if err != nil {
		return 0, false
	}
	f := strings.Fields(v)
	if len(f) == 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	return n * 1024, err == nil
}

// Profile implements Runner.
func (o *OCI) Profile() string { return Sandbox }

func (o *OCI) cli(ctx context.Context, args ...string) (string, error) {
	cmd := osexec.CommandContext(ctx, o.bin(), args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")} // the CLI's own config; nothing reaches the step
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%s %s: %w: %s", o.bin(), args[0], err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

// Available implements Runner: the runtime answers and reports cgroup v2 (the profile's measurements need it).
func (o *OCI) Available(ctx context.Context) error {
	v, err := o.cli(ctx, "info", "--format", "{{.CgroupVersion}}")
	if err != nil {
		return err
	}
	if v != "2" {
		return errors.New("the container runtime reports cgroup version " + v + "; the sandbox profile needs cgroup v2 to measure peak RSS")
	}
	return nil
}

// Image implements Runner. The pinned digest must be the image's id or one of its repository digests; the
// image is never pulled.
func (o *OCI) Image(ctx context.Context, img Image) (string, string, error) {
	out, err := o.cli(ctx, "image", "inspect", "--format", "{{.Id}} {{range .RepoDigests}}{{.}} {{end}}|{{.Os}}/{{.Architecture}}{{with index . \"Variant\"}}/{{.}}{{end}}", img.Reference)
	if err != nil {
		return "", "", ErrImageUnavailable
	}
	ids, plat, _ := strings.Cut(out, "|")
	plat = strings.TrimSuffix(plat, "/")
	for _, f := range strings.Fields(ids) {
		if i := strings.LastIndex(f, "@"); i >= 0 {
			f = f[i+1:]
		}
		if f == img.Digest {
			return img.Digest, plat, nil
		}
	}
	first := strings.Fields(ids)
	if len(first) == 0 {
		return "", "", ErrImageUnavailable
	}
	return first[0], plat, nil // a different digest under the reference: Execute refuses (hash mismatch)
}

type cgStats struct {
	peakRSS, pidsPeak int64
	oom, pidsMax      bool
	ok                bool
	pids              []int
}

func (o *OCI) cgroupDir(ctx context.Context, id string) string {
	pid, err := o.cli(ctx, "inspect", "--format", "{{.State.Pid}}", id)
	if err != nil || pid == "0" {
		return ""
	}
	b, err := os.ReadFile("/proc/" + pid + "/cgroup")
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if p, ok := strings.CutPrefix(l, "0::"); ok {
			return filepath.Join(o.cgroot(), p)
		}
	}
	return ""
}

func readStats(dir string) cgStats {
	var s cgStats
	if dir == "" {
		return s
	}
	num := func(f string) (int64, bool) {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return 0, false
		}
		n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		return n, err == nil
	}
	event := func(f, key string) bool {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			return false
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			k, v, _ := strings.Cut(sc.Text(), " ")
			if k == key && v != "0" {
				return true
			}
		}
		return false
	}
	s.peakRSS, s.ok = num("memory.peak")
	s.pidsPeak, _ = num("pids.peak")
	s.oom = event("memory.events", "oom_kill")
	s.pidsMax = event("pids.events", "max")
	if b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs")); err == nil {
		for _, f := range strings.Fields(string(b)) {
			if n, err := strconv.Atoi(f); err == nil {
				s.pids = append(s.pids, n)
			}
		}
	}
	return s
}

// Run implements Runner.
func (o *OCI) Run(ctx context.Context, j Job) (Outcome, error) {
	if j.Spec.Image == nil {
		return Outcome{}, errors.New("no image pinned")
	}
	interp := strings.Fields(j.Spec.Interpreter)
	if len(interp) == 0 {
		return Outcome{}, errors.New("no interpreter")
	}
	user := o.user()
	scratch := o.ScratchBytes
	if scratch == 0 {
		scratch = 1 << 20
	}
	disk := j.Caps[CapDisk]
	if disk == 0 {
		disk = 64 << 20
	}
	// a granted network opens the runtime's default bridge: everything, not only the declared endpoints, and the
	// record says so (network.enforced: all, execution §6)
	network := "none"
	if j.Network != nil {
		network = "bridge"
	}
	args := []string{"run", "-d", "--init", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
		"--user", user, "--network", network, "--ipc", "private", "--log-driver", "none",
		"--mount", "type=bind,src=" + j.InDir + ",dst=/in,readonly",
		"--mount", fmt.Sprintf("type=tmpfs,dst=/out,tmpfs-size=%d,tmpfs-mode=1777", disk),
		"--mount", fmt.Sprintf("type=tmpfs,dst=/tmp,tmpfs-size=%d,tmpfs-mode=1777", scratch),
		"--label", "research-commons.run=1"}
	if m, ok := j.Caps[CapMemory]; ok {
		args = append(args, "--memory", strconv.FormatInt(m, 10), "--memory-swap", strconv.FormatInt(m, 10))
	}
	if p, ok := j.Caps[CapPids]; ok {
		args = append(args, "--pids-limit", strconv.FormatInt(p, 10))
	}
	if c, ok := j.Caps[CapCPUs]; ok {
		args = append(args, "--cpus", strconv.FormatFloat(float64(c)/1000, 'f', 3, 64))
	}
	id0, _, _ := o.Image(ctx, *j.Spec.Image)
	img := j.Spec.Image.Digest
	if id0 == img {
		if out, err := o.cli(ctx, "image", "inspect", "--format", "{{.Id}}", j.Spec.Image.Reference); err == nil {
			img = out // run by the immutable local id the pin resolved to
		}
	}
	args = append(args, img, "sleep", "2147483647")
	id, err := o.cli(ctx, args...)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{ImageReference: j.Spec.Image.Reference, ImageDigest: j.Spec.Image.Digest, Boundary: "sandbox: oci, image " + j.Spec.Image.Digest}
	if j.Network != nil {
		out.NetworkEnforced = EnforcedAll
	}
	_, out.Platform, _ = o.Image(ctx, *j.Spec.Image)
	if v, err := o.cli(ctx, "version", "--format", "{{.Server.Version}}"); err == nil {
		out.Runtime = o.bin() + " " + v
	}
	cg := o.cgroupDir(ctx, id)
	rmctx := context.WithoutCancel(ctx)
	seen := map[int]bool{}
	removed := false
	defer func() {
		if !removed {
			_, _ = o.cli(rmctx, "rm", "-f", id)
		}
	}()

	// the step, through exec, under the wall-time cap; env through a 0600 file, so no value is on a command line
	envf, err := os.CreateTemp("", "rc-env-")
	if err != nil {
		return out, err
	}
	defer os.Remove(envf.Name())
	env := map[string]string{"OUT_DIR": "/out", "HOME": "/tmp"}
	for _, in := range j.Spec.Inputs {
		env["IN_"+in.Name] = "/in/" + in.Name
	}
	for k, v := range j.Env {
		env[k] = v
	}
	for k, v := range env {
		if strings.ContainsAny(k+v, "\n\x00") {
			envf.Close()
			return out, errors.New("environment value contains a newline or NUL")
		}
		fmt.Fprintf(envf, "%s=%s\n", k, v)
	}
	envf.Close()
	wall := j.Caps[CapWallTime]
	if wall == 0 {
		wall = 60_000
	}
	execArgs := []string{"exec", "--user", user, "--env-file", envf.Name(), "--workdir", "/tmp", id, interp[0], "/in/" + codeName}
	cmd := osexec.Command(o.bin(), execArgs...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return out, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(time.Duration(wall) * time.Millisecond)
	defer timer.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	timedOut, diskFull := false, false
	ticks := 0
	var waitErr error
	var st cgStats
wait:
	for {
		select {
		case waitErr = <-done:
			break wait
		case <-tick.C:
			ticks++
			if ticks%10 == 0 {
				// the output filesystem full while the step still runs: the disk cap stops it now, not at the
				// wall-time cap (a step that ignores ENOSPC would otherwise spin until then)
				if used, ok := o.outUsage(rmctx, id); ok && used+64*1024 >= disk {
					diskFull = true
					st = readStats(cg)
					_, _ = o.cli(rmctx, "kill", id)
					waitErr = <-done
					break wait
				}
			}
			s := readStats(cg)
			for _, p := range s.pids {
				seen[p] = true
			}
			if o.Observe != nil && len(s.pids) > 0 {
				o.Observe(s.pids)
			}
		case <-timer.C:
			timedOut = true
			st = readStats(cg) // counters first: the cgroup goes with the container
			if used, ok := o.outUsage(rmctx, id); ok && used+64*1024 >= disk {
				diskFull = true
			}
			_, _ = o.cli(rmctx, "kill", id)
			waitErr = <-done
			break wait
		}
	}
	out.WallTimeMs = time.Since(start).Milliseconds()
	if !timedOut && !diskFull {
		st = readStats(cg)
	}
	for _, p := range st.pids {
		seen[p] = true
	}
	if st.ok {
		v := st.peakRSS
		out.PeakRSS = &v
	}
	out.PidsPeak = st.pidsPeak
	var ee *osexec.ExitError
	switch {
	case waitErr == nil:
	case errors.As(waitErr, &ee):
		out.ExitCode = ee.ExitCode()
	default:
		return out, waitErr
	}

	// outputs: copied out of /out as a tar stream, before removal, only if no cap tripped
	switch {
	case st.oom:
		out.Killed = CapMemory
	case st.pidsMax:
		out.Killed = CapPids
	case diskFull:
		// the output filesystem filled while the step ran: writes failed inside the container and the container
		// was killed for it
		out.Killed = CapDisk
	case timedOut:
		out.Killed = CapWallTime
		out.WallTimeMs = wall
	}
	if out.Killed == "" {
		n, err := o.copyOut(rmctx, id, j.OutDir)
		out.Bytes = n
		if err != nil {
			return out, err
		}
		if used, ok := o.outUsage(rmctx, id); out.ExitCode != 0 && ok && used+64*1024 >= disk {
			out.Killed = CapDisk
			out.Bytes = used
		}
	}

	// removal and the cleanup check
	_, rmErr := o.cli(rmctx, "rm", "-f", id)
	removed = rmErr == nil
	var faults []string
	if _, err := o.cli(rmctx, "inspect", "--format", "{{.Id}}", id); err == nil {
		faults = append(faults, "container still exists")
	}
	if cg != "" {
		if _, err := os.Stat(cg); err == nil {
			faults = append(faults, "cgroup still exists")
		}
	}
	for p := range seen {
		if alive(p) {
			faults = append(faults, "pid "+strconv.Itoa(p)+" alive")
		}
	}
	if len(faults) == 0 {
		out.Cleanup = fmt.Sprintf("ok: container removed; cgroup gone; none of %d pids seen in it alive", len(seen))
	} else {
		out.Cleanup = "FAILED: " + strings.Join(faults, "; ")
		return out, errors.New("cleanup check failed: " + out.Cleanup)
	}
	if v, err := o.cli(rmctx, "version", "--format", "{{.Server.Os}}"); err == nil && out.Platform == "" {
		out.Platform = v
	}
	return out, nil
}

func alive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// copyOut copies /out from the container and writes its regular files into dir through the confinement
// function. A symlink the step made is recreated as a symlink (its target never read or followed) and any other
// non-regular member as a fifo, so the read-back of a declared output refuses it by name (§3). Returns the bytes
// of regular files copied.
func (o *OCI) copyOut(ctx context.Context, id, dir string) (int64, error) {
	// `cp` cannot read a tmpfs mount, so the stream comes from the image's own tar, run as the step's user
	// inside the container; the host parses it and places every member through the confinement function
	cmd := osexec.CommandContext(ctx, o.bin(), "exec", "--user", o.user(), id, "tar", "-C", "/out", "-cf", "-", ".")
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME")}
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	defer cmd.Wait()
	tr := tar.NewReader(pipe)
	var n int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return n, err
		}
		name := strings.TrimPrefix(strings.TrimPrefix(h.Name, "./"), "/")
		if name == "" || name == "." {
			continue
		}
		name = strings.TrimSuffix(name, "/")
		p, err := Join(dir, name, "output copy")
		if err != nil {
			continue // a name that cannot be placed inside the output directory is never written
		}
		switch h.Typeflag {
		case tar.TypeDir:
			_ = os.MkdirAll(p, 0o755)
		case tar.TypeReg:
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
			if err != nil {
				continue
			}
			c, _ := io.Copy(f, tr)
			n += c
			f.Close()
		case tar.TypeSymlink:
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = os.Symlink(h.Linkname, p)
		default:
			_ = os.MkdirAll(filepath.Dir(p), 0o755)
			_ = syscall.Mkfifo(p, 0o644)
		}
	}
	return n, nil
}
