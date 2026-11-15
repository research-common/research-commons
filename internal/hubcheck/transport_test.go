package hubcheck

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/gate"
)

// Transport tests. The hub is a local bare repository (the remote is a path); nothing is dialled.

// withRemote gives h a bare origin holding main, with refs/remotes/origin/HEAD set, and checks out a change branch.
// Send runs git in the caller's environment; the tests point that at no system or global configuration, so a
// developer's own hooks path or URL rewrites do not reach the throwaway remotes.
func withRemote(h *hub) string {
	h.t.Helper()
	h.t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	h.t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	remote := filepath.Join(h.t.TempDir(), "hub.git")
	h.git("init", "-q", "--bare", "-b", "main", remote)
	h.git("remote", "add", "origin", remote)
	h.git("push", "-q", "origin", "main")
	h.git("fetch", "-q", "origin")
	h.git("remote", "set-head", "origin", "main")
	h.branch("change")
	return remote
}

func gitAt(t *testing.T, dir string, args ...string) string {
	t.Helper()
	out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func plan(t *testing.T, h *hub, cfg PushConfig) *PushPlan {
	t.Helper()
	if cfg.Remote == "" {
		cfg.Remote = "origin"
	}
	pl, err := PlanPush(h.dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return pl
}

// TestSendJudgedCommit: TOCTOU. A commit made after the judgement is not sent: Send pushes the judged head, never
// HEAD as it is when the push runs. The remote's branch then holds exactly the judged commit.
func TestSendJudgedCommit(t *testing.T) {
	h := newHub(t, defaultPolicy)
	remote := withRemote(h)
	s := newSigner()
	p, line, _ := s.sign("A", "authored", obj("content", contentOf([]byte("a")), "type", "dataset"))
	h.write(p, line)
	judged := h.commit("judged")
	pl := plan(t, h, PushConfig{Transport: true})
	if pl.Head != judged || pl.Branch != "main" || pl.BranchFrom != "refs/remotes/origin/main" {
		t.Fatalf("plan: head %s branch %q from %q", pl.Head, pl.Branch, pl.BranchFrom)
	}
	// between the judgement and the transport, another commit lands on the branch
	p2, line2, _ := s.sign("A", "authored", obj("content", contentOf([]byte("unjudged")), "type", "dataset"))
	h.write(p2, line2)
	later := h.commit("not judged")
	res, err := pl.Send()
	if err != nil || !res.Transported || res.Pushed != judged || res.Ref != "refs/heads/main" || res.Update != "fast-forward" {
		t.Fatalf("send: %v %+v", err, res)
	}
	if got := gitAt(t, remote, "rev-parse", "refs/heads/main"); got != judged {
		t.Fatalf("the remote holds %s, want the judged %s (HEAD is %s)", got, judged, later)
	}
	if _, err := exec.Command("git", "-C", remote, "cat-file", "-e", later).CombinedOutput(); err == nil {
		t.Fatal("the unjudged commit reached the remote")
	}
	// sent again: up to date, still transported
	if res, _ := pl.Send(); !res.Transported || res.Update != "up to date" {
		t.Fatalf("again: %+v", res)
	}
}

// TestSendNeverForces: the remote branch moved on (another contributor pushed) while this checkout's view is stale.
// The judgement is clean against the stale base, git rejects the non-fast-forward, and the remote keeps the other
// contributor's commit: no force, nothing overwritten.
func TestSendNeverForces(t *testing.T) {
	h := newHub(t, defaultPolicy)
	remote := withRemote(h)
	other := filepath.Join(t.TempDir(), "other")
	gitAt(t, filepath.Dir(other), "clone", "-q", remote, other)
	gitAt(t, other, "-c", "user.name=o", "-c", "user.email=o@example.invalid", "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "theirs")
	gitAt(t, other, "push", "-q", "origin", "HEAD:main")
	theirs := gitAt(t, remote, "rev-parse", "refs/heads/main")
	s := newSigner()
	p, line, _ := s.sign("A", "authored", obj("content", contentOf([]byte("a")), "type", "dataset"))
	h.write(p, line)
	h.commit("mine")
	pl := plan(t, h, PushConfig{Transport: true})
	if pl.Report.Exit() != 0 {
		t.Fatalf("the judgement is not clean:\n%s", pl.Render())
	}
	res, err := pl.Send()
	if err != nil || res.Transported || !strings.Contains(res.Update, "non-fast-forward") && !strings.Contains(res.Update, "fetch first") || res.Git == "" {
		t.Fatalf("send: %v %+v", err, res)
	}
	if got := gitAt(t, remote, "rev-parse", "refs/heads/main"); got != theirs {
		t.Fatalf("the remote's branch moved to %s: their commit %s was overwritten", got, theirs)
	}
}

// TestPushBranch: the branch is --branch, else the base's branch on the pushed remote; a base that is not a branch
// of that remote names no branch: a transport does not start (did-not-start, naming --branch), a dry run is fine.
func TestPushBranch(t *testing.T) {
	h := newHub(t, defaultPolicy)
	withRemote(h)
	h.commit("x")
	base := h.git("rev-parse", "main")
	for _, tc := range []struct {
		cfg         PushConfig
		branch      string
		didNotStart bool
	}{
		{PushConfig{}, "main", false},
		{PushConfig{Base: "origin/main"}, "main", false},
		{PushConfig{Base: "origin/main", Branch: "topic"}, "topic", false},
		{PushConfig{Base: base}, "", false},
		{PushConfig{Base: base, Transport: true}, "", true},
		{PushConfig{Base: "main", Transport: true}, "", true}, // a local branch is not the remote's
		{PushConfig{Base: base, Branch: "topic", Transport: true}, "topic", false},
		{PushConfig{Branch: "a..b", Transport: true}, "", true}, // git's own ref-name check
	} {
		tc.cfg.Remote = "origin"
		pl, err := PlanPush(h.dir, tc.cfg)
		var d *gate.DidNotStart
		if tc.didNotStart {
			if !errors.As(err, &d) || d.Scope != "option --branch" {
				t.Fatalf("%+v: want did-not-start on --branch, got %v", tc.cfg, err)
			}
			continue
		}
		if err != nil || pl.Branch != tc.branch {
			t.Fatalf("%+v: %v branch %q", tc.cfg, err, pl.Branch)
		}
	}
	if _, err := (&PushPlan{}).Send(); !errors.Is(err, ErrNoBranch) {
		t.Fatalf("a plan without a branch: %v", err)
	}
}

func TestBranchName(t *testing.T) {
	for _, ok := range []string{"main", "topic/x", "my-branch_1"} {
		if !BranchName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "HEAD", "-f", "--force", "+main", "refs/heads/main", "a:b", "a b", "a*", "a?", "a[", `a\b`, "a^", "a~1", "a@{0}"} {
		if BranchName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// TestRedact: a credential in a remote URL is never echoed from git's output.
func TestRedact(t *testing.T) {
	in := "fatal: unable to access 'https://user:tok3n@example.invalid/hub.git/': denied; also ssh://git@example.invalid/x"
	out := redact(in)
	if strings.Contains(out, "tok3n") || strings.Contains(out, "user:") || strings.Contains(out, "git@") || !strings.Contains(out, "https://example.invalid/hub.git/") {
		t.Fatalf("%s", out)
	}
	if len(redact(strings.Repeat("x", 5000))) > 2010 {
		t.Fatal("not bounded")
	}
}
