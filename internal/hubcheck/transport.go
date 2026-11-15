package hubcheck

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// The transport of `push` (storage note §4.5: a hub kept in a version-control repository receives a package as the
// change between a base revision and the change's head). It is one `git push` of the judged commit to one branch:
//
//   - The judged commit, never HEAD: the refspec is <judged sha>:refs/heads/<branch>, so a commit made after the
//     judgement is not sent.
//   - Never forced: no --force, no leading +, no --mirror, no deletion; a remote branch that moved on is a
//     rejection, and the rejection is the answer.
//   - In the user's own git environment: their credential helpers, configuration and hooks. The repository is
//     theirs, git never clones hooks, and pushing applies no filter, so the objects sent are the objects stored,
//     which are the bytes the hardened reader judged (it ignores replacement refs for the same reason).
//   - Nothing but the one ref: no tags follow, no submodule is pushed.
//
// Send is the only function in this package that writes anywhere or reaches a remote, and it runs only when its
// caller asks for it after a clean judgement.

// SendResult is what one transport did.
type SendResult struct {
	// Transported: the remote's branch now holds the judged commit (updated, created or already there).
	Transported bool
	// Pushed is the commit sent (the judged head); Ref the remote ref (refs/heads/<branch>).
	Pushed, Ref string
	// Update is git's account of the ref: "new branch", "fast-forward", "up to date", or for a rejection git's
	// reason ("rejected (non-fast-forward)", "remote rejected (…)").
	Update string
	// Git is git's own report, with credentials in URLs redacted; set on a rejection or a failure.
	Git string
}

// ErrNoBranch is returned by Send when the plan names no branch (a dry-run plan).
var ErrNoBranch = errors.New("the plan names no branch to push to")

// Send pushes the plan's judged head to refs/heads/<Branch> of the plan's remote. A rejection or any git failure is
// a SendResult with Transported false (never an error): the caller reports it. The error is reserved for a plan
// that cannot be sent at all.
func (pl *PushPlan) Send() (*SendResult, error) {
	if pl.Branch == "" || !BranchName(pl.Branch) {
		return nil, ErrNoBranch
	}
	ref := "refs/heads/" + pl.Branch
	res := &SendResult{Pushed: pl.Head, Ref: ref}
	cmd := exec.Command("git", "-C", pl.Root, "push", "--porcelain", "--no-follow-tags", "--recurse-submodules=no",
		"--end-of-options", pl.Remote, pl.Head+":"+ref)
	// the user's environment, minus anything that would point git at another repository than the checkout judged
	env := []string{}
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); k == "GIT_DIR" || k == "GIT_WORK_TREE" || k == "GIT_INDEX_FILE" ||
			k == "GIT_OBJECT_DIRECTORY" || k == "GIT_ALTERNATE_OBJECT_DIRECTORIES" || k == "GIT_NAMESPACE" {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = env
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	runErr := cmd.Run()
	flag, summary := porcelainRef(out.String(), ref)
	res.Update = summary
	switch {
	case runErr == nil && (flag == " " || flag == "*" || flag == "="):
		res.Transported = true
	default:
		res.Git = redact(strings.TrimSpace(errb.String() + "\n" + out.String()))
		if res.Update == "" {
			res.Update = "failed"
		}
	}
	return res, nil
}

// porcelainRef finds the line for ref in `git push --porcelain` output ("<flag>\t<from>:<to>\t<summary> (<reason>)")
// and returns its flag and a readable summary.
func porcelainRef(out, ref string) (string, string) {
	for _, line := range strings.Split(out, "\n") {
		f := strings.SplitN(line, "\t", 3)
		if len(f) != 3 || len(f[0]) != 1 || !strings.HasSuffix(f[1], ":"+ref) {
			continue
		}
		s := strings.TrimSpace(f[2])
		switch f[0] {
		case "*":
			return f[0], "new branch"
		case " ":
			return f[0], "fast-forward"
		case "=":
			return f[0], "up to date"
		}
		// "[rejected] (non-fast-forward)" → "rejected (non-fast-forward)"
		if strings.HasPrefix(s, "[") {
			s = strings.Replace(s[1:], "]", "", 1)
		}
		return f[0], s
	}
	return "", ""
}

var userinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]*@`)

// redact removes the user-info part of every URL in git's output (https://user:token@host → https://host), so a
// credential embedded in a remote URL is never echoed, and bounds the text.
func redact(s string) string {
	s = userinfo.ReplaceAllString(s, "$1")
	if len(s) > 2000 {
		s = s[:2000] + " …"
	}
	return s
}
