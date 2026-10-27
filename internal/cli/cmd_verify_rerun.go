package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
)

// verify --rerun (claims-model note §13; execution note §2, §4, §5.2). The reader re-runs a derivation only
// when it asks to (--rerun) and only under its own execution policy (--exec-policy <file>). This package
// executes nothing: it selects the pin from the statements held, reads the policy file, and hands both to the
// Rerunner the binary wires in (Env.Rerun). Without a policy, or in a build without a Rerunner, nothing runs
// and the re-run is `unchecked` (exit 3), never a pass.

// ExecPolicyFormat tags the execution policy file. The format is this tool's own and PROVISIONAL: the
// execution note specifies what the policy decides (§2, §2.3, §2.4, §6), not a file encoding.
const ExecPolicyFormat = "rc-exec-policy/0"

// ExecPolicy is the reader's execution policy as read from its file. Native runs and secret grants are not
// expressible yet: the file has no place for secret values, and the native profile is not wired here.
type ExecPolicy struct {
	ExecSigners, ExecWorkflows []string
	Network, Images            []string
	Ceiling                    map[string]int64
}

// RerunRequest is one re-run: the workflow spec and its author's declarations, the pin, and the store's blobs.
type RerunRequest struct {
	Policy *ExecPolicy
	// Spec is the workflow spec blob; Signer the key whose authored statement declares the workflow.
	Spec   []byte
	Signer string
	// Mode, Comparator and Match are the workflow's declarations (from its authored statement, never the spec).
	Mode, Comparator string
	Match            []string
	// PinEnv is the pinned environment record (provenance.environment), nil when none was recorded.
	PinEnv *canon.Object
	// Output names the pinned output ("" = the spec's only output); Digest is the pinned blob.
	Output, Digest string
	// Blob reads a blob the store holds (re-hashed by the execution layer when staged).
	Blob func(digest string) ([]byte, bool)
}

// RerunResult is the re-run's token. Refused is set (and Token empty) when the run was refused before staging:
// it never started, no record was written (execution note §5.2).
type RerunResult struct {
	// Token is the closed-vocabulary word (match, diverged, timeout, …); Detail the full token as the execution
	// layer prints it ("failed: exit 2", "environment mismatch: platform"); Exit its verify exit.
	Token, Detail string
	Exit          int
	Explain       []string
	Refused       string
}

// Rerunner runs a re-run. The binary supplies one; tests supply fakes.
type Rerunner interface {
	Rerun(ctx context.Context, q RerunRequest) (RerunResult, error)
}

var rerunFlags = []Flag{
	{Name: "rerun", Help: "re-run the blob's derivation under --exec-policy and compare it with the pin (a blob only); never the default"},
	{Name: "exec-policy", Value: "file", Help: "the reader's execution policy file (format " + ExecPolicyFormat + ", provisional); only applies alongside --rerun"},
}

// prepareRerun checks the re-run options before any work: --exec-policy only with --rerun, --rerun only for a
// blob, and the policy file strict-parsed (an unreadable or malformed policy exits 2, like the hub policy).
func prepareRerun(c *Ctx) *Problem {
	_, rerun := c.Flag("rerun")
	path, hasPol := c.Flag("exec-policy")
	if hasPol && !rerun {
		return usage("malformed-argument", "--exec-policy only applies alongside --rerun",
			"verify is statement-only without --rerun and reads no execution policy; nothing was done", "option --exec-policy",
			"add --rerun, or drop --exec-policy", "")
	}
	if !rerun {
		return nil
	}
	if !isDigest(c.Args["digest|id"]) {
		return usage("malformed-argument", "--rerun applies to a blob", "a statement id names no derivation to re-run; nothing was done",
			"argument digest|id", "give the blob's digest", c.Args["digest|id"])
	}
	if !hasPol {
		return nil
	}
	pol, prob := readExecPolicy(path)
	if prob != nil {
		return prob
	}
	c.Prep = pol
	return nil
}

func readExecPolicy(path string) (*ExecPolicy, *Problem) {
	bad := func(detail string) *Problem {
		return usage("malformed-exec-policy", "the execution policy file cannot be used", detail+"; nothing ran", "execution policy file",
			"fix the file (format "+ExecPolicyFormat+": exec_signers, exec_workflows, network, images, ceiling)", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, bad("it cannot be read")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	f.Close()
	if err != nil || len(b) > 1<<20 {
		return nil, bad("it cannot be read or is over 1 MiB")
	}
	v, err := canon.Parse(bytes.TrimRight(b, "\n"))
	o, ok := v.(*canon.Object)
	if err != nil || !ok {
		return nil, bad("it is not a strict JSON object")
	}
	if o.Members["format"] != canon.String(ExecPolicyFormat) {
		return nil, bad("its format member is not " + ExecPolicyFormat)
	}
	p := &ExecPolicy{Ceiling: map[string]int64{}}
	strs := func(k string, check func(string) bool) ([]string, bool) {
		x, present := o.Members[k]
		if !present {
			return nil, true
		}
		a, ok := x.(canon.Array)
		if !ok {
			return nil, false
		}
		var out []string
		for _, e := range a {
			s, ok := e.(canon.String)
			if !ok || (check != nil && !check(string(s))) {
				return nil, false
			}
			out = append(out, string(s))
		}
		return out, true
	}
	isKey := func(s string) bool {
		return strings.HasPrefix(s, "ed25519:") && len(s) == 72 || strings.HasPrefix(s, "0x") && len(s) == 42
	}
	for _, k := range o.Keys {
		var ok bool
		switch k {
		case "format":
			ok = true
		case "exec_signers":
			p.ExecSigners, ok = strs(k, isKey)
		case "exec_workflows":
			p.ExecWorkflows, ok = strs(k, isDigest)
		case "network":
			p.Network, ok = strs(k, isDigest)
		case "images":
			p.Images, ok = strs(k, nil)
		case "ceiling":
			co, isObj := o.Members[k].(*canon.Object)
			ok = isObj
			for _, ck := range keysOf(co) {
				n, isInt := co.Members[ck].(canon.Int)
				if !isInt || n < 0 || !slices.Contains([]string{"cpus", "memory", "pids", "disk", "wall_time"}, ck) {
					return nil, bad("ceiling." + ck + " is not a known cap with a non-negative integer")
				}
				p.Ceiling[ck] = int64(n)
			}
		default:
			return nil, bad("member " + k + " is not defined (native runs and secret grants are not expressible in this format yet)")
		}
		if !ok {
			return nil, bad("member " + k + " has the wrong shape")
		}
	}
	return p, nil
}

func keysOf(o *canon.Object) []string {
	if o == nil {
		return nil
	}
	return o.Keys
}

// rerunPin is the derivation selected for a re-run.
type rerunPin struct {
	statement, signer string
	workflow          string
	env               *canon.Object
	note              string
}

// selectPin picks the authored claim whose derivation the re-run checks: current counted authored statements
// on the blob with full provenance, sorted by id; the first is taken and the others are named.
func (v *view) selectPin(d string) (*rerunPin, []string) {
	a := v.r.Artifact(d)
	var ids []string
	for _, cl := range a.Claims {
		if cl.Provenance == nil {
			continue
		}
		ids = append(ids, cl.Current...)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	if len(ids) == 0 {
		return nil, nil
	}
	p, ok := v.r.Statement(ids[0])
	if !ok {
		return nil, nil
	}
	pv, _ := p.St.Body.Get("provenance")
	po, _ := pv.(*canon.Object)
	if po == nil {
		return nil, nil
	}
	wf, _ := po.Members["workflow"].(canon.String)
	env, _ := po.Members["environment"].(*canon.Object)
	pin := &rerunPin{statement: p.St.ID, signer: p.St.Signer, workflow: string(wf), env: env}
	if len(ids) > 1 {
		pin.note = "several authored claims pin this blob; the re-run checks " + ids[0] + " (the first by id); name another with commons verify <id>"
	}
	return pin, ids
}

// workflowDecl is the workflow's declarations from the authored statement of its default author.
func (v *view) workflowDecl(wf string) (signer, mode, comparator string, match []string, why string) {
	a := v.r.Artifact(wf)
	if a.Default == nil || len(a.Default.Claims) == 0 || len(a.Default.Claims[0].Current) == 0 {
		return "", "", "", nil, "the workflow's authorship is " + string(a.State) + ": no default author declares its replication"
	}
	cl := a.Default.Claims[0]
	p, ok := v.r.Statement(cl.Current[0])
	if !ok {
		return "", "", "", nil, "the workflow's authored statement is not held"
	}
	b := p.St.Body
	s := func(k string) string {
		x, _ := b.Members[k].(canon.String)
		return string(x)
	}
	if em, ok := b.Members["environment_match"].(canon.Array); ok {
		match = []string{}
		for _, e := range em {
			if x, ok := e.(canon.String); ok {
				match = append(match, string(x))
			}
		}
	}
	return cl.Signer, s("replication"), s("comparator"), match, ""
}

func (v *view) readBlob(d string) ([]byte, bool) {
	f, err := v.st.OpenBlob(store.Digest(d))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	return b, err == nil
}

func rerunCause(state, detail string) *Obj {
	o := newObj().set("about", textV("re-run")).set("state", tokV(tok(state)))
	if detail != "" && detail != state {
		o.set("detail", textV(detail))
	}
	return o
}

func (v *view) verifyRerun(c *Ctx, d string) (*Obj, int, error) {
	a := v.r.Artifact(d)
	code0, causes0 := v.verifyArtifact(d)
	o := v.artifactCore(a)
	if a.State == resolve.ContestedAuthorship {
		o.set("claimants", v.claimants(a))
	}
	finish := func(code int, causes listV) (*Obj, int, error) {
		o.set("causes", causes).set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code)))
		return o, code, nil
	}
	if code0 == ExitNothing || len(v.unpinned(d)) > 0 {
		o.set("rerun", newObj().set("ran", boolV(false)).set("why", textV("an input is unpinned: nothing to re-run")))
		return finish(code0, causes0)
	}
	// keep every statement-only cause except the derivation's: the reader's re-run replaces that answer
	var keep listV
	for _, x := range causes0 {
		if xo, ok := x.(*Obj); ok && xo.get("about") == textV("derivation") {
			continue
		}
		keep = append(keep, x)
	}
	stopped := func(why string, ran bool) (*Obj, int, error) {
		o.set("rerun", newObj().set("ran", boolV(ran)).set("why", textV(why)))
		return finish(ExitCouldNot, append(keep, rerunCause("unchecked", why)))
	}
	pin, _ := v.selectPin(d)
	if pin == nil {
		return stopped("no counted authored claim on this blob declares a derivation (provenance): nothing to re-run", false)
	}
	pol, _ := c.Prep.(*ExecPolicy)
	if pol == nil {
		return stopped("no execution policy: nothing ran (give --exec-policy <file>)", false)
	}
	if c.Env.Rerun == nil {
		return stopped("re-run not available in this build: nothing ran", false)
	}
	signer, mode, comparator, match, why := v.workflowDecl(pin.workflow)
	if why != "" {
		return stopped(why+": nothing ran", false)
	}
	spec, ok := v.readBlob(pin.workflow)
	if !ok {
		return stopped("the workflow spec blob "+pin.workflow+" is not held here: nothing ran (fetch it)", false)
	}
	res, err := c.Env.Rerun.Rerun(context.Background(), RerunRequest{Policy: pol, Spec: spec, Signer: signer, Mode: mode,
		Comparator: comparator, Match: match, PinEnv: pin.env, Digest: d, Blob: v.readBlob})
	if err != nil {
		var p *Problem
		if errors.As(err, &p) {
			return nil, 0, p
		}
		return nil, 0, failed(err, "re-run", false, "see peer_text")
	}
	ro := newObj().set("statement", refV(pin.statement)).set("pinned_by", refV(pin.signer)).set("workflow", refV(pin.workflow))
	if pin.note != "" {
		ro.set("note", textV(pin.note))
	}
	if res.Refused != "" {
		ro.set("ran", boolV(false)).set("why", textV("refused before staging: "+res.Refused))
		o.set("rerun", ro)
		return finish(ExitCouldNot, append(keep, rerunCause("unchecked", "refused before staging (no record written): "+res.Refused)))
	}
	ro.set("ran", boolV(true)).set("grade_note", textV("the grade shown is the statements' (the resolver's); this re-run is the reader's own check and changes no statement"))
	if len(res.Explain) > 0 {
		ro.set("explain", texts(res.Explain...))
	}
	o.set("rerun", ro)
	code, causes := combineRerun(keep, rerunCause(res.Token, res.Detail), res.Exit)
	return finish(code, causes)
}

// combineRerun is run.VerifyWithRerun over the CLI's cause objects (checked equal to it by test): a re-run
// exiting 1, 4 or 5 decides the exit and leads the causes; one exiting 3 is a cause like any other; otherwise
// any remaining cause keeps exit 3.
func combineRerun(keep listV, cause *Obj, exit int) (int, listV) {
	switch exit {
	case ExitWrong, ExitNothing, ExitEnvironment:
		return exit, append(listV{cause}, keep...)
	case ExitCouldNot:
		return ExitCouldNot, append(keep, cause)
	}
	// a match is shown too; it decides nothing beside the other causes
	if len(keep) > 0 {
		return ExitCouldNot, append(keep, cause)
	}
	return ExitOK, listV{cause}
}
