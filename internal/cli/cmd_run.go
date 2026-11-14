package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// run [--publish] (execution note §1, §5.1, §5.2, §7). The command executes a workflow the store holds under the
// reader's own execution policy and prints the result token, the environment record and the outputs; nothing is
// appended. With --publish it signs what the run emits (the execution note's §5.1 table: `authored` on a first
// derivation, `reproduced` over the runner's own `authored` of the same provenance, `observed` for an acquisition)
// and commits the statements and the output blobs as one unit.
//
// This package executes nothing: it reads the spec and the policy, hands both to the Executor the binary wires in
// (Env.Exec, the same bridge as verify --rerun), and signs and commits what the execution layer planned. The
// planner (run.PlanPublish) decides every member the tool writes; this file decides only what the runner holds
// (its own current `authored` statements under the run's provenance) and which disclosures it supplied.
//
// Order: every option checked (exit 2, nothing ran) → the workflow resolved and its spec described (an output name
// the spec does not declare is exit 2, nothing ran) → the run (no lock: a run may be long) → without --publish,
// the result → with it: the writer lock, the held statements read again, the plan, the pre-pin check of each
// output's --intended-for, the statements signed, the output blobs installed and the statements committed as one
// journal record (a failure before the commit point removes the blobs it installed: the store is as it was).

// WorkflowInfo is what the execution layer reads from a workflow spec, for the checks made before anything runs.
type WorkflowInfo struct {
	// Digest is the spec blob's digest; Inputs the pinned input digests in provenance order.
	Digest string
	Inputs []string
	// Unpinned lists inputs named by anything but a content hash, as "name (ref)" (§1 rule 1).
	Unpinned []string
	// Outputs are the declared output names, sorted.
	Outputs []string
	// Acquisition is true for a spec that requires the network (§1 rule 3): its outputs are `observed`.
	Acquisition bool
}

// RunRequest is one run: the reader's policy, the spec and its author, and the store's blobs.
type RunRequest struct {
	Policy *ExecPolicy
	Spec   []byte
	// Signer is the workflow's default author (admission by signer, §2.3); "" when it has none.
	Signer string
	Blob   func(digest string) ([]byte, bool)
}

// RunOutput is one output read back.
type RunOutput struct {
	Name, Digest string
	Bytes        []byte
}

// RunResult is a run's outcome. Refused is set (and nothing else) when the run was refused before staging: it
// never started and wrote no record (§5.2).
type RunResult struct {
	Refused string
	// Token is the closed-vocabulary word of the run token, Detail the token as the execution layer prints it,
	// Exit its exit. Completed is true for a step that ran to exit 0 with every output read back.
	Token, Detail string
	Exit          int
	Completed     bool
	// Environment is the run record (§4), nil when the step never started.
	Environment *canon.Object
	Outputs     []RunOutput
	Explain     []string
	// Handle is the execution layer's own result, passed back to Plan unread.
	Handle any
}

// PlanRequest is what the runner holds and supplies, for Executor.Plan (run.PublishInput).
type PlanRequest struct {
	Own              []OwnAuthored
	Of               map[string]string
	Mode, Comparator string
	Disclosures      map[string]map[string]canon.Value
	MediaTypes       map[string]string
	// CaptureAt, WindowFrom and WindowTo are filled for an acquisition; RequestLog names its request log output.
	CaptureAt, WindowFrom, WindowTo string
	RequestLog                      string
}

// OwnAuthored is one of the runner's own current `authored` statements under the run's provenance.
type OwnAuthored struct{ ID, Digest string }

// PlannedStatement is one statement to sign. Result is a `reproduced`'s result word (match, diverged, not
// comparable).
type PlannedStatement struct {
	Output, Kind string
	Body         *canon.Object
	Result       string
}

// Executor runs workflows. The binary supplies one (internal/clirun); tests supply fakes over the same bridge.
type Executor interface {
	Describe(spec []byte) (*WorkflowInfo, error)
	Run(ctx context.Context, q RunRequest) (*RunResult, error)
	// Plan decides what the run emits; a refusal (nothing to publish, a disclosure the tool writes) is an error.
	Plan(r *RunResult, q PlanRequest) ([]PlannedStatement, error)
}

// runPerOutput are the per-output options besides the disclosures: each value is <output>=<value>.
var runPerOutput = []Flag{
	{Name: "of", Value: "output=id", Repeat: true, Help: "the output re-runs this statement of yours (an authored under the same provenance); needed only when the run has several outputs and their bytes changed", Check: perOutput(checkIDFlag)},
	{Name: "media-type", Value: "output=type", Repeat: true, Help: "the output's content.media_type", Check: perOutput(nil)},
}

// perOutput checks an <output>=<value> option value, the value with check.
func perOutput(check func(string) error) func(string) error {
	return func(v string) error {
		out, val, ok := strings.Cut(v, "=")
		if !ok || out == "" {
			return errors.New("not <output>=<value>")
		}
		if check != nil {
			return check(val)
		}
		return nil
	}
}

func init() {
	flags := slices.Clone(writerFlags)
	flags = append(flags,
		Flag{Name: "exec-policy", Value: "file", Help: "the reader's execution policy file (format " + ExecPolicyFormat + ", provisional); required: nothing runs without one"},
		Flag{Name: "publish", Help: "sign and commit what the run emits (authored, reproduced or observed per output) with the output blobs, as one unit"},
		Flag{Name: "request-log", Value: "output", Help: "an acquisition's request log output (rc-request-log/1): its referent's format, count and endpoint are read from it"},
	)
	flags = append(flags, runPerOutput...)
	for _, d := range publishDisclosures {
		f := disclosureFlag(d.Field, d.Shape)
		f.Value, f.Repeat = "output="+f.Value, true
		f.Help = "per output: " + f.Help
		f.Check = perOutput(f.Check)
		flags = append(flags, f)
	}
	Register(&Command{Name: "run", Summary: "run a held workflow under your execution policy; --publish signs what it emits",
		Args: []Arg{{Name: "workflow", Shape: ShapeRef}}, Store: true, Writes: true, Flags: flags, Prepare: prepareRun, Run: runCmd,
		Help: "Runs the workflow spec the store holds (its digest, or the id of an authored statement on it) under --exec-policy, and prints the result token, the environment record and each output; nothing is appended. With --publish (and --key or $" + KeyEnv + ") it signs, per output: authored on a first derivation, reproduced over your own current authored of the same workflow and inputs (match on the same bytes; diverged, or the comparator's word, on different bytes; never a second authored), observed for a workflow that requires the network. Disclosures are per output (--licence out=CC-BY-4.0) and nothing is inherited: not from the workflow, its inputs or a sibling output. The provenance, environment record and capture are written from the run and cannot be supplied. A run that did not complete, or a re-run whose comparison could not finish, publishes nothing and says why. The statements and the output blobs commit as one unit: all or nothing."})
}

// runPrep is what prepareRun checked.
type runPrep struct {
	policy  *ExecPolicy
	publish bool
	pub     *pubPrep // the key and ts, with --publish
	// per output name: disclosures, media type, the statement re-run, the pre-pin edition
	disclosures map[string]map[string]canon.Value
	media, of   map[string]string
	intended    map[string][2]string
	requestLog  string
	tsGiven     bool
}

func prepareRun(c *Ctx) *Problem {
	p := &runPrep{disclosures: map[string]map[string]canon.Value{}, media: map[string]string{}, of: map[string]string{}, intended: map[string][2]string{}}
	path, ok := c.Flag("exec-policy")
	if !ok {
		return usage("missing-argument", "run needs the reader's execution policy", "nothing runs without --exec-policy <file>; nothing was done",
			"option --exec-policy", "give --exec-policy <file> (format "+ExecPolicyFormat+")", "")
	}
	pol, prob := readExecPolicy(path)
	if prob != nil {
		return prob
	}
	p.policy = pol
	_, p.publish = c.Flag("publish")
	if !p.publish {
		for _, f := range c.Cmd.Flags {
			if _, given := c.Flags[f.Name]; given && f.Name != "exec-policy" && f.Name != "json" && f.Name != "store" {
				return usage("malformed-argument", "an option applies only with --publish", "without --publish the run is printed and nothing is signed; nothing was done",
					"option --"+f.Name, "add --publish, or drop --"+f.Name, "")
			}
		}
		c.Prep = p
		return nil
	}
	split := func(name string, each func(out, val string) *Problem) *Problem {
		for _, v := range c.Repeated[name] {
			out, val, _ := strings.Cut(v, "=")
			if prob := each(out, val); prob != nil {
				return prob
			}
		}
		return nil
	}
	twice := func(name, out string) *Problem {
		return usage("malformed-argument", "an option names one output twice", "give each output one value; nothing was done", "option --"+name, "drop one", out)
	}
	for _, d := range publishDisclosures {
		name := flagOf(d.Field)
		if prob := split(name, func(out, val string) *Problem {
			if d.Shape == "pre-pin" {
				if _, dup := p.intended[out]; dup {
					return twice(name, out)
				}
				r, e, _ := strings.Cut(val, "/")
				p.intended[out] = [2]string{r, e}
				return nil
			}
			if p.disclosures[out] == nil {
				p.disclosures[out] = map[string]canon.Value{}
			}
			if _, dup := p.disclosures[out][d.Field]; dup {
				return twice(name, out)
			}
			p.disclosures[out][d.Field] = disclosureValue(d.Shape, val)
			return nil
		}); prob != nil {
			return prob
		}
	}
	for name, m := range map[string]map[string]string{"of": p.of, "media-type": p.media} {
		if prob := split(name, func(out, val string) *Problem {
			if _, dup := m[out]; dup {
				return twice(name, out)
			}
			m[out] = val
			return nil
		}); prob != nil {
			return prob
		}
	}
	p.requestLog, _ = c.Flag("request-log")
	_, p.tsGiven = c.Flag("ts")
	p.pub = &pubPrep{}
	if prob := prepareCommon(c, p.pub); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

// runWorkflow resolves the workflow argument: a spec digest, or an authored statement's id (its content).
func (v *view) runWorkflow(arg string) (string, *Problem) {
	if isDigest(arg) {
		return arg, nil
	}
	p, ok := v.r.Statement(arg)
	if ok && p.St.Kind == "authored" {
		if d := contentOf(p.St); d != "" {
			return d, nil
		}
	}
	return "", usage("malformed-argument", "the statement is not an authored statement on a workflow", "give the workflow spec's digest, or the id of an authored statement whose content is the spec; nothing ran",
		"argument workflow", "commons show <digest> lists the statements on a blob", arg)
}

// runNow is the clock the capture window and the default ts are read from after a run. Tests replace Now.
func runNow() time.Time { return Now().UTC() }

func utcText(t time.Time) string { return t.UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z") }

func runCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*runPrep)
	if c.Env.Exec == nil {
		return nil, 0, &Problem{Slug: "not-available", Title: "run is not available in this build", Class: refusal.Operational, Scope: "invocation",
			Detail: "this build wires no execution bridge; nothing ran", Next: "use a build of the commons binary", Exit: ExitCouldNot}
	}
	v, err := loadView(c.Store, nil)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run status, then fsck")
	}
	wf, prob := v.runWorkflow(c.Args["workflow"])
	if prob != nil {
		return nil, 0, prob
	}
	spec, ok := v.readBlob(wf)
	if !ok {
		return nil, 0, &Problem{Slug: "not-held", Title: "the workflow spec is not held here", Class: refusal.Operational, Scope: "argument workflow",
			Detail: "the spec blob is not in this store (or its stored copy is corrupt); nothing ran", Next: "fetch " + wf, Peer: wf, Exit: ExitCouldNot}
	}
	info, err := c.Env.Exec.Describe(spec)
	if err != nil {
		return nil, 0, &Problem{Slug: "refused", Title: "refused: the workflow spec cannot be run", Class: refusal.Intrinsic, Scope: "workflow " + wf,
			Detail: "the spec does not parse as a workflow spec; nothing ran; the parser's text is in peer_text", Next: "check the digest names a workflow spec",
			Peer: err.Error(), Exit: ExitCouldNot}
	}
	if prob := p.checkOutputs(info); prob != nil {
		return nil, 0, prob
	}
	signer, mode, comparator, _, why := v.workflowDecl(wf)
	out := newObj().set("workflow", refV(wf))
	if signer != "" {
		out.set("author", refV(signer))
	} else {
		out.set("author_note", textV(why+"; admission is by workflow hash only, and the comparison mode is undeclared"))
	}
	start := runNow()
	res, err := c.Env.Exec.Run(context.Background(), RunRequest{Policy: p.policy, Spec: spec, Signer: signer, Blob: v.readBlob})
	if err != nil {
		var pr *Problem
		if errors.As(err, &pr) {
			return nil, 0, pr
		}
		return nil, 0, failed(err, "run", false, "see peer_text")
	}
	end := runNow()
	if res.Refused != "" {
		out.set("ran", boolV(false)).set("why", textV("refused before staging (no record written): "+res.Refused))
		if p.publish {
			out.set("published", boolV(false))
		}
		return out.set("exit", intV(ExitCouldNot)).set("exit_name", textV(ExitName(ExitCouldNot))), ExitCouldNot, nil
	}
	out.set("ran", boolV(res.Environment != nil)).set("run", runResultObj(res))
	if len(info.Unpinned) > 0 {
		out.set("unpinned", texts(info.Unpinned...)).set("unpinned_note", textV("partial provenance: an authored from this run joins no derivation group and verify cannot report T0 (exit 4)"))
	}
	code := ExitOK
	if !res.Completed {
		code = res.Exit
	}
	if !p.publish {
		out.set("published", boolV(false)).set("note", textV("nothing was signed or appended; add --publish to sign what the run emits"))
		return out.set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code))), code, nil
	}
	if !res.Completed {
		out.set("published", boolV(false)).set("why", textV("the run did not complete ("+res.Detail+"): a run that did not complete emits nothing"))
		return out.set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code))), code, nil
	}
	q := PlanRequest{Of: p.of, Mode: mode, Comparator: comparator, Disclosures: p.disclosures, MediaTypes: p.media, RequestLog: p.requestLog}
	if info.Acquisition {
		q.CaptureAt, q.WindowFrom, q.WindowTo = utcText(end), utcText(start), utcText(end)
	}
	if !p.tsGiven {
		p.pub.ts = utcText(runNow())
	}
	return p.publishRun(c, out, wf, info, res, q)
}

// checkOutputs refuses, before anything runs, a per-output option naming an output the spec does not declare.
func (p *runPrep) checkOutputs(info *WorkflowInfo) *Problem {
	check := func(name, out string) *Problem {
		if slices.Contains(info.Outputs, out) {
			return nil
		}
		return usage("unknown-output", "an option names an output the spec does not declare", "the spec declares "+strings.Join(info.Outputs, ", ")+"; nothing ran",
			"option --"+name, "name a declared output", out)
	}
	for out, ds := range p.disclosures {
		for k := range ds {
			if prob := check(flagOf(k), out); prob != nil {
				return prob
			}
		}
	}
	for name, m := range map[string]map[string]string{"of": p.of, "media-type": p.media} {
		for out := range m {
			if prob := check(name, out); prob != nil {
				return prob
			}
		}
	}
	for out := range p.intended {
		if prob := check("intended-for", out); prob != nil {
			return prob
		}
	}
	if p.requestLog != "" {
		if prob := check("request-log", p.requestLog); prob != nil {
			return prob
		}
		if !info.Acquisition {
			return usage("malformed-argument", "--request-log applies to an acquisition", "the spec requires no network, so its outputs are not observations; nothing ran",
				"option --request-log", "drop --request-log", p.requestLog)
		}
	}
	return nil
}

func runResultObj(res *RunResult) *Obj {
	o := newObj().set("state", tokV(tok(res.Token))).set("completed", boolV(res.Completed))
	if res.Detail != res.Token {
		o.set("detail", textV(res.Detail))
	}
	if res.Completed {
		o.set("note", textV("the step ran to exit 0 and every output was read back; nothing is compared until a pin is"))
	}
	if res.Environment != nil {
		o.set("environment", rawV{res.Environment})
	}
	var outs listV
	for _, x := range res.Outputs {
		outs = append(outs, newObj().set("output", textV(x.Name)).set("digest", refV(x.Digest)).set("size", intV(int64(len(x.Bytes)))))
	}
	if len(outs) > 0 {
		o.set("outputs", outs)
	}
	if len(res.Explain) > 0 {
		o.set("explain", texts(res.Explain...))
	}
	return o
}

// ownAuthored lists the runner's own current, counted `authored` statements whose provenance is the run's
// (workflow and input hashes, in order): the input PlanPublish reads the §5.1 table from. Another key's statements
// are never listed (§5.1, last row).
func (v *view) ownAuthored(signer string, info *WorkflowInfo) []OwnAuthored {
	var out []OwnAuthored
	for _, pl := range v.r.All() {
		if pl.St.Kind != "authored" || pl.St.Signer != signer || !v.r.Counted(pl).Counts {
			continue
		}
		pv, _ := pl.St.Body.Get("provenance")
		po, _ := pv.(*canon.Object)
		if po == nil || po.Members["workflow"] != canon.String(info.Digest) {
			continue
		}
		ins, _ := po.Members["inputs"].(canon.Array)
		var got []string
		for _, x := range ins {
			s, _ := x.(canon.String)
			got = append(got, string(s))
		}
		if !slices.Equal(got, info.Inputs) {
			continue
		}
		d := contentOf(pl.St)
		for _, cl := range v.r.Artifact(d).Claims {
			if cl.Subject == resolve.KeySubject(signer) && slices.Contains(cl.Current, pl.St.ID) {
				out = append(out, OwnAuthored{ID: pl.St.ID, Digest: d})
				break
			}
		}
	}
	return out
}

// publishRun signs and commits what the run emits, under the writer lock, from the statements held now.
func (p *runPrep) publishRun(c *Ctx, out *Obj, wf string, info *WorkflowInfo, res *RunResult, q PlanRequest) (*Obj, int, error) {
	bytesOf := map[string][]byte{}
	for _, o := range res.Outputs {
		bytesOf[o.Digest] = o.Bytes
	}
	mem := memContent{st: c.Store, mem: bytesOf}
	signer := p.pub.key.Key.Signer()
	wl := lockFor(c, signer)
	defer wl.Unlock()
	var opts []resolve.Option
	for _, d := range ruleDialects {
		opts = append(opts, resolve.WithDialect(d))
	}
	opts = append(opts, resolve.WithContent(gate.NewMemoContent(mem, 0)))
	v, err := loadView(c.Store, nil, opts...)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run status, then fsck")
	}
	h, prob := v.nextLine(c, signer, "authored")
	if prob != nil {
		return nil, 0, prob
	}
	afterHead()
	noteLock(out, wl)
	q.Own = v.ownAuthored(signer, info)
	for o, id := range q.Of {
		if !slices.ContainsFunc(q.Own, func(a OwnAuthored) bool { return a.ID == id }) {
			return nil, 0, &Problem{Slug: "refused", Title: "refused: --of names no authored of yours under this provenance", Class: refusal.Policy,
				Scope: "option --of", Detail: "output " + strconv.Quote(o) + " names a statement that is not one of your own current authored statements with this workflow and these inputs; the run is printed, nothing was signed or appended",
				Next: "name one of yours (commons show <digest>), or drop --of to publish a first derivation", Peer: id, Exit: exitWriterRefused}
		}
	}
	plan, err := c.Env.Exec.Plan(res, q)
	if err != nil {
		var r *refusal.Refusal
		if errors.As(err, &r) {
			why := r.Reason
			if r.Detail != "" {
				why += ": " + r.Detail
			}
			out.set("published", boolV(false)).set("why", textV(why))
			code := ExitCouldNot
			if r.Class == refusal.Policy {
				code = ExitDidNotStart
			}
			return v.scopedResult(out.set("exit", intV(int64(code))).set("exit_name", textV(ExitName(code))), code, nil)
		}
		return nil, 0, failed(err, "publish plan", false, "see peer_text")
	}
	var drafts []wire.Draft
	var blobs []store.Digest
	var warns []string
	var pl listV
	for _, s := range plan {
		body := s.Body
		row := newObj().set("output", textV(s.Output)).set("kind", peerV(s.Kind))
		if s.Result != "" {
			row.set("state", tokV(tok(s.Result)))
		}
		if pin, ok := p.intended[s.Output]; ok {
			if s.Kind == "reproduced" {
				return v.scopedResult(out.set("published", boolV(false)).set("why", textV("--intended-for names output "+strconv.Quote(s.Output)+", which this run emits as a reproduced: a reproduced carries no disclosures; nothing was signed")).
					set("exit", intV(ExitDidNotStart)).set("exit_name", textV(ExitName(ExitDidNotStart))), ExitDidNotStart, nil)
			}
			pp, err := v.r.CheckIntendedFor(body, pin[0], pin[1])
			if err != nil {
				return nil, 0, prepinRefused(err, &pubPrep{resource: pin[0], edition: pin[1]})
			}
			body = pp.Body
			row.set("intended_for", newObj().set("resource", refV(pp.Resource)).set("edition", refV(pp.Edition)).set("state", tokV(tok(string(pp.Outcome)))))
		}
		if s.Kind == "reproduced" && len(p.disclosures[s.Output]) > 0 {
			warns = append(warns, "output "+strconv.Quote(s.Output)+" is a reproduced, which carries no disclosures: the ones supplied for it are not written")
		}
		if w := withheldWarning(body); w != "" {
			warns = append(warns, w)
		}
		pl = append(pl, row)
		drafts = append(drafts, wire.Draft{Kind: s.Kind, Body: body})
		d := store.Digest(contentOf(&wire.Statement{Body: body}))
		if d != "" && !slices.Contains(blobs, d) {
			blobs = append(blobs, d)
		}
		if s.Kind == "authored" {
			hb := &canon.Object{Keys: []string{"content"}, Members: map[string]canon.Value{"content": body.Members["content"]}}
			drafts = append(drafts, wire.Draft{Kind: "holds", Body: hb})
		}
	}
	out.set("emits", pl)
	if len(warns) > 0 {
		out.set("warnings", texts(warns...))
	}
	sts, err := signAll(p.pub.key.Key, h, p.pub.ts, drafts)
	if err != nil {
		return nil, 0, writeRefused(err)
	}
	open := func(d store.Digest) (io.ReadCloser, error) {
		b, ok := bytesOf[string(d)]
		if !ok {
			return nil, errors.New("no output has digest " + string(d))
		}
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	return v.scopedResult(commitUnitFrom(c, out, "run", sts, blobs, open, "run outputs", h))
}

// memContent gives edition rules a run output's bytes before they are installed, the store's blobs otherwise.
type memContent struct {
	st  *store.Store
	mem map[string][]byte
}

func (m memContent) Units(d string) ([]resolve.ContentUnit, bool) {
	if b, ok := m.mem[d]; ok {
		units, err := gate.ScanReader(keylog.Short(strings.TrimPrefix(d, "sha256:")), bytes.NewReader(b), store.DefaultLimits(), maxScan, "size limit="+strconv.FormatInt(maxScan, 10))
		return units, err == nil
	}
	return prepinContent{st: m.st, digest: d}.Units(d)
}
