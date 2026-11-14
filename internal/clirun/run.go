package clirun

import (
	"context"
	"errors"

	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/run"
)

// Describe implements cli.Executor: what `run` checks before anything runs.
func (b *Bridge) Describe(spec []byte) (*cli.WorkflowInfo, error) {
	s, err := run.ParseSpec(spec)
	if err != nil {
		return nil, err
	}
	info := &cli.WorkflowInfo{Digest: s.Digest, Inputs: s.InputDigests(), Unpinned: s.Unpinned(), Acquisition: s.Acquisition()}
	for _, o := range s.Outputs {
		info.Outputs = append(info.Outputs, o.Name)
	}
	return info, nil
}

// handle is the execution layer's result, carried from Run to Plan through cli.RunResult.Handle.
type handle struct {
	spec *run.Spec
	res  *run.Result
}

// Run implements cli.Executor over run.Execute: staging, admission, the step, the read-back.
func (b *Bridge) Run(ctx context.Context, q cli.RunRequest) (*cli.RunResult, error) {
	s, err := run.ParseSpec(q.Spec)
	if err != nil {
		return &cli.RunResult{Refused: refusedResult(err).Refused}, nil
	}
	blobs := map[string][]byte{}
	for _, d := range append([]string{s.Code}, s.InputDigests()...) {
		data, ok := q.Blob(d)
		if !ok {
			return &cli.RunResult{Refused: "blob " + d + " is not held here (staging needs the code and every pinned input; fetch them)"}, nil
		}
		blobs[d] = data
	}
	inv := run.Invocation{Request: run.Request{Spec: s, Signer: q.Signer}, Blobs: blobs, StagingRoot: b.StagingRoot}
	res, err := run.Execute(ctx, Policy(q.Policy), b.Runner, inv)
	if err != nil {
		var r *refusal.Refusal
		if errors.As(err, &r) {
			return &cli.RunResult{Refused: refusedResult(r).Refused}, nil
		}
		return nil, err
	}
	out := &cli.RunResult{Token: Word(res.Token), Detail: res.Token.String(), Exit: res.Token.Exit(), Completed: res.Completed(),
		Explain: res.Explain, Handle: handle{spec: s, res: res}}
	if res.Record != nil {
		out.Environment = res.Record.Object()
	}
	for _, o := range res.Outputs {
		out.Outputs = append(out.Outputs, cli.RunOutput{Name: o.Name, Digest: o.Digest, Bytes: o.Bytes})
	}
	return out, nil
}

// Plan implements cli.Executor over run.PlanPublish: the execution note's §5.1 table.
func (b *Bridge) Plan(r *cli.RunResult, q cli.PlanRequest) ([]cli.PlannedStatement, error) {
	h, ok := r.Handle.(handle)
	if !ok {
		return nil, errors.New("clirun: the run result is not this bridge's")
	}
	in := run.PublishInput{Spec: h.spec, Result: h.res, Of: q.Of, Mode: q.Mode, Comparator: q.Comparator, Cmp: b.Comparator,
		Disclosures: q.Disclosures, MediaTypes: q.MediaTypes, CaptureAt: q.CaptureAt, WindowFrom: q.WindowFrom, WindowTo: q.WindowTo}
	for _, o := range q.Own {
		in.Own = append(in.Own, run.HeldAuthored{ID: o.ID, Digest: o.Digest})
	}
	if q.RequestLog != "" {
		in.RequestLog = &run.RequestLog{Output: q.RequestLog}
	}
	plan, err := run.PlanPublish(in)
	if err != nil {
		return nil, err
	}
	var out []cli.PlannedStatement
	for _, p := range plan {
		ps := cli.PlannedStatement{Output: p.Output, Kind: p.Kind, Body: p.Body}
		if p.Kind == "reproduced" {
			ps.Result = Word(p.Token)
		}
		out = append(out, ps)
	}
	return out, nil
}
