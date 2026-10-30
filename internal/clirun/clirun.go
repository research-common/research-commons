// Package clirun is the one bridge between the command line and the execution layer: it implements
// cli.Rerunner over run.Rerun. Package cli imports nothing that executes; the binary (cmd/commons) wires this
// bridge in, and it is the only execution import the binary has (checked by the CLI's static test).
package clirun

import (
	"context"
	"errors"
	"strings"

	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/run"
)

// Bridge runs re-runs on Runner (the OCI sandbox in the binary, a fake under test).
type Bridge struct {
	Runner run.Runner
	// Comparator runs a protocol workflow's comparator; nil = none configured (the comparison is unchecked).
	Comparator run.Comparator
	// StagingRoot is where staging directories go ("" = the OS temp directory).
	StagingRoot string
}

// Sandbox is the binary's bridge: re-runs on the OCI sandbox runner (execution note §2.1), no comparator runner.
func Sandbox() *Bridge { return &Bridge{Runner: &run.OCI{}} }

// Policy converts the CLI's execution policy into the execution layer's. Grants, native and own keys stay
// empty: the provisional file format has no place for them.
func Policy(p *cli.ExecPolicy) *run.Policy {
	rp := &run.Policy{ExecSigners: p.ExecSigners, ExecWorkflows: p.ExecWorkflows, Network: p.Network, Images: p.Images,
		Ceiling: run.Resources{}}
	for k, v := range p.Ceiling {
		rp.Ceiling[k] = v
	}
	return rp
}

// Rerun implements cli.Rerunner.
func (b *Bridge) Rerun(ctx context.Context, q cli.RerunRequest) (cli.RerunResult, error) {
	spec, err := run.ParseSpec(q.Spec)
	if err != nil {
		return refusedResult(err), nil
	}
	blobs := map[string][]byte{}
	need := append([]string{spec.Code}, spec.InputDigests()...)
	for _, d := range need {
		data, ok := q.Blob(d)
		if !ok {
			return cli.RerunResult{Refused: "blob " + d + " is not held here (staging needs the code and every pinned input; fetch them)"}, nil
		}
		blobs[d] = data
	}
	pin := run.Pin{Mode: q.Mode, Comparator: q.Comparator, Match: q.Match, Env: run.Fields(q.PinEnv), Output: q.Output, Digest: q.Digest}
	inv := run.Invocation{Request: run.Request{Spec: spec, Signer: q.Signer}, Blobs: blobs, StagingRoot: b.StagingRoot}
	_, d, err := run.Rerun(ctx, Policy(q.Policy), b.Runner, inv, pin, b.Comparator)
	if err != nil {
		var r *refusal.Refusal
		if errors.As(err, &r) {
			return refusedResult(r), nil
		}
		return cli.RerunResult{}, err
	}
	return cli.RerunResult{Token: Word(d.Token), Detail: d.Token.String(), Exit: d.Token.Exit(), Explain: d.Explain}, nil
}

func refusedResult(err error) cli.RerunResult {
	var r *refusal.Refusal
	if errors.As(err, &r) {
		return cli.RerunResult{Refused: string(r.Class) + ": " + r.Reason + " (" + r.Detail + ")"}
	}
	return cli.RerunResult{Refused: err.Error()}
}

// Word is the closed-vocabulary word of a run token: the token without its parameter.
func Word(t run.Token) string {
	switch t.Kind {
	case run.FailedExit:
		return "failed"
	case run.FailedCap:
		return "failed: operational"
	case run.EnvMismatch:
		return "environment mismatch"
	case run.Match:
		if t.Identical {
			return "match (identical bytes)"
		}
	}
	return strings.TrimSpace(string(t.Kind))
}
