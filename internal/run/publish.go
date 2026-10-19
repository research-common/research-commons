package run

import (
	"slices"
	"strconv"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
)

// What `run --publish` emits (execution note §5.1, §7, §1 rules 1 and 3). PlanPublish is pure: it returns the
// statement bodies to sign, and the caller signs them with the runner's own key through wire.Write, which reads
// each back through the one validation core, so nothing leaves the writer that a reader would refuse.
//
// Encodings the wire note does not fix yet (each is a spec finding in this slice's report; a wire reader
// retains them as unknown fields, and no resolver reads them):
//   - partial provenance (§1 rule 1): the wire `provenance` requires every input as a digest, so a run with an
//     unpinned input writes no `provenance` (it joins no derivation group) and writes `provenance_partial`
//     {workflow, inputs (the pinned ones), unpinned (the names as written), environment};
//   - an acquisition's capture record (§1 rule 3): the endpoints, the run's window and the environment record
//     go in `capture` as `endpoints`, `window` and `environment`, beside the wire's `at` and `evidence`.

// HeldAuthored is one of the runner's own counted, current `authored` statements under this run's provenance.
type HeldAuthored struct {
	ID, Digest string
}

// PublishInput is everything PlanPublish needs.
type PublishInput struct {
	Spec   *Spec
	Result *Result
	// Own are the runner's own current `authored` statements with this run's provenance (workflow and input
	// hashes), from the held set. Another key's statements are never passed: they change nothing here (§5.1,
	// last row; the group display handles them).
	Own []HeldAuthored
	// Of names, for an output whose bytes match none of Own, the runner's own `authored` it re-runs. With one
	// output and one own statement it is inferred; with several outputs, provenance does not say which output a
	// statement is, so an unnamed output is a first derivation.
	Of map[string]string
	// Mode, Comparator and Cmp are the workflow's declarations and the reader's comparator runner, for a
	// re-run whose bytes differ (§5.3).
	Mode, Comparator string
	Cmp              Comparator
	// Disclosures are supplied per output name (§7). Nothing is inherited: not from the workflow, the inputs or
	// a sibling output.
	Disclosures map[string]map[string]canon.Value
	// MediaTypes per output name (optional).
	MediaTypes map[string]string
	// Capture is filled for an acquisition: the time the capture finished and the window it ran in.
	CaptureAt, WindowFrom, WindowTo string
	// RequestLog names the output that is the run's request log, with its format and request count, for an
	// acquisition that made more than one request (§1 rule 3).
	RequestLog *RequestLog
}

// RequestLog names an acquisition's request log output.
type RequestLog struct {
	Output, Format string
	Count          int64
}

// Planned is one statement to sign.
type Planned struct {
	Output string
	Kind   string // "authored", "reproduced" or "observed"
	Body   *canon.Object
	// Token is the result of a `reproduced` (match, diverged, not comparable).
	Token Token
}

// Disclosure names `run --publish` accepts: every disclosure of `authored` (wire §5, the disclosures group,
// and the author's lineage fields). `type`, `content` and `provenance` are written by the tool from the run
// and cannot be supplied (§7).
var Disclosure = []string{"attribution", "availability", "comparator", "description", "extends", "fulfills",
	"intended_for", "licence", "licence_texts", "pre_registration", "replication", "sampling", "shelf_life_days",
	"supersedes"}

// written are the members the tool writes from the run; a disclosure may not supply them (§7).
var written = []string{"content", "type", "provenance", "provenance_partial", "class", "referent", "capture"}

// PlanPublish decides what a completed run emits. A run that did not complete (a failed step, a missing
// output, a cap, a timeout, the pinned environment unavailable) emits nothing (§2.2, §5.2; C-exec-11, C-exec-15).
func PlanPublish(in PublishInput) ([]Planned, error) {
	r := in.Result
	if r == nil || !r.Completed() {
		tok := "no run"
		if r != nil {
			tok = r.Token.String()
		}
		return nil, &refusal.Refusal{Class: refusal.Operational, Reason: "nothing to publish",
			Detail: "the run result is " + tok + "; no statement is emitted"}
	}
	for out, ds := range in.Disclosures {
		if _, ok := r.Output(out); !ok {
			return nil, &refusal.Refusal{Class: refusal.Policy, Reason: "unknown output", Detail: "disclosures name output " + strconv.Quote(out) + ", which the spec does not declare"}
		}
		for k := range ds {
			if slices.Contains(written, k) || !slices.Contains(Disclosure, k) {
				return nil, &refusal.Refusal{Class: refusal.Policy, Reason: "not a disclosure",
					Detail: strconv.Quote(k) + " is written by the tool from the run or is not a disclosure of authored"}
			}
		}
	}
	env := r.Record.Object()
	var plan []Planned
	for _, o := range r.Outputs {
		content := contentObject(o, in.MediaTypes[o.Name])
		if in.Spec.Acquisition() {
			plan = append(plan, Planned{Output: o.Name, Kind: "observed", Body: observedBody(in, o, content, env)})
			continue
		}
		if un := in.Spec.Unpinned(); len(un) > 0 {
			b := disclosed(in.Disclosures[o.Name])
			b.set("content", content)
			b.set("type", canon.String("dataset"))
			b.set("provenance_partial", object(
				"workflow", canon.String(in.Spec.Digest),
				"inputs", strings2array(in.Spec.InputDigests()),
				"unpinned", strings2array(un),
				"environment", env))
			plan = append(plan, Planned{Output: o.Name, Kind: "authored", Body: b.done()})
			continue
		}
		prov := object("workflow", canon.String(in.Spec.Digest), "inputs", strings2array(in.Spec.InputDigests()), "environment", env)
		of, tok := in.reproduces(o)
		if of == "" {
			b := disclosed(in.Disclosures[o.Name])
			b.set("content", content)
			b.set("type", canon.String("dataset"))
			b.set("provenance", prov)
			plan = append(plan, Planned{Output: o.Name, Kind: "authored", Body: b.done()})
			continue
		}
		if tok.WireResult() == "" {
			// the comparison could not run (no comparator, mode undeclared): a reproduced needs a result, so
			// the re-run emits nothing and says why (wire §5: match, diverged, not-comparable)
			return nil, &refusal.Refusal{Class: refusal.Operational, Reason: "nothing to publish",
				Detail: "output " + strconv.Quote(o.Name) + " re-runs " + of + " and the comparison is " + tok.String() + "; a reproduced needs a completed comparison"}
		}
		b := &builder{o: &canon.Object{Members: map[string]canon.Value{}}}
		b.set("of", canon.String(of))
		b.set("result", canon.String(tok.WireResult()))
		b.set("content", content)
		b.set("provenance", prov)
		if in.Mode == "protocol" && in.Comparator != "" && !tok.Identical {
			b.set("comparator", canon.String(in.Comparator))
		}
		plan = append(plan, Planned{Output: o.Name, Kind: "reproduced", Body: b.done(), Token: tok})
	}
	return plan, nil
}

// reproduces finds the runner's own `authored` this output re-runs (§5.1): one with the same bytes is a match;
// otherwise the one named in Of, or the only one when the run has one output and the runner one statement.
func (in PublishInput) reproduces(o OutputBlob) (string, Token) {
	for _, h := range in.Own {
		if h.Digest == o.Digest {
			t := Token{Kind: Match}
			if in.Mode == "protocol" {
				t.Identical = true
			}
			return h.ID, t
		}
	}
	var pin *HeldAuthored
	if id, ok := in.Of[o.Name]; ok {
		for i := range in.Own {
			if in.Own[i].ID == id {
				pin = &in.Own[i]
			}
		}
	} else if len(in.Result.Outputs) == 1 && len(in.Own) == 1 {
		pin = &in.Own[0]
	}
	if pin == nil {
		return "", Token{}
	}
	t, _ := compareOutputs(Pin{Mode: in.Mode, Comparator: in.Comparator, Digest: pin.Digest}, o.Digest, in.Cmp, nil)
	return pin.ID, t
}

func observedBody(in PublishInput, o OutputBlob, content, env *canon.Object) *canon.Object {
	b := disclosed(in.Disclosures[o.Name])
	b.set("content", content)
	b.set("class", canon.String("source"))
	var ref *canon.Object
	switch {
	case in.RequestLog != nil:
		lg, _ := in.Result.Output(in.RequestLog.Output)
		ref = object("requests", object("digest", canon.String(lg.Digest), "format", canon.String(in.RequestLog.Format), "count", canon.Int(in.RequestLog.Count)))
	case len(in.Spec.Network) == 1:
		params := in.Spec.Parameters
		if params == nil {
			params = &canon.Object{Members: map[string]canon.Value{}}
		}
		ref = object("endpoint", canon.String(in.Spec.Network[0]), "parameters", params, "response_digest", canon.String(o.Digest))
	default:
		ref = &canon.Object{Members: map[string]canon.Value{}} // shown unpinned: the referent cannot be filled from the run
	}
	b.set("referent", ref)
	capture := object("at", canon.String(in.CaptureAt), "evidence", canon.String("self-asserted"),
		"endpoints", strings2array(in.Spec.Network), "environment", env)
	if in.WindowFrom != "" {
		capture.Keys = append(capture.Keys, "window")
		capture.Members["window"] = object("from", canon.String(in.WindowFrom), "to", canon.String(in.WindowTo))
		slices.SortFunc(capture.Keys, canon.CompareKeys)
	}
	b.set("capture", capture)
	return b.done()
}

func contentObject(o OutputBlob, media string) *canon.Object {
	c := object("digest", canon.String(o.Digest), "size", canon.Int(int64(len(o.Bytes))))
	if media != "" {
		c.Keys = append(c.Keys, "media_type")
		c.Members["media_type"] = canon.String(media)
		slices.SortFunc(c.Keys, canon.CompareKeys)
	}
	return c
}

type builder struct{ o *canon.Object }

func disclosed(ds map[string]canon.Value) *builder {
	b := &builder{o: &canon.Object{Members: map[string]canon.Value{}}}
	for k, v := range ds {
		b.set(k, v)
	}
	return b
}

func (b *builder) set(k string, v canon.Value) {
	if _, ok := b.o.Members[k]; !ok {
		b.o.Keys = append(b.o.Keys, k)
	}
	b.o.Members[k] = v
}

func (b *builder) done() *canon.Object {
	slices.SortFunc(b.o.Keys, canon.CompareKeys)
	return b.o
}

func object(kv ...any) *canon.Object {
	b := &builder{o: &canon.Object{Members: map[string]canon.Value{}}}
	for i := 0; i < len(kv); i += 2 {
		b.set(kv[i].(string), kv[i+1].(canon.Value))
	}
	return b.done()
}

// Partial reads an `authored` body's partial provenance: the unpinned inputs, or nil when the body has none.
// `verify` of such a blob has nothing to re-run: exit 4, naming the inputs (§1 rule 1; C-exec-03).
func Partial(body *canon.Object) []string {
	v, ok := body.Get("provenance_partial")
	if !ok {
		return nil
	}
	po, ok := v.(*canon.Object)
	if !ok {
		return nil
	}
	u, ok := po.Get("unpinned")
	if !ok {
		return nil
	}
	arr, _ := u.(canon.Array)
	var out []string
	for _, x := range arr {
		if s, ok := x.(canon.String); ok {
			out = append(out, string(s))
		}
	}
	return out
}

// VerifyPartial is `verify` for a derivation with partial provenance: nothing to re-run (exit 4), the unpinned
// inputs named. It never reports T0.
func VerifyPartial(unpinned []string) (int, []string) {
	why := []string{"nothing to re-run: provenance is partial"}
	for _, u := range unpinned {
		why = append(why, "unpinned input "+u)
	}
	return NothingToRerun.Exit(), why
}
