package resolve

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Every unsupported fixture is signed with a synthetic test key and ingested by
// wire.Read and keylog. Unknown algorithms really sign, but are not verified by
// this reader; a subsequent ordinary signature vouches for their placement.
func signOpaqueObservationInput(w *world, mode, name, by, kind string, body *canon.Object) string {
	w.t.Helper()
	if mode == "critical" {
		return signCritical(w, name, by, kind, body)
	}
	key := w.key(by)
	d := wire.Draft{Kind: kind, Body: body}
	if mode == "major" {
		d.RC = "rc/2"
	} else {
		w.keys[by] = unknownAlgorithmKey{key}
	}
	id := signDraft(w, name, by, d)
	w.keys[by] = key
	w.sign(name+"-vouch", by, "holds", obj("content", contentOf("vouch")))
	return id
}

func opaqueDeliveryOrders(w *world) [][]int {
	var reverse, duplicate []int
	for i := range w.lines {
		reverse = append(reverse, len(w.lines)-1-i)
		duplicate = append(duplicate, i, i)
	}
	return [][]int{nil, reverse, duplicate}
}

func noObservationPanic(t *testing.T) {
	t.Helper()
	if v := recover(); v != nil {
		t.Errorf("observation view panicked on retained opaque evidence: %v", v)
	}
}

func opaqueObservedBody() *canon.Object {
	return obj("content", contentOf("X"), "class", "exact-bytes", "referent", chainRef(3),
		"finality", obj("rule", "confirmations >= 6", "rule_source", dig("rule"), "state_at_capture", obj("depth", 3)),
		"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "device-attested", "operator", "opaque operator",
			"instrument", "opaque instrument", "attestation", obj("format", "test")))
}

// Successful callbacks would manufacture apparently meaningful status if an
// opaque input leaked past the gate. Record every call, not just the final count.
type opaqueObservationHooks struct{ calls []string }

func (h *opaqueObservationHooks) Check(*wire.Statement) ReCheck {
	h.calls = append(h.calls, "referent")
	return ReCheck{Outcome: ReSame}
}
func (h *opaqueObservationHooks) Evaluate(string, State) (bool, string, bool) {
	h.calls = append(h.calls, "finality")
	return true, "6", true
}
func (h *opaqueObservationHooks) Compare(string, State, State) (int, bool) {
	h.calls = append(h.calls, "compare")
	return 0, true
}
func (h *opaqueObservationHooks) VerifyAttestation(*wire.Statement) (bool, string) {
	h.calls = append(h.calls, "attestation")
	return true, ""
}
func (h *opaqueObservationHooks) Has(string) bool {
	h.calls = append(h.calls, "blob")
	return true
}
func (h *opaqueObservationHooks) Apply(string) ([]string, string, string, bool) {
	h.calls = append(h.calls, "cohort")
	return nil, "", "", true
}
func (h *opaqueObservationHooks) Verify(*wire.Statement) Bound {
	h.calls = append(h.calls, "time")
	return Bound{}
}
func (h *opaqueObservationHooks) options() []Option {
	return []Option{WithReferentChecker(h), WithFinalityRules(h), WithAttestationVerifier(h), WithBlobIndex(h), WithCohortRules(h), WithTimeVerifier(h)}
}

func assertOpaqueObservation(t *testing.T, o *Observation, id string) {
	t.Helper()
	if o == nil || o.Statement != id || o.Signer == "" || o.Counts || o.BodyUnderstood || o.Class != "" || len(o.Referent) != 0 || len(o.Unpinned) != 0 || o.Finality != nil ||
		!reflect.DeepEqual(o.Capture, Capture{}) || len(o.Comparability) != 0 || len(o.Others) != 0 || len(o.ReferentHistory) != 0 {
		t.Fatalf("opaque observation acquired interpreted fields: %+v", o)
	}
	if o.ReCheck.Outcome != ReUnchecked || o.Corroboration == nil || !o.Corroboration.Unchecked || o.Corroboration.Corroborated != 0 || o.Corroboration.Contradicted != 0 || len(o.Corroboration.Evidence) != 0 {
		t.Fatalf("opaque observation acquired corroboration: %+v", o.Corroboration)
	}
	has(t, o.Render(), "body not interpreted")
	has(t, o.Render(), keylog.Short(id))
	has(t, o.Render(), "unsupported")
	hasNot(t, o.Render(), "(asserted by")
	hasNot(t, o.Render(), "roles:")
}

func TestOpaqueObservationBodies(t *testing.T) {
	cases := []struct {
		name, field string
		value       canon.Value
		valid       bool
	}{
		{name: "apparently_valid", valid: true},
		{"finality_number", "finality", canon.Int(1), false},
		{"finality_null", "finality", canon.Null{}, false},
		{"finality_array", "finality", canon.Array{}, false},
		{"capture_scalar", "capture", canon.String("opaque"), false},
		{"witnesses_scalar", "capture", obj("witnesses", "opaque"), false},
		{"witnesses_mixed", "capture", obj("witnesses", canon.Array{canon.Int(1)}), false},
		{"referent_null", "referent", canon.Null{}, false},
		{"referent_array", "referent", canon.Array{}, false},
		{"content_scalar", "content", canon.String("opaque"), false},
		{"content_digest_number", "content", obj("digest", 1), false},
		{"missing_fields", "", nil, false},
	}
	for _, by := range []string{"A", "BB"} {
		for _, mode := range []string{"critical", "major", "algorithm"} {
			for _, tc := range cases {
				for _, lite := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/%s/lite=%t", by, mode, tc.name, lite), func(t *testing.T) {
						defer noObservationPanic(t)
						w := newWorld(t)
						body := opaqueObservedBody()
						if tc.name == "missing_fields" {
							body = obj("content", contentOf("X"))
						} else if tc.field != "" {
							body.Members[tc.field] = tc.value
						}
						plain, _ := wire.Sign(wire.Draft{Kind: "observed", TS: "2026-10-16T02:00:00Z", Body: body}, w.key(by))
						if _, err := wire.Read(plain); (err == nil) != tc.valid {
							t.Fatalf("unexpected ordinary schema control: %v", err)
						}
						id := signOpaqueObservationInput(w, mode, "opaque", by, "observed", body)
						// A supported anchor must not cause opaque capture interpretation.
						w.anchor("anchor", by, "btc:812000")
						var first string
						for _, order := range opaqueDeliveryOrders(w) {
							h := &opaqueObservationHooks{}
							r := w.store(order, h.options()...)
							p := requireRetained(t, r, id, wire.Unsupported, mode == "critical", true)
							if !bytes.Equal(p.St.Line(), w.lines[0]) || (mode == "major" && p.St.Body != nil) {
								t.Fatal("opaque wire evidence changed")
							}
							var o *Observation
							if lite {
								o = r.observationLite(p)
							} else {
								var ok bool
								o, ok = r.Observation(id)
								if !ok {
									t.Fatal("placed observation lost")
								}
							}
							assertOpaqueObservation(t, o, id)
							wantDigest := contentDigest(body)
							if mode == "major" {
								wantDigest = ""
							}
							if o.Digest != wantDigest {
								t.Fatal("unsafe content association")
							}
							if got := r.Observations(dig("X")); (len(got) == 1) != (wantDigest == dig("X")) {
								t.Fatalf("blob lookup lost or invented association: %d", len(got))
							}
							if len(r.Observations("")) != 0 {
								t.Fatal("absent content became an association")
							}
							if len(h.calls) != 0 {
								t.Fatalf("opaque body reached reader callbacks: %v", h.calls)
							}
							if got := o.Render(); first == "" {
								first = got
							} else if got != first {
								t.Fatal("delivery changed opaque display")
							}
						}
					})
				}
			}
		}
	}
}

func opaqueEvidence(t *testing.T, c *Corroboration, id string) Evidence {
	t.Helper()
	for _, e := range c.Evidence {
		if e.Statement == id {
			return e
		}
	}
	t.Fatalf("opaque corroboration %s disappeared: %+v", id, c)
	return Evidence{}
}

func assertOpaqueEvidence(t *testing.T, e Evidence) {
	t.Helper()
	if e.Counted || e.Key == "" || e.Via != "corroborates" || !strings.Contains(e.Cause, "unsupported") ||
		e.Verdict != "" || e.Model != "" || e.Cohort != "" || len(e.Shares) != 0 || e.Result != "" || e.Grade != "" ||
		len(e.Comparison) != 0 || len(e.CohortCheck) != 0 || e.Capture != "" {
		t.Fatalf("opaque corroboration interpreted: %+v", e)
	}
}

func TestOpaqueCorroborationBodies(t *testing.T) {
	for _, by := range []string{"A", "BB"} {
		for _, mode := range []string{"critical", "major", "algorithm"} {
			for _, shares := range []canon.Value{canon.String("not an array"), canon.Null{}, obj(), canon.Array{canon.Int(1)}, canon.Array{canon.String("feed")}} {
				t.Run(fmt.Sprintf("%s/%s/%s", by, mode, canon.Encode(shares)), func(t *testing.T) {
					defer noObservationPanic(t)
					w := newWorld(t)
					x := w.observed("X", "observer", "X", "none-yet", obj())
					w.workflow("workflow", "W", "bytes", "")
					result := w.result("result", "result-key", "verdict", "W", "X", "REF")
					body := obj("of", x, "result", result, "verdict", "contradicts", "model", "opaque model", "cohort", obj("rule", "opaque rule"), "shares", shares)
					plain, _ := wire.Sign(wire.Draft{Kind: "corroborates", TS: "2026-10-16T02:00:00Z", Body: body}, w.key(by))
					_, err := wire.Read(plain)
					if (err == nil) != bytes.Equal(canon.Encode(shares), []byte(`["feed"]`)) {
						t.Fatalf("schema control: %v", err)
					}
					id := signOpaqueObservationInput(w, mode, "opaque", by, "corroborates", body)
					var first string
					for _, order := range opaqueDeliveryOrders(w) {
						h := &opaqueObservationHooks{}
						r := w.store(order, WithCohortRules(h), WithOrigins(fakeOrigins{id: {"z", "a"}}))
						requireRetained(t, r, id, wire.Unsupported, mode == "critical", true)
						o, _ := r.Observation(x)
						if mode == "major" {
							if len(o.Corroboration.Evidence) != 0 {
								t.Fatal("unknown major supplied an of association")
							}
						} else {
							e := opaqueEvidence(t, o.Corroboration, id)
							assertOpaqueEvidence(t, e)
							if !slices.Equal(e.Origins, []string{"a", "z"}) {
								t.Fatal("delivery evidence lost")
							}
						}
						wantStatus(t, o, "unchecked within statements you hold")
						if len(h.calls) != 0 {
							t.Fatalf("opaque cohort evaluated: %v", h.calls)
						}
						if got := o.Render(); first == "" {
							first = got
						} else if got != first {
							t.Fatal("delivery changed opaque evidence")
						}
						p, _ := r.Statement(x)
						if lite := r.observationLite(p); !reflect.DeepEqual(lite.Corroboration, o.Corroboration) {
							t.Fatal("lite evidence differs")
						}
					}
				})
			}
		}
	}
}

func TestOpaqueObservationMixedEvidence(t *testing.T) {
	for _, mode := range []string{"critical", "major", "algorithm"} {
		t.Run(mode, func(t *testing.T) {
			defer noObservationPanic(t)
			w := newWorld(t)
			x := w.observed("X", "observer", "X", "exact-bytes", chainRef(3),
				"finality", obj("rule", "confirmations >= 6", "rule_source", dig("rule"), "state_at_capture", obj("depth", 3)),
				"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "witnessed", "witnesses", []string{w.signer("A")}))
			w.observed("reread", "rereader", "X", "exact-bytes", chainRef(9), "at", "2026-10-17T00:00:00Z")
			w.workflow("workflow", "W", "bytes", "")
			result := w.result("result", "result-key", "verdict", "W", "X", "REF")
			w.corroborates("valid", "supporter", x, result, "supports")
			w.result("derived", "deriver", "OUT", "W", "X")
			before := w.store(nil)
			base, _ := before.Observation(x)
			artifact := before.Artifact(dig("OUT")).Render()
			bad := signOpaqueObservationInput(w, mode, "same", "A", "observed", opaqueObservedBody())
			different := opaqueObservedBody()
			different.Members["content"] = contentOf("Y")
			different.Members["finality"] = depthFinality("confirmations >= 6", 4)
			signOpaqueObservationInput(w, mode, "different", "A", "observed", different)
			doc := opaqueObservedBody()
			doc.Members["content"] = contentOf("rule")
			signOpaqueObservationInput(w, mode, "document", "A", "observed", doc)
			bc := signOpaqueObservationInput(w, mode, "corroboration", "BB", "corroborates",
				obj("of", x, "result", result, "verdict", "contradicts", "model", "opaque model", "cohort", obj("rule", "opaque rule"), "shares", []string{"opaque feed"}))
			var first string
			for _, order := range opaqueDeliveryOrders(w) {
				r := w.store(order)
				o, _ := r.Observation(x)
				if o.Corroboration.Status() != base.Corroboration.Status() || o.ReferentStatus != base.ReferentStatus ||
					!reflect.DeepEqual(o.Finality, base.Finality) || !reflect.DeepEqual(o.Capture, base.Capture) || len(o.Corroboration.Shared) != 0 {
					t.Fatalf("opaque evidence changed status, rule document or witness: %s", o.Render())
				}
				if mode != "major" {
					assertOpaqueEvidence(t, opaqueEvidence(t, o.Corroboration, bc))
					found := false
					for _, line := range o.Others {
						if strings.Contains(line, keylog.Short(bad)) {
							found = true
							if strings.Contains(line, " as exact-bytes") || !strings.Contains(line, "body not interpreted") {
								t.Fatalf("opaque class interpreted: %s", line)
							}
						}
					}
					if !found {
						t.Fatal("associated opaque observation disappeared")
					}
				}
				if got := r.Artifact(dig("OUT")).Render(); got != artifact {
					t.Fatalf("opaque evidence changed derived summary:\n%s\nvs\n%s", got, artifact)
				}
				rep, err := r.Reputation(w.signer("A"), ReputationRule{Name: "test", From: "2026-01-01T00:00:00Z", To: "2027-01-01T00:00:00Z"})
				if err != nil || rep.Denominator != 0 {
					t.Fatalf("opaque capture entered reputation: %+v, %v", rep, err)
				}
				if got := o.Render(); first == "" {
					first = got
				} else if got != first {
					t.Fatal("mixed display depends on delivery")
				}
			}
		})
	}
}

func TestOpaqueObservationUnderstoodIneligible(t *testing.T) {
	for _, state := range []string{"detached", "doubted", "after"} {
		t.Run(state, func(t *testing.T) {
			w := newWorld(t)
			good := w.authored("good", "A", "before")
			x := w.observed("X", "A", "X", "exact-bytes", chainRef(3), "finality", depthFinality("confirmations >= 6", 3))
			w.workflow("workflow", "W", "bytes", "")
			result := w.result("result", "BB", "verdict", "W", "X", "REF")
			c := w.corroborates("corroborates", "BB", x, result, "supports", "shares", []string{"feed"})
			if state != "detached" {
				w.sign("revoke-A", "A", "revoke_key", obj("reason", "key_compromise", "last_good", good))
				w.sign("revoke-B", "BB", "revoke_key", obj("reason", "key_compromise", "last_good", result))
				if state == "after" {
					x = w.observed("late", "A", "X", "exact-bytes", chainRef(3), "finality", depthFinality("confirmations >= 6", 3))
					c = w.corroborates("late-corrob", "BB", x, result, "supports", "shares", []string{"feed"})
				}
			}
			var first string
			for _, order := range opaqueDeliveryOrders(w) {
				if state == "detached" {
					if order == nil {
						for i := range w.lines {
							order = append(order, i)
						}
					}
					order = slices.DeleteFunc(order, func(i int) bool { return i == 0 || i == 3 })
				}
				r := w.store(order)
				for _, id := range []string{x, c} {
					p := assertEligibility(t, r, id, state != "detached", false)
					if !p.St.Verified || p.St.Status != wire.Valid {
						t.Fatal("key eligibility replaced cryptographic validity")
					}
					if state == "doubted" && len(p.Doubted) == 0 || state == "after" && len(p.After) == 0 {
						t.Fatal("missing key-event exclusion")
					}
				}
				o, _ := r.Observation(x)
				if o.Counts || o.Class != "exact-bytes" || len(o.Referent) != 3 || o.Finality == nil || o.Capture.Verified != "self-asserted" {
					t.Fatalf("understood ineligible display lost: %s", o.Render())
				}
				e := opaqueEvidence(t, o.Corroboration, c)
				wantCause := state
				if state == "doubted" {
					wantCause = "last_good"
				}
				if e.Counted || e.Verdict != "supports" || e.Model != "M" || e.Result != result || !slices.Equal(e.Shares, []string{"feed"}) || !strings.Contains(e.Cause, wantCause) {
					t.Fatalf("understood evidence lost: %+v", e)
				}
				hasNot(t, o.Render(), "body not interpreted")
				hasNot(t, o.Render(), "unverified")
				wantStatus(t, o, "unchecked within statements you hold")
				if got := o.Render(); first == "" {
					first = got
				} else if got != first {
					t.Fatal("ineligible display depends on delivery")
				}
			}
		})
	}
}

func TestOpaqueObservationSharedBody(t *testing.T) {
	w := newWorld(t)
	good := w.authored("good", "A", "before")
	body := opaqueObservedBody()
	bad := signCritical(w, "opaque", "A", "observed", body)
	x := w.sign("valid", "BB", "observed", body)
	w.workflow("workflow", "W", "bytes", "")
	result := w.result("result", "C", "verdict", "W", "X", "REF")
	co := obj("of", x, "result", result, "verdict", "supports", "model", "M", "cohort", obj("hand_picked", true))
	badCor := signCritical(w, "opaque-cor", "A", "corroborates", co)
	validCor := w.sign("valid-cor", "C", "corroborates", co)
	w.sign("revoke", "A", "revoke_key", obj("reason", "key_compromise", "last_good", good))
	var first string
	for _, order := range opaqueDeliveryOrders(w) {
		r := w.store(order)
		for _, id := range []string{bad, badCor} {
			p := requireRetained(t, r, id, wire.Unsupported, true, true)
			if len(p.Doubted) == 0 {
				t.Fatal("unsupported input lacks real key-event doubt")
			}
		}
		bo, _ := r.Observation(bad)
		assertOpaqueObservation(t, bo, bad)
		hasNot(t, bo.Render(), "signature unverified")
		o, _ := r.Observation(x)
		if !o.Counts || o.Class != "exact-bytes" || o.Finality == nil || len(o.Referent) != 3 {
			t.Fatal("valid co-body lost its own display")
		}
		wantStatus(t, o, "corroborated 1 within statements you hold")
		assertOpaqueEvidence(t, opaqueEvidence(t, o.Corroboration, badCor))
		if !opaqueEvidence(t, o.Corroboration, validCor).Counted {
			t.Fatal("valid corroboration did not count")
		}
		if got := o.Render(); first == "" {
			first = got
		} else if got != first {
			t.Fatal("same-body display changed with delivery")
		}
	}
}

func TestOpaqueObservationNoAssociation(t *testing.T) {
	for _, of := range []canon.Value{canon.Null{}, canon.Int(1), obj(), canon.Array{}} {
		w := newWorld(t)
		x := w.observed("X", "observer", "X", "none-yet", obj())
		id := signCritical(w, "opaque", "A", "corroborates", obj("of", of, "shares", 1))
		for _, order := range opaqueDeliveryOrders(w) {
			r := w.store(order)
			requireRetained(t, r, id, wire.Unsupported, true, true)
			o, _ := r.Observation(x)
			if len(o.Corroboration.Evidence) != 0 {
				t.Fatal("non-string of became an association")
			}
		}
	}
	for _, major := range []bool{false, true} {
		w := newWorld(t)
		key := w.key("A")
		d := wire.Draft{Kind: "observed", Body: opaqueObservedBody()}
		if major {
			d.RC = "rc/2"
		} else {
			w.keys["A"] = unknownAlgorithmKey{key}
		}
		id := signDraft(w, "unvouched", "A", d)
		w.keys["A"] = key
		r := w.store(nil)
		if _, ok := r.Observation(id); ok {
			t.Fatal("unvouched unverified evidence was placed")
		}
		v := r.logs.Log(w.signer("A")).View()
		if len(v.Retained) != 1 || !bytes.Equal(v.Retained[0].Line(), w.lines[0]) {
			t.Fatal("unvouched bytes were discarded")
		}
	}
}

// Exercise the secondary consumers with an understood target: source comparison,
// method comparability, symmetric contradictions and input-summary computation.
func TestOpaqueObservationRelatedHelpers(t *testing.T) {
	for _, class := range []string{"source", "method"} {
		for _, mode := range []string{"critical", "major", "algorithm"} {
			t.Run(class+"/"+mode, func(t *testing.T) {
				defer noObservationPanic(t)
				w := newWorld(t)
				ref := obj("requests", obj("digest", dig("requests"), "format", "test", "count", 1))
				if class == "method" {
					ref = obj("method_edition", strings.Repeat("e1", 32),
						"environment", obj("image_digest", dig("img"), "platform", "linux/amd64", "harness_commit", strings.Repeat("c", 40)),
						"system", obj("model", "m"), "inputs", []string{dig("input")},
						"window", obj("from", "2026-10-01T00:00:00Z", "to", "2026-10-02T00:00:00Z"))
				}
				x := w.observed("X", "observer", "X", class, ref)
				other := w.observed("Y", "another", "Y", "none-yet", obj())
				w.workflow("workflow", "W", "bytes", "")
				result := w.result("result", "result-key", "verdict", "W", "Y", "X")
				baseline, _ := w.store(nil).Observation(x)
				// Fresh parsed objects, not mutation of a retained statement's validity.
				badRef, err := canon.Parse(canon.Encode(ref))
				if err != nil {
					t.Fatal(err)
				}
				if class == "source" {
					badRef.(*canon.Object).Members["requests"] = canon.Int(1)
				} else {
					badRef.(*canon.Object).Members["system"] = obj("extra", "opaque")
				}
				signOpaqueObservationInput(w, mode, "comparison", "A", "observed",
					obj("content", contentOf("Y"), "class", class, "referent", badRef, "capture", obj("at", "2026-10-17T00:00:00Z", "evidence", "self-asserted")))
				signOpaqueObservationInput(w, mode, "symmetric", "BB", "corroborates",
					obj("of", other, "result", result, "verdict", "contradicts", "shares", canon.Int(1)))
				for _, order := range opaqueDeliveryOrders(w) {
					r := w.store(order)
					o, _ := r.Observation(x)
					if o.Render() != baseline.Render() {
						t.Fatalf("opaque secondary evidence changed the target:\n%s", o.Render())
					}
					p, _ := r.Statement(x)
					if lite := r.observationLite(p); !reflect.DeepEqual(lite.Corroboration, o.Corroboration) || len(lite.Comparability) != 0 {
						t.Fatal("opaque evidence reached lite helper")
					}
				}
			})
		}
	}
}
