package identity_test

// Regressions from the independent review of 1ed2168 (three reviewers from different model families). Each test
// names the finding it pins. Every line is signed and admitted through identity.Admit.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"filippo.io/edwards25519"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/wire"
)

// F1 (high): a valid rc/1 root revoke_key/rotate_key whose prev lineage reaches I is terminal whatever defects its
// ancestry or merges carry (profile §3 "irrespective of … branch"; user decision 2026-10-22: root_retired).
func TestReviewTerminalRootEventIgnoresAncestryDefects(t *testing.T) {
	terminal := func(w *world, kind, parent string, merges ...string) {
		body := obj("reason", "key_compromise", "last_good", w.ids["G2"])
		if kind == "rotate_key" {
			body = obj("successor", w.signer("S"))
		}
		w.sign(stmt{name: "Rterm", by: "R", rc: "rc/1", parent: parent, merges: merges, kind: kind, body: body})
	}
	cases := []struct {
		name  string
		build func(w *world, kind string)
	}{
		{"descends from an invalid self-grant", func(w *world, kind string) {
			b := w.grantBody("K1", authoredAny())
			b.Members["delegate"] = obj("key", w.signer("R"), "inception", w.ids["I"])
			w.sign(stmt{name: "Xbad", by: "R", parent: "G2", kind: "identity_grant", body: b})
			terminal(w, kind, "Xbad")
		}},
		{"descends from a malformed cut of another grant", func(w *world, kind string) {
			b := cutBody(w, "G2", "")
			b.Members["reason"] = canon.String("Not A Token")
			w.sign(stmt{name: "Xbad", by: "R", parent: "G2", kind: "identity_cut", body: b})
			terminal(w, kind, "Xbad")
		}},
		{"merges a rival inception", func(w *world, kind string) {
			w.sign(stmt{name: "Irival", by: "R", kind: "identity_inception", body: obj("profile", "fixed-root-v1", "n", 2)})
			terminal(w, kind, "G2", "Irival")
		}},
		{"merges a rival seq-0 line", func(w *world, kind string) {
			w.sign(stmt{name: "X0", by: "R", rc: "rc/1", kind: "authored", body: authoredBody(15)})
			terminal(w, kind, "G2", "X0")
		}},
		{"merges another key's line", func(w *world, kind string) {
			terminal(w, kind, "G2", "K1.0")
		}},
		{"merges a higher-seq own line", func(w *world, kind string) {
			about := obj("about", obj("statement", w.ids["I"]), "note", "a")
			w.sign(stmt{name: "Rd", by: "R", rc: "rc/1", parent: "G2", kind: "describes", body: about})
			w.sign(stmt{name: "Rd2", by: "R", rc: "rc/1", parent: "Rd", kind: "describes", body: withField(about, "note", canon.String("b"))})
			terminal(w, kind, "G2", "Rd2")
		}},
	}
	for _, tc := range cases {
		for _, kind := range []string{"revoke_key", "rotate_key"} {
			t.Run(tc.name+"/"+kind, func(t *testing.T) {
				w := base(t)
				tc.build(w, kind)
				s := w.admit()
				if st, v := s.Status(w.ids["Rterm"]); st != wire.Valid || !v {
					t.Fatalf("precondition: terminal event read %s/%v", st, v)
				}
				for _, n := range []string{"A1", "B1"} {
					w.expect(s, n, identitymodel.Denied, "root_retired")
				}
			})
		}
	}
}

// F1 attack shape: a thief with the root key forks R's log (a grant to itself, then one invalid line); the owner's
// fork-clearing key_compromise revoke merges every tip. The thief's grant must die with the root.
func TestReviewCompromisedRootGrantDiesWithRevoke(t *testing.T) {
	for _, viaMerge := range []bool{true, false} {
		t.Run(fmt.Sprintf("merge=%v", viaMerge), func(t *testing.T) {
			w := base(t)
			w.sign(stmt{name: "S.0", by: "S", rc: "rc/1", kind: "authored", body: authoredBody(6)})
			w.sign(stmt{name: "Gevil", by: "R", parent: "G2", kind: "identity_grant", body: w.grantBody("S", authoredAny())})
			bad := w.grantBody("S", authoredAny())
			bad.Members["permissions"] = canon.Array{}
			if viaMerge {
				w.sign(stmt{name: "Xbad", by: "R", parent: "Gevil", kind: "identity_grant", body: bad})
				w.sign(stmt{name: "Head", by: "R", rc: "rc/1", parent: "G2", kind: "describes", body: obj("about", obj("statement", w.ids["I"]), "note", "head")})
				w.sign(stmt{name: "Rrev", by: "R", rc: "rc/1", parent: "Head", merges: []string{"Xbad"}, kind: "revoke_key", body: obj("reason", "key_compromise", "last_good", w.ids["G2"])})
			} else {
				w.sign(stmt{name: "Xbad", by: "R", parent: "G2", kind: "identity_grant", body: bad})
				w.sign(stmt{name: "Rrev", by: "R", rc: "rc/1", parent: "Xbad", kind: "revoke_key", body: obj("reason", "key_compromise", "last_good", w.ids["G2"])})
			}
			w.sign(stmt{name: "Sact", by: "S", parent: "S.0", kind: "authored", body: authoredBody(7), actor: [2]string{"I", "Gevil"}})
			s := w.admit()
			for _, n := range []string{"Sact", "A1", "B1"} {
				w.expect(s, n, identitymodel.Denied, "root_retired")
			}
		})
	}
}

// F2 (Kimi): vocabulary before ancestry. A root line outside the closed vocabulary is unknown with or without a
// defective merge; the defect must not turn uncertainty into a warning.
func TestReviewUnsupportedRootEventSurvivesBadMerge(t *testing.T) {
	for _, merge := range []bool{false, true} {
		w := base(t)
		var merges []string
		if merge {
			w.sign(stmt{name: "X0", by: "R", rc: "rc/1", kind: "authored", body: authoredBody(15)})
			merges = []string{"X0"}
		}
		w.sign(stmt{name: "RD", by: "R", rc: "rc/1", parent: "G2", merges: merges, kind: "authored", body: authoredBody(1)})
		r := w.admit().Evaluate(w.ids["A1"])
		if r.Status == identitymodel.Eligible || !hasReason(r, "unsupported_root_event") {
			t.Fatalf("merge=%v: %s %+v", merge, r.Status, r.Reasons)
		}
		// With the bad merge the ancestry proof's own denial is recorded too (fail closed; only R can do this).
		if merge && !hasReason(r, "wrong_lineage") {
			t.Fatalf("ancestry defect not reported: %+v", r.Reasons)
		}
	}
}

// A malformed root key event (the event itself, clean ancestry) stays unknown, never ineffective (contract §3).
func TestReviewMalformedRootKeyEventIsUnknown(t *testing.T) {
	w := base(t)
	w.sign(stmt{name: "Rbad", by: "R", rc: "rc/1", parent: "G2", kind: "revoke_key", body: obj("reason", "Bad Reason")})
	w.expect(w.admit(), "A1", identitymodel.Unknown, "unsupported_root_event")
}

// O-F2: a root cut that names G1 under another identity is an invalid cut addressed to G1 (denies G1, recorded as
// a relevant cut), never silently "a cut for another grant". Other grants are unaffected.
func TestReviewCutWithWrongIdentityDeniesItsGrant(t *testing.T) {
	for _, other := range []string{"rival inception", "nonexistent id"} {
		t.Run(other, func(t *testing.T) {
			w := base(t)
			b := cutBody(w, "G1", "")
			if other == "rival inception" {
				w.sign(stmt{name: "J", by: "R", kind: "identity_inception", body: obj("profile", "fixed-root-v1", "n", 2)})
				b.Members["identity"] = canon.String(w.ids["J"])
			} else {
				b.Members["identity"] = canon.String(strings.Repeat("ab", 32))
			}
			w.sign(stmt{name: "Cj", by: "R", parent: "G2", kind: "identity_cut", body: b})
			s := w.admit()
			r := w.expect(s, "A1", identitymodel.Denied, "wrong_cut_identity")
			if len(r.RelevantCuts) != 1 || string(r.RelevantCuts[0]) != w.ids["Cj"] {
				t.Fatalf("relevant cuts %v", r.RelevantCuts)
			}
			w.expect(s, "B1", identitymodel.Eligible, "")
		})
	}
}

// O-F3 + K-F3 (user decision 2026-10-22: fixed-root-v1 permissions are leaf operations, so an unknown kind affects
// only its grant): sibling grants stay eligible with a warning; acts under the unsupported grant read unknown,
// never a definite scope denial built from the entries this reader happened to parse.
func TestReviewUnsupportedGrantAffectsOnlyItself(t *testing.T) {
	for _, perms := range [][]canon.Value{
		{obj("kind", "zz_future")},
		{authoredAny(), obj("kind", "zz_future")},
	} {
		w := base(t)
		w.sign(stmt{name: "G9", by: "R", parent: "G2", kind: "identity_grant", body: w.grantBody("K2", perms...)})
		w.sign(stmt{name: "B9", by: "K2", parent: "B2", kind: "authored", body: authoredBody(6), actor: [2]string{"I", "G9"}})
		w.sign(stmt{name: "H9", by: "K2", parent: "B9", kind: "holds", body: obj("content", obj("digest", digest(2), "size", 10)), actor: [2]string{"I", "G9"}})
		s := w.admit()
		for _, n := range []string{"A1", "B1"} {
			r := w.expect(s, n, identitymodel.Eligible, "")
			if !hasWarning(r, "unsupported_sibling_grant") {
				t.Fatalf("%s: sibling warning missing: %+v", n, r.Warnings)
			}
		}
		for _, n := range []string{"B9", "H9"} {
			r := w.expect(s, n, identitymodel.Unknown, "unsupported_evidence")
			for _, x := range r.Reasons {
				if x.Status == identitymodel.Denied {
					t.Fatalf("%s: definite denial %s under an unsupported grant", n, x.Code)
				}
			}
		}
	}
}

// G-F2 / O-F4: facts are a function of canonical bytes. The same signed grant delivered with its target members
// in the other order (same id, same canonical line) gives the same digest and result in either delivery order.
func TestReviewTranslationIgnoresMemberOrder(t *testing.T) {
	w := base(t)
	perm := obj("kind", "authored", "targets", obj("any_content", true, "contents", []string{digest(1)}), "amend", false)
	w.sign(stmt{name: "G9", by: "R", parent: "G2", kind: "identity_grant", body: w.grantBody("K1", perm)})
	w.sign(stmt{name: "A9", by: "K1", parent: "A2", kind: "authored", body: authoredBody(1), actor: [2]string{"I", "G9"}})
	orig := string(w.lines["G9"])
	a, b := `"any_content":true,"contents":["`+digest(1)+`"]`, `"contents":["`+digest(1)+`"],"any_content":true`
	if !strings.Contains(orig, a) {
		t.Fatalf("precondition: %s", orig)
	}
	swapped := strings.Replace(orig, a, b, 1)
	rest := w.all("G9")
	var snaps []*identity.Snapshot
	for _, first := range [][]string{{orig, swapped}, {swapped, orig}, {swapped}} {
		var lines [][]byte
		for _, l := range first {
			lines = append(lines, []byte(l))
		}
		s, err := identity.Admit(append(lines, rest...))
		if err != nil || len(s.Refused()) != 0 {
			t.Fatalf("admit: %v %v", err, s.Refused())
		}
		snaps = append(snaps, s)
	}
	for i := 1; i < len(snaps); i++ {
		if snaps[i].Receipt() != snaps[0].Receipt() || snaps[i].EvidenceDigest() != snaps[0].EvidenceDigest() ||
			!reflect.DeepEqual(snaps[i].Evaluate(w.ids["A9"]), snaps[0].Evaluate(w.ids["A9"])) {
			t.Fatalf("delivery %d differs from delivery 0", i)
		}
	}
	w.expect(snaps[0], "A9", identitymodel.Denied, "invalid_evidence")
}

// G-F1 / O-F7: the profile caps rc/2 merges at 256 (real connected forks, not missing ids).
func TestReviewCandidateMergesCap(t *testing.T) {
	for _, n := range []int{256, 257} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			w := base(t)
			merges := make([]string, n)
			for i := range merges {
				merges[i] = fmt.Sprintf("fork-%03d", i)
				w.sign(stmt{name: merges[i], by: "K1", rc: "rc/1", parent: "K1.0", kind: "authored",
					body: withField(authoredBody(1), "nonce", canon.Int(i))})
			}
			w.sign(stmt{name: "M", by: "K1", parent: "A2", kind: "authored", body: authoredBody(1), actor: [2]string{"I", "G1"}, merges: merges})
			s := w.admit()
			st, v := s.Status(w.ids["M"])
			if n == 256 {
				if st != wire.Valid || !v {
					t.Fatalf("256 merges read %s/%v", st, v)
				}
				w.expect(s, "M", identitymodel.Eligible, "")
				return
			}
			if st != wire.Invalid || !v {
				t.Fatalf("257 merges read %s/%v", st, v)
			}
			w.expect(s, "M", identitymodel.Denied, "invalid_actor_binding")
		})
	}
}

// G-F3 / O-F9: a bad, missing or mistyped ts does not erase what the authenticated body and actor say.
func TestReviewBadTimeKeepsBindings(t *testing.T) {
	for _, ts := range []canon.Value{canon.String("not-a-time"), canon.Int(5), nil} {
		t.Run(fmt.Sprint(ts), func(t *testing.T) {
			w := base(t)
			resign(w, "Cbad", stmt{name: "Cbad", by: "R", parent: "G2", kind: "identity_cut", body: cutBody(w, "G1", "A1")}, ts)
			resign(w, "A3", stmt{name: "A3", by: "K1", parent: "A2", kind: "authored", body: authoredBody(1), actor: [2]string{"I", "G1"}}, ts)
			s := w.admit()
			for _, n := range []string{"Cbad", "A3"} {
				if st, v := s.Status(w.ids[n]); st != wire.Invalid || !v {
					t.Fatalf("%s read %s/%v", n, st, v)
				}
			}
			w.expect(s, "A1x", identitymodel.Denied, "invalid_evidence") // the invalid cut addressed to G1 denies G1
			w.expect(s, "B1", identitymodel.Eligible, "")                // and only G1
			r := w.expect(s, "A3", identitymodel.Denied, "invalid_actor_binding")
			if r.Actor.Kind != identitymodel.IdentitySubject {
				t.Fatalf("A3 reported as %v, not an identity context", r.Actor.Kind)
			}
		})
	}
}

// resign signs s with its envelope ts replaced (nil removes it).
func resign(w *world, name string, s stmt, ts canon.Value) {
	w.t.Helper()
	w.sign(s)
	v, err := canon.Parse(w.lines[name])
	if err != nil {
		w.t.Fatal(err)
	}
	full := v.(*canon.Object)
	env := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range full.Keys {
		if k != "sig" && k != "ts" {
			env.Keys = append(env.Keys, k)
			env.Members[k] = full.Members[k]
		}
	}
	if ts != nil {
		env = withField(env, "ts", ts)
	}
	rc, _ := env.Get("rc")
	major := 1
	if rc == canon.String("rc/2") {
		major = 2
	}
	ss := wire.PAE(wire.PayloadType(s.kind, major), canon.Encode(env))
	w.ids[name] = wire.ID(ss)
	w.lines[name] = canon.Encode(withField(env, "sig", canon.String(w.keys[s.by].Sign(ss))))
}

// O-F6: a third party resending an unverified line with other sig bytes does not move the receipt.
func TestReviewReceiptIgnoresUnverifiedSig(t *testing.T) {
	w := base(t)
	w.sign(stmt{name: "R3", by: "R", rc: "rc/3", parent: "G2", kind: "identity_cut", body: obj("future", true)})
	ref := w.admit()
	l := string(w.lines["R3"])
	i := strings.Index(l, `"sig":"`)
	j := strings.Index(l[i+7:], `"`)
	forged := l[:i+7] + l[i+7+j:]
	s, err := identity.Admit(append(w.all(), []byte(forged)))
	if err != nil {
		t.Fatal(err)
	}
	if s.Receipt() != ref.Receipt() || s.EvidenceDigest() != ref.EvidenceDigest() {
		t.Fatal("a resent unverified line with sig \"\" changed the receipt")
	}
}

// O-F11 guard: vouching is same-signer only. A verified K1 line naming an unverified line that claims signer R does
// not authenticate it (deleting the signer check in vouch must fail this test).
func TestReviewCrossKeyVouchRejected(t *testing.T) {
	w := base(t)
	w.sign(stmt{name: "R3", by: "R", rc: "rc/3", parent: "G2", kind: "identity_cut", body: obj("future", true)})
	w.sign(stmt{name: "Kv", by: "K1", rc: "rc/1", parent: "A2", merges: []string{"R3"}, kind: "describes",
		body: obj("about", obj("statement", w.ids["I"]), "note", "x")})
	w.expect(w.admit(), "A1", identitymodel.Eligible, "")
	// Control: the same bytes vouched by R make every grant of I unknown.
	w.sign(stmt{name: "Rv", by: "R", rc: "rc/1", parent: "R3", kind: "describes", body: obj("about", obj("statement", w.ids["I"]), "note", "y")})
	w.expect(w.admit(), "A1", identitymodel.Unknown, "unsupported_root_event")
}

// O-F11 guard: two different valid Ed25519 signatures over one id give a delivery-order-independent receipt
// (keeping the first-delivered copy instead of the smallest canonical line must fail this test).
func TestReviewTwoValidSignaturesReceiptOrderIndependent(t *testing.T) {
	w := base(t)
	orig := string(w.lines["A1"])
	st, err := wire.NewIdentityReader().Read([]byte(orig))
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("research-commons go test identity slice key worker-1"))
	alt := altSign(seed[:], st.SignedString)
	pub, _ := hex.DecodeString(strings.TrimPrefix(st.Signer, "ed25519:"))
	if !ed25519.Verify(pub, st.SignedString, alt) || hex.EncodeToString(alt) == st.Sig {
		t.Fatal("precondition: a second valid signature")
	}
	other := strings.Replace(orig, st.Sig, hex.EncodeToString(alt), 1)
	rest := w.all("A1")
	s1, err1 := identity.Admit(append([][]byte{[]byte(orig), []byte(other)}, rest...))
	s2, err2 := identity.Admit(append([][]byte{[]byte(other), []byte(orig)}, rest...))
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if s1.Receipt() != s2.Receipt() || s1.EvidenceDigest() != s2.EvidenceDigest() {
		t.Fatal("receipt depends on which valid signature arrived first")
	}
}

// altSign makes a second valid Ed25519 signature with a non-RFC 8032 nonce.
func altSign(seed, msg []byte) []byte {
	h := sha512.Sum512(seed)
	s, _ := edwards25519.NewScalar().SetBytesWithClamping(h[:32])
	A := new(edwards25519.Point).ScalarBaseMult(s)
	rb := sha512.Sum512(append([]byte("alt nonce"), msg...))
	r, _ := edwards25519.NewScalar().SetUniformBytes(rb[:])
	R := new(edwards25519.Point).ScalarBaseMult(r)
	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(A.Bytes())
	kh.Write(msg)
	k, _ := edwards25519.NewScalar().SetUniformBytes(kh.Sum(nil))
	S := edwards25519.NewScalar().MultiplyAdd(k, s, r)
	return append(R.Bytes(), S.Bytes()...)
}

// O-F5: a delegate's own raw key events are examined up to a bound; past it one warning, never a status change.
func TestReviewDelegateSelfEventsBounded(t *testing.T) {
	w := base(t)
	for i := 0; i <= identitymodel.MaxDelegateSelfEvents; i++ {
		w.sign(stmt{name: "V" + strconv.Itoa(i), by: "K1", rc: "rc/1", parent: "A2", kind: "revoke_key",
			body: obj("reason", "superseded", "note", strconv.Itoa(i))})
	}
	r := w.expect(w.admit(), "A1", identitymodel.Eligible, "")
	if !hasWarning(r, "delegate_self_event_limit") {
		t.Fatalf("no limit warning: %d warnings", len(r.Warnings))
	}
}

func hasWarning(r identitymodel.Result, code string) bool {
	for _, x := range r.Warnings {
		if x.Code == code {
			return true
		}
	}
	return false
}

// all returns every signed line in signing order except the named ones.
func (w *world) all(except ...string) [][]byte {
	var out [][]byte
	for _, n := range without(w.order, except...) {
		out = append(out, w.lines[n])
	}
	return out
}

// Re-review N1 (GPT): a cut is addressed by its grant alone. A readable grant with a missing, mistyped or malformed
// identity denies that grant and leaves sibling grants alone; an unreadable grant stays unknown for every grant.
func TestReviewCutAddressIsTheGrant(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		value canon.Value // nil removes the field
	}{
		{"identity missing", "identity", nil},
		{"identity integer", "identity", canon.Int(5)},
		{"identity malformed", "identity", canon.String("not-an-id")},
		{"identity wrong id", "identity", canon.String(strings.Repeat("ab", 32))},
		{"grant missing", "grant", nil},
		{"grant integer", "grant", canon.Int(5)},
		{"grant malformed", "grant", canon.String("not-an-id")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := base(t)
			b := cutBody(w, "G1", "")
			if tc.value == nil {
				delete(b.Members, tc.field)
				b.Keys = without(b.Keys, tc.field)
			} else {
				b.Members[tc.field] = tc.value
			}
			w.sign(stmt{name: "C", by: "R", parent: "G2", kind: "identity_cut", body: b})
			s := w.admit()
			if tc.field == "grant" {
				w.expect(s, "A1", identitymodel.Unknown, "unsupported_root_event")
				w.expect(s, "B1", identitymodel.Unknown, "unsupported_root_event")
				return
			}
			w.expect(s, "A1", identitymodel.Denied, "wrong_cut_identity")
			w.expect(s, "B1", identitymodel.Eligible, "")
		})
	}
}
