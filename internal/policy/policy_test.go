package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/refusal"
)

const (
	dA   = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	dB   = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	sID  = "3333333333333333333333333333333333333333333333333333333333333333"
	idI  = "4444444444444444444444444444444444444444444444444444444444444444"
	kEd  = "ed25519:5555555555555555555555555555555555555555555555555555555555555555"
	kEth = "0x6666666666666666666666666666666666666666"
)

func doc(sel, tr string) string {
	return `{"version":"reader-policy-v1","selections":[` + sel + `],"trust":[` + tr + `]}`
}

// sortedDoc builds a policy whose entries are put in canonical order (for tests that are not about sorting).
func sortedDoc(sels, trs []string) string {
	sortEntries := func(xs []string) string {
		enc := make([]string, len(xs))
		for i, x := range xs {
			v, err := canon.Parse([]byte(x))
			if err != nil {
				panic(err)
			}
			enc[i] = string(canon.Encode(v))
		}
		slices.SortFunc(enc, canon.CompareKeys)
		return strings.Join(enc, ",")
	}
	return doc(sortEntries(sels), sortEntries(trs))
}

func pin(content, role, st string) string {
	return `{"statement":"` + st + `","subject":{"content":"` + content + `","role":"` + role + `"}}`
}

func follow(content, role, principal string) string {
	return `{"principal":` + principal + `,"subject":{"content":"` + content + `","role":"` + role + `"}}`
}

func trustOf(principal, purposes, targets string) string {
	return `{"principal":` + principal + `,"purposes":[` + purposes + `],"targets":` + targets + `}`
}

// TestPolicyVectors runs every `policy` case of the identity profile's vectors file through Parse.
func TestPolicyVectors(t *testing.T) {
	b, err := os.ReadFile("../../docs/fixed-root-identity.vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	suite, err := canon.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, cv := range suite.(*canon.Object).Members["cases"].(canon.Array) {
		c := cv.(*canon.Object)
		if string(c.Members["mode"].(canon.String)) != "policy" {
			continue
		}
		n++
		name := string(c.Members["name"].(canon.String))
		accept := bool(c.Members["accept"].(canon.Bool))
		t.Run(name, func(t *testing.T) {
			var data []byte
			if raw, ok := c.Members["raw"].(canon.String); ok {
				data = []byte(raw)
			} else {
				data = canon.Encode(c.Members["value"])
			}
			p, err := Parse(data)
			if (err == nil) != accept {
				t.Fatalf("accept=%v, got %v", accept, err)
			}
			if err != nil && !errors.Is(err, ErrInvalid) {
				t.Fatalf("not a policy error: %T %v", err, err)
			}
			if p != nil && p.Digest == "" {
				t.Fatal("no digest")
			}
		})
	}
	if n < 7 {
		t.Fatalf("only %d policy vectors found", n)
	}
}

// TestParseRules: one row per rule of note §6 and the schema. Each reject row is a minimal mutation of an
// accepted document, and the expected reason fragment shows the mutation reached that rule and not another.
func TestParseRules(t *testing.T) {
	key := `{"key":"` + kEd + `"}`
	ident := `{"identity":"` + idI + `"}`
	any := `{"any_content":true}`
	okSel := pin(dA, RoleWorkflow, sID)
	okTr := trustOf(key, `"corroboration"`, any)
	big := make([]string, 257)
	for i := range big {
		big[i] = fmt.Sprintf(`"sha256:%064x"`, i)
	}
	sels257 := make([]string, 257)
	for i := range sels257 {
		sels257[i] = pin(fmt.Sprintf("sha256:%064x", i), RoleAuthorship, sID)
	}
	trs256 := make([]string, 256)
	for i := range trs256 {
		trs256[i] = trustOf(key, `"admission"`, `{"contents":["`+fmt.Sprintf("sha256:%064x", i)+`"]}`)
	}
	pad := strings.Repeat(" ", 70000)
	cases := []struct {
		name, in, reason string // reason "" = accept
	}{
		{"minimal", doc("", ""), ""},
		{"both kinds", doc(okSel, okTr), ""},
		{"principal key selection", doc(follow(dA, RoleAuthorship, key), ""), ""},
		{"principal identity selection", doc(follow(dA, RoleAuthorship, ident), ""), ""},
		{"eip191 key", doc("", trustOf(`{"key":"`+kEth+`"}`, `"attestation"`, any)), ""},
		{"all purposes sorted", doc("", trustOf(key, `"admission","attestation","corroboration"`, any)), ""},
		{"explicit contents", doc("", trustOf(key, `"admission"`, `{"contents":["`+dA+`","`+dB+`"]}`)), ""},
		{"non-canonical whitespace and member order accepted", " {\"trust\":[],\n\"selections\":[], \"version\":\"reader-policy-v1\"} ", ""},
		{"two roles same content", doc(pin(dA, RoleAuthorship, sID)+","+pin(dA, RoleWorkflow, sID), ""), ""},
		{"256 trust entries", doc("", strings.Join(trs256, ",")), ""},

		{"not json", `{"version":`, "malformed"},
		{"duplicate member", `{"version":"reader-policy-v1","version":"reader-policy-v1","selections":[],"trust":[]}`, "duplicate"},
		{"BOM", "\xef\xbb\xbf" + doc("", ""), "byte order mark"},
		{"not an object", `[]`, "not an object"},
		{"unknown version", strings.Replace(doc("", ""), "v1", "v2", 1), "unknown policy version"},
		{"missing trust", `{"version":"reader-policy-v1","selections":[]}`, `missing member "trust"`},
		{"missing selections", `{"version":"reader-policy-v1","trust":[]}`, `missing member "selections"`},
		{"unknown top member", `{"version":"reader-policy-v1","selections":[],"trust":[],"x":1}`, `unknown member "x"`},
		{"selections not array", `{"version":"reader-policy-v1","selections":{},"trust":[]}`, "not an array"},
		{"unknown role", doc(pin(dA, "anything", sID), ""), "unknown role"},
		{"unknown purpose", doc("", trustOf(key, `"execution"`, any)), "unknown purpose"},
		{"selector two modes", doc(`{"principal":`+key+`,"statement":"`+sID+`","subject":{"content":"`+dA+`","role":"`+RoleWorkflow+`"}}`, ""), "exactly one of statement or principal"},
		{"selector no mode", doc(`{"subject":{"content":"`+dA+`","role":"`+RoleWorkflow+`"}}`, ""), "exactly one of statement or principal"},
		{"unknown selection member", doc(`{"statement":"`+sID+`","subject":{"content":"`+dA+`","role":"`+RoleWorkflow+`"},"z":1}`, ""), `unknown member "z"`},
		{"unknown subject member", doc(`{"statement":"`+sID+`","subject":{"content":"`+dA+`","role":"`+RoleWorkflow+`","z":1}}`, ""), `unknown member "z"`},
		{"bad statement id", doc(pin(dA, RoleWorkflow, strings.Repeat("A", 64)), ""), "not a statement id"},
		{"short statement id", doc(pin(dA, RoleWorkflow, sID[:63]), ""), "not a statement id"},
		{"bad content digest", doc(pin("sha256:abc", RoleWorkflow, sID), ""), "not a content digest"},
		{"bad key", doc(follow(dA, RoleWorkflow, `{"key":"ed25519:00"}`), ""), "not a signing key"},
		{"bad identity", doc(follow(dA, RoleWorkflow, `{"identity":"xyz"}`), ""), "not a identity id"},
		{"principal both", doc(follow(dA, RoleWorkflow, `{"identity":"`+idI+`","key":"`+kEd+`"}`), ""), "exactly one of key or identity"},
		{"principal empty", doc(follow(dA, RoleWorkflow, `{}`), ""), "exactly one of key or identity"},
		{"principal unknown member", doc(follow(dA, RoleWorkflow, `{"group":"g"}`), ""), `unknown member "group"`},
		{"conflicting subject (different statements)", doc(pin(dA, RoleWorkflow, sID)+","+pin(dA, RoleWorkflow, idI), ""), "a second selection"},
		{"conflicting subject (pin and principal)", doc(follow(dA, RoleWorkflow, key)+","+pin(dA, RoleWorkflow, sID), ""), "a second selection"},
		{"identical selections", doc(okSel+","+okSel, ""), "identical to the previous entry"},
		{"identical trust entries", doc("", okTr+","+okTr), "identical to the previous entry"},
		{"unsorted selections", doc(pin(dB, RoleWorkflow, sID)+","+pin(dA, RoleWorkflow, sID), ""), "not sorted"},
		{"unsorted trust", doc("", trustOf(key, `"corroboration"`, any)+","+trustOf(key, `"attestation"`, any)), "not sorted"},
		{"unsorted purposes", doc("", trustOf(key, `"corroboration","admission"`, any)), "not sorted"},
		{"repeated purpose", doc("", trustOf(key, `"admission","admission"`, any)), "not sorted or repeats"},
		{"empty purposes", doc("", trustOf(key, ``, any)), "not a nonempty array"},
		{"four purposes", doc("", trustOf(key, `"admission","attestation","corroboration","corroboration"`, any)), "at most 3"},
		{"unsorted contents", doc("", trustOf(key, `"admission"`, `{"contents":["`+dB+`","`+dA+`"]}`)), "not sorted"},
		{"empty contents", doc("", trustOf(key, `"admission"`, `{"contents":[]}`)), "not a nonempty array"},
		{"257 contents", doc("", trustOf(key, `"admission"`, `{"contents":[`+strings.Join(big, ",")+`]}`)), "at most 256"},
		{"no target", doc("", `{"principal":`+key+`,"purposes":["corroboration"]}`), `missing member "targets"`},
		{"any_content false", doc("", trustOf(key, `"admission"`, `{"any_content":false}`)), "must be true"},
		{"both targets", doc("", trustOf(key, `"admission"`, `{"any_content":true,"contents":["`+dA+`"]}`)), "exactly one of any_content or contents"},
		{"257 selections", doc(strings.Join(sels257, ","), ""), "257 entries"},
		{"canonical size limit", doc("", strings.Join(append(trs256[:0:0], func() []string {
			out := make([]string, 256)
			for i := range out {
				cs := make([]string, 3)
				for j := range cs {
					cs[j] = fmt.Sprintf(`"sha256:%064x"`, 3*i+j)
				}
				out[i] = trustOf(key, `"admission","attestation","corroboration"`, `{"contents":[`+strings.Join(cs, ",")+`]}`)
			}
			return out
		}()...), ",")), "canonical size limit"},
		{"whitespace does not count toward the canonical limit", doc(pad[:100]+okSel, ""), ""},
		{"input size limit", pad + pad + pad + pad + pad + pad + doc("", ""), "input size limit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse([]byte(c.in))
			if c.reason == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("accepted %+v", p)
			}
			var pe *Error
			if !errors.As(err, &pe) || !errors.Is(err, ErrInvalid) || pe.ExitCode() != 2 {
				t.Fatalf("not a policy error with exit 2: %T %v", err, err)
			}
			if !strings.Contains(err.Error(), c.reason) {
				t.Fatalf("reason %q not in %q", c.reason, err)
			}
		})
	}
}

// TestDigest: sha256 of the JCS bytes; whitespace and member order do not change it; any entry does.
func TestDigest(t *testing.T) {
	a, err := Parse([]byte(doc(pin(dA, RoleWorkflow, sID), "")))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(a.Canonical)
	if a.Digest != "sha256:"+hex.EncodeToString(sum[:]) {
		t.Fatal("digest is not sha256(JCS)")
	}
	if string(a.Canonical) != `{"selections":[`+pin(dA, RoleWorkflow, sID)+`],"trust":[],"version":"reader-policy-v1"}` {
		t.Fatalf("canonical form %s", a.Canonical)
	}
	b, _ := Parse([]byte(" {\"trust\" : [],\"selections\":[{\"subject\":{\"role\":\"workflow-declaration\",\"content\":\"" + dA + "\"},\"statement\":\"" + sID + "\"}],\"version\":\"reader-policy-v1\"}\n"))
	if b.Digest != a.Digest {
		t.Fatal("encoding changed the digest")
	}
	c, _ := Parse([]byte(doc(pin(dA, RoleAuthorship, sID), "")))
	if c.Digest == a.Digest {
		t.Fatal("a different role kept the digest")
	}
	if d := Diff(a, c); len(d) != 3 || !strings.HasPrefix(d[1], "- selection ") || !strings.HasPrefix(d[2], "+ selection ") {
		t.Fatalf("diff %q", d)
	}
	if Diff(a, b) != nil {
		t.Fatal("equal policies differ")
	}
	if d := Diff(nil, a); len(d) != 2 || !strings.Contains(d[0], "(none) -> "+a.Digest) {
		t.Fatalf("diff from none %q", d)
	}
}

// TestTrusts: purpose-scoped, target-scoped, additive; identity entries answer unknown; no policy answers
// unconfigured, as does a policy naming no principal for the purpose; once a purpose is named, no matching entry
// answers not trusted (never universal trust).
func TestTrusts(t *testing.T) {
	var none *Policy
	if a := none.Trusts(kEd, PurposeCorroboration, dA); a.State != Unconfigured || a.Trusted() {
		t.Fatalf("nil policy: %+v", a)
	}
	// trust is configured per purpose: a policy naming nobody for a purpose leaves it unconfigured
	empty, _ := Parse([]byte(doc("", "")))
	if a := empty.Trusts(kEd, PurposeCorroboration, dA); a.State != Unconfigured || a.Policy != "" || empty.Configures(PurposeCorroboration) {
		t.Fatalf("empty policy: %+v", a)
	}
	admOnly, _ := Parse([]byte(doc("", trustOf(`{"key":"`+kEth+`"}`, `"admission"`, `{"any_content":true}`))))
	if a := admOnly.Trusts(kEd, PurposeCorroboration, dA); a.State != Unconfigured || !admOnly.Configures(PurposeAdmission) {
		t.Fatalf("admission-only policy, corroboration: %+v", a)
	}
	if a := admOnly.Trusts(kEd, PurposeAdmission, dA); a.State != NotTrusted || a.Policy != admOnly.Digest {
		t.Fatalf("admission-only policy, admission: %+v", a)
	}
	p, err := Parse([]byte(sortedDoc(nil, []string{
		trustOf(`{"identity":"`+idI+`"}`, `"attestation"`, `{"any_content":true}`),
		trustOf(`{"key":"`+kEd+`"}`, `"admission","corroboration"`, `{"contents":["`+dA+`"]}`),
		trustOf(`{"key":"`+kEth+`"}`, `"corroboration"`, `{"any_content":true}`)})))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		key, purpose, content string
		want                  TrustState
	}{
		{kEd, PurposeCorroboration, dA, Trusted},
		{kEd, PurposeAdmission, dA, Trusted},
		{kEd, PurposeCorroboration, dB, NotTrusted}, // target is the content judged
		{kEd, PurposeCorroboration, "", NotTrusted}, // explicit contents never cover "no content"
		{kEd, PurposeAttestation, dA, Unknown},      // only the identity entry names attestation
		{kEth, PurposeCorroboration, dB, Trusted},   // any_content
		{kEth, PurposeCorroboration, "", Trusted},   // any_content covers no content
		{kEth, PurposeAdmission, dB, NotTrusted},    // a purpose matches only itself
		{"ed25519:" + strings.Repeat("7", 64), PurposeCorroboration, dA, NotTrusted},
	} {
		if a := p.Trusts(c.key, c.purpose, c.content); a.State != c.want {
			t.Errorf("%s %s %s: %s, want %s", c.key[:10], c.purpose, c.content, a.State, c.want)
		} else if c.want == Trusted && !strings.Contains(a.String(), p.Digest[:19]) {
			t.Errorf("answer does not cite the policy: %s", a)
		}
	}
}

// TestAdmit: C-core-111's predicate. A trust floor excluding Z: refused with class reader policy, reason trust
// floor, scope Z's objects; or admitted and labelled. No policy, or one naming nobody for admission, admits
// everything unlabelled.
func TestAdmit(t *testing.T) {
	conformance.Partial(t, "C-core-111", "the reader-policy predicate (Policy.Admit: refused, or admitted and labelled, class reader policy: trust floor, scoped to Z's objects); applying it at pull and the other gates needs the gate code")
	conformance.Partial(t, "C-core-133a", "(c) only: an unparseable or invalid policy is a *policy.Error with ExitCode 2 before any evaluation; (a), (b), (d), (e) and the root snapshot need the CLI")
	const z = "0x7777777777777777777777777777777777777777"
	var none *Policy
	if a := none.Admit(z, dA, FloorRefuse); !a.Admitted || a.Label != "" || a.Refusal != nil {
		t.Fatalf("no policy: %+v", a)
	}
	p, _ := Parse([]byte(doc("", trustOf(`{"key":"`+kEd+`"}`, `"admission"`, `{"any_content":true}`))))
	if a := p.Admit(kEd, dA, FloorRefuse); !a.Admitted || a.Label != "" {
		t.Fatalf("trusted key: %+v", a)
	}
	a := p.Admit(z, dA, FloorRefuse)
	if a.Admitted || a.Refusal == nil || a.Refusal.Class != refusal.Policy || a.Refusal.Reason != TrustFloorReason ||
		!strings.Contains(a.Refusal.Detail, "objects signed by "+z) {
		t.Fatalf("refusal: %+v %v", a, a.Refusal)
	}
	if got := a.Refusal.Error(); !strings.HasPrefix(got, "reader policy: trust floor") {
		t.Fatalf("rendered %q", got)
	}
	l := p.Admit(z, dA, FloorLabel)
	if !l.Admitted || l.Refusal != nil || !strings.Contains(l.Label, "below the reader's trust floor") {
		t.Fatalf("label: %+v", l)
	}
	// corroboration trust is not admission trust: under a policy naming another key for admission it does not
	// admit; under a policy naming nobody for admission the floor is not configured and admits unlabelled
	q, _ := Parse([]byte(sortedDoc(nil, []string{
		trustOf(`{"key":"`+kEd+`"}`, `"admission"`, `{"any_content":true}`),
		trustOf(`{"key":"`+z+`"}`, `"corroboration"`, `{"any_content":true}`)})))
	if q.Admit(z, dA, FloorRefuse).Admitted {
		t.Fatal("corroboration trust admitted")
	}
	c, _ := Parse([]byte(doc("", trustOf(`{"key":"`+z+`"}`, `"corroboration"`, `{"any_content":true}`))))
	if a := c.Admit(z, dA, FloorRefuse); !a.Admitted || a.Label != "" || a.Answer.State != Unconfigured {
		t.Fatalf("no admission entry: %+v", a)
	}
}

// TestSelect: lookup by (content, role) only.
func TestSelect(t *testing.T) {
	p, err := Parse([]byte(sortedDoc([]string{pin(dA, RoleAuthorship, sID), follow(dA, RoleWorkflow, `{"key":"`+kEd+`"}`)}, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := p.Select(dA, RoleWorkflow); !ok || s.Principal == nil || s.Principal.Key != kEd {
		t.Fatalf("workflow selection %+v", s)
	}
	if s, ok := p.Select(dA, RoleAuthorship); !ok || s.Statement != sID {
		t.Fatalf("authorship selection %+v", s)
	}
	if _, ok := p.Select(dB, RoleAuthorship); ok {
		t.Fatal("selected another content")
	}
	if _, ok := (*Policy)(nil).Select(dA, RoleAuthorship); ok {
		t.Fatal("nil policy selected")
	}
}
