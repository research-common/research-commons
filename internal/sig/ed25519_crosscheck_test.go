package sig_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/sig"
)

// The second Ed25519 implementation of C-core-144's "two implementations built on different Ed25519
// libraries". It uses nothing but the standard library: math/big for the curve arithmetic of steps 1–3 of the
// pinned rule (wire-format note §4), written here from RFC 8032 §5.1 and the note's text, and crypto/ed25519
// for step 4. It shares no code with internal/sig (which uses filippo.io/edwards25519 for the same steps), so
// a disagreement between the two is a real finding about one of them.

var (
	refP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	refL = func() *big.Int {
		l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
		return l
	}()
	refD = func() *big.Int { return mod(new(big.Int).Mul(big.NewInt(-121665), inv(big.NewInt(121666)))) }()
	refI = func() *big.Int {
		return new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(refP, big.NewInt(1)), 2), refP)
	}() // sqrt(-1)
	refId = point{big.NewInt(0), big.NewInt(1)}
)

type point struct{ x, y *big.Int }

func mod(a *big.Int) *big.Int { return new(big.Int).Mod(a, refP) }
func inv(a *big.Int) *big.Int { return new(big.Int).ModInverse(mod(a), refP) }

// add is the complete twisted Edwards addition law for a = -1 (RFC 8032 §5.1.4, affine form).
func add(p, q point) point {
	t := mod(new(big.Int).Mul(refD, mod(new(big.Int).Mul(mod(new(big.Int).Mul(p.x, q.x)), mod(new(big.Int).Mul(p.y, q.y))))))
	x1 := mod(new(big.Int).Add(mod(new(big.Int).Mul(p.x, q.y)), mod(new(big.Int).Mul(q.x, p.y))))
	y1 := mod(new(big.Int).Add(mod(new(big.Int).Mul(p.y, q.y)), mod(new(big.Int).Mul(p.x, q.x)))) // a = -1: y1y2 - a x1x2
	one := big.NewInt(1)
	return point{
		mod(new(big.Int).Mul(x1, inv(new(big.Int).Add(one, t)))),
		mod(new(big.Int).Mul(y1, inv(new(big.Int).Sub(one, t)))),
	}
}

func scalarMult(k *big.Int, p point) point {
	r := refId
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = add(r, r)
		if k.Bit(i) == 1 {
			r = add(r, p)
		}
	}
	return r
}

func le(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

// decode is RFC 8032 §5.1.3 as written: y is the low 255 bits and must be below p; x comes from the curve
// equation; x = 0 with the sign bit set is invalid. It reports which rule refused.
func decode(enc []byte) (point, bool) {
	y := le(enc)
	sign := y.Bit(255)
	y.SetBit(y, 255, 0)
	if y.Cmp(refP) >= 0 {
		return point{}, false
	}
	y2 := mod(new(big.Int).Mul(y, y))
	u := mod(new(big.Int).Sub(y2, big.NewInt(1)))
	v := mod(new(big.Int).Add(mod(new(big.Int).Mul(refD, y2)), big.NewInt(1)))
	x2 := mod(new(big.Int).Mul(u, inv(v)))
	x := new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Add(refP, big.NewInt(3)), 3), refP) // x2^((p+3)/8)
	if mod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
		x = mod(new(big.Int).Mul(x, refI))
	}
	if mod(new(big.Int).Mul(x, x)).Cmp(x2) != 0 {
		return point{}, false // no square root: not on the curve
	}
	if x.Sign() == 0 && sign == 1 {
		return point{}, false
	}
	if x.Bit(0) != sign {
		x = mod(new(big.Int).Neg(x))
	}
	return point{x, y}, true
}

func isID(p point) bool { return p.x.Sign() == 0 && p.y.Cmp(big.NewInt(1)) == 0 }

// refVerify applies the pinned rule and returns "" when valid, else the step that refused (numbered as the
// note). The note's steps are phased: step 2 for both points, then step 3 for both. perPoint instead runs steps
// 2 and 3 on the public key, then on R, which is what internal/sig does; the verdict is identical either way and
// only the label of the refusing step can differ (when A fails step 3 and R fails step 2).
func refVerify(pub, msg, signature []byte, perPoint bool) string {
	if len(pub) != 32 || len(signature) != 64 {
		return "length"
	}
	if le(signature[32:]).Cmp(refL) >= 0 {
		return "1"
	}
	enc := [2][]byte{pub, signature[:32]}
	subgroup := func(p point) bool { return !isID(p) && isID(scalarMult(refL, p)) }
	var pts [2]point
	if perPoint {
		for i := range enc {
			p, ok := decode(enc[i])
			if !ok {
				return "2"
			}
			if !subgroup(p) {
				return "3"
			}
		}
	} else {
		for i := range enc {
			p, ok := decode(enc[i])
			if !ok {
				return "2"
			}
			pts[i] = p
		}
		for _, p := range pts {
			if !subgroup(p) {
				return "3"
			}
		}
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, signature) {
		return "4"
	}
	return ""
}

// stepNumber maps internal/sig's step names onto the note's numbers.
func stepNumber(s string) string {
	switch s {
	case "":
		return ""
	case sig.StepScalar:
		return "1"
	case sig.StepEncoding:
		return "2"
	case sig.StepSubgroup:
		return "3"
	case sig.StepEquation:
		return "4"
	}
	return "length"
}

type edCase struct {
	name         string
	pub, msg, sg []byte
	// fileStep is the step the vectors file says refuses the case, "" for a case that must verify.
	fileStep string
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// TestEd25519TwoImplementations: C-core-144 (b), the "two implementations" half. Every Ed25519 vector of the
// vectors file (E1, E2, NE1–NE13) is run through internal/sig and through the standard-library implementation
// above; the verdict and the refusing step must be identical. Beyond the file, a seeded family of honest and
// mutated signatures (bit flips in R, S, A and M; S + L; the identity and small-order encodings as R and A) runs
// through both.
func TestEd25519TwoImplementations(t *testing.T) {
	conformance.Partial(t, "C-core-144", "(b) verdicts of internal/sig and an independent standard-library implementation agree on every vector: checked here; (a) and (c) are checked in keylog and wire, still on one implementation")
	v, err := conformance.LoadVectors()
	if err != nil {
		t.Fatal(err)
	}
	pub := unhex(t, v.Ed25519Public)
	var cases []edCase
	for _, x := range v.EdPositive {
		cases = append(cases, edCase{x.Name, pub, []byte(x.SignedString), unhex(t, x.Sig), ""})
	}
	for _, x := range v.EdNegative {
		if x.PublicKey == "" {
			// NE13: the signature is valid Ed25519 over the string; it is refused for its envelope, not its signature
			cases = append(cases, edCase{x.Name, pub, []byte(x.SignedString), unhex(t, x.Sig), ""})
			continue
		}
		step := strings.TrimPrefix(strings.SplitN(x.PinnedStep, " ", 2)[0]+" "+strings.SplitN(x.PinnedStep, " ", 3)[1], "step ")
		cases = append(cases, edCase{x.Name, unhex(t, x.PublicKey), unhex(t, x.MessageHex), unhex(t, x.Sig), strings.TrimSpace(step)})
	}
	if len(cases) != 2+13 {
		t.Fatalf("%d Ed25519 vectors, want 15 (E1, E2, NE1–NE13)", len(cases))
	}
	// the honest signature of a few seeds, and mutations of each
	for i := 0; i < 8; i++ {
		seed := sha256.Sum256([]byte{byte(i), 'e', 'd'})
		msg := []byte(strings.Repeat("m", i*7))
		pk, sg := sig.SignEd25519(seed[:], msg)
		cases = append(cases, edCase{name: "honest/" + string(rune('0'+i)), pub: pk, msg: msg, sg: sg})
		for bit := 0; bit < 8*64; bit += 37 + i {
			m := append([]byte{}, sg...)
			m[bit/8] ^= 1 << (bit % 8)
			cases = append(cases, edCase{name: "flip-sig", pub: pk, msg: msg, sg: m})
		}
		for bit := 0; bit < 8*32; bit += 29 + i {
			m := append([]byte{}, pk...)
			m[bit/8] ^= 1 << (bit % 8)
			cases = append(cases, edCase{name: "flip-pub", pub: m, msg: msg, sg: sg})
		}
		cases = append(cases, edCase{name: "flip-msg", pub: pk, msg: append([]byte{1}, msg...), sg: sg})
		// S + L is the same scalar mod L, so the stock verifier may accept it; step 1 must refuse it
		s := new(big.Int).Add(le(sg[32:]), refL)
		if s.BitLen() <= 256 {
			sb := s.FillBytes(make([]byte, 32))
			for a, b := 0, 31; a < b; a, b = a+1, b-1 {
				sb[a], sb[b] = sb[b], sb[a]
			}
			cases = append(cases, edCase{name: "S+L", pub: pk, msg: msg, sg: append(append([]byte{}, sg[:32]...), sb...)})
		}
	}
	// the identity and small-order points in every position
	small := [][]byte{
		unhex(t, "0100000000000000000000000000000000000000000000000000000000000000"), // identity
		unhex(t, "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // order 2 (y = -1)
		unhex(t, "0000000000000000000000000000000000000000000000000000000000000000"), // order 4
		unhex(t, "0100000000000000000000000000000000000000000000000000000000000080"), // x = 0 with the sign bit set
		unhex(t, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p (non-canonical)
	}
	for i, a := range small {
		for j, r := range small {
			cases = append(cases, edCase{name: "small", pub: a, msg: []byte("x"), sg: append(append([]byte{}, r...), make([]byte, 32)...)})
			_, _ = i, j
		}
	}
	accepted, relabelled := 0, []string{}
	for _, c := range cases {
		got := stepNumber(sig.VerifyEd25519(c.pub, c.msg, c.sg))
		if ref := refVerify(c.pub, c.msg, c.sg, true); got != ref {
			t.Errorf("%s: internal/sig says step %q, the independent implementation says step %q\n  pub %x\n  msg %x\n  sig %x", c.name, got, ref, c.pub, c.msg, c.sg)
			continue
		}
		// the verdict is identical under the note's phased ordering too; only the label may move
		phased := refVerify(c.pub, c.msg, c.sg, false)
		if (phased == "") != (got == "") {
			t.Errorf("%s: phased ordering changed the verdict: %q vs %q", c.name, phased, got)
		}
		if phased != got && c.name != "small" {
			relabelled = append(relabelled, c.name+": per-point step "+got+", phased step "+phased)
		}
		if strings.HasPrefix(c.name, "NE") || strings.HasPrefix(c.name, "E") {
			if c.fileStep != got {
				t.Errorf("%s: both implementations say step %q, the vectors file says %q", c.name, got, c.fileStep)
			}
		}
		if got == "" {
			accepted++
		}
	}
	// Finding PROPS-F1 (label only): NE9 and NE10 have a public key that fails step 3 and an R that fails step 2.
	// The note lists step 2 for both points before step 3, so a phased reader labels them step 2; the vectors
	// file (and internal/sig) say step 3. Every verdict is the same.
	if got := strings.Join(relabelled, "; "); got != "NE9: per-point step 3, phased step 2; NE10: per-point step 3, phased step 2" {
		t.Errorf("step labels that depend on the order of steps 2 and 3: %q", got)
	}
	// the cases that must verify: E1, E2, NE13's signature, the 8 honest ones
	if accepted != 2+1+8 {
		t.Fatalf("%d cases verified, want 11 (E1, E2, NE13's signature, 8 honest); the harness may not reach the pre-checks", accepted)
	}
	t.Logf("%d cases, identical verdicts in both implementations (labels per PROPS-F1)", len(cases))
}
