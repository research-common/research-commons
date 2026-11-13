package wire

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestWriterMajorPerKind: the writer's major is a property of each statement (identity profile §2.1), not one
// global constant. Bare-key statements stay rc/1, the administrative kinds and every act for an identity are rc/2,
// raw key events stay rc/1 and never carry an actor, and genesis/describes take no actor.
func TestWriterMajorPerKind(t *testing.T) {
	cases := []struct {
		kind   string
		acting bool
		want   int
	}{
		{"authored", false, Major}, {"holds", false, Major}, {"genesis", false, Major}, {"describes", false, Major},
		{"rotate_key", false, Major}, {"revoke_key", false, Major},
		{"authored", true, CandidateMajor}, {"observed", true, CandidateMajor}, {"corroborates", true, CandidateMajor},
		{"edition", true, CandidateMajor}, {"submit", true, CandidateMajor}, {"anchors", true, CandidateMajor},
		{"identity_inception", false, CandidateMajor}, {"identity_grant", false, CandidateMajor}, {"identity_cut", false, CandidateMajor},
		{"identity_grant", true, 0}, {"rotate_key", true, 0}, {"revoke_key", true, 0}, {"genesis", true, 0}, {"describes", true, 0},
	}
	for _, c := range cases {
		if got := WriterMajor(c.kind, c.acting); got != c.want {
			t.Errorf("WriterMajor(%s, acting %v) = %d, want %d", c.kind, c.acting, got, c.want)
		}
	}
	if Major != 1 {
		t.Fatalf("Major is %d: the rc/1 reader's major and the bare-key writer major stay 1", Major)
	}
	for _, d := range []struct {
		kind  string
		actor *Actor
	}{{"revoke_key", nil}, {"rotate_key", &Actor{Identity: hex64('a'), Grant: hex64('b')}}, {"identity_grant", &Actor{Identity: hex64('a'), Grant: hex64('b')}},
		{"authored", &Actor{Identity: "x", Grant: hex64('b')}}} {
		if _, err := IdentityDraft(Draft{Kind: d.kind, Body: &canon.Object{Members: map[string]canon.Value{}}}, d.actor, nil); err == nil {
			t.Errorf("IdentityDraft(%s, %v) built an rc/2 draft", d.kind, d.actor)
		}
	}
	if _, err := IdentityDraft(Draft{Kind: "authored", Body: ivObj(IdentityCrit, ivObj())}, &Actor{Identity: hex64('a'), Grant: hex64('b')}, nil); err == nil {
		t.Error("IdentityDraft accepted a body already carrying the marker")
	}
}

func hex64(c byte) string { return string(bytes.Repeat([]byte{c}, 64)) }

// TestWriterReproducesSignedVectors: the writer path (WriterMajor + IdentityDraft + Sign) rebuilds every published
// positive signed vector, both algorithms, byte for byte from its kind, body (without the marker), marker, actor and
// linkage; Write reads each back through the production reader with the vector's own status and actor. So what the
// writer signs is exactly the representation the reader was built and tested against.
func TestWriterReproducesSignedVectors(t *testing.T) {
	v, err := conformance.LoadSignedIdentityVectors()
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]Key{}
	for _, k := range v.Keys {
		sec, _ := hex.DecodeString(k.Secret)
		if k.Alg == AlgEd25519 {
			keys[k.Signer] = Ed25519Key{Seed: sec}
		} else {
			keys[k.Signer] = EIP191Key{Scalar: sec}
		}
	}
	n := 0
	for _, p := range v.Positive {
		pv, err := canon.Parse([]byte(p.JCS))
		if err != nil {
			t.Fatal(err)
		}
		env := pv.(*canon.Object)
		body := env.Members["body"].(*canon.Object)
		var marker *canon.Object
		bare := &canon.Object{Members: map[string]canon.Value{}}
		for _, k := range body.Keys {
			if k == IdentityCrit {
				marker = body.Members[k].(*canon.Object)
				continue
			}
			bare.Keys = append(bare.Keys, k)
			bare.Members[k] = body.Members[k]
		}
		var actor *Actor
		if a, ok := env.Members[ActorField].(*canon.Object); ok {
			actor = &Actor{Identity: string(a.Members["identity"].(canon.String)), Grant: string(a.Members["grant"].(canon.String))}
		}
		d := Draft{Kind: p.Kind, Seq: int64(env.Members["seq"].(canon.Int)), TS: string(env.Members["ts"].(canon.String)), Body: bare}
		if pr, ok := env.Members["prev"].(canon.String); ok {
			d.Prev = string(pr)
		}
		want := WriterMajor(p.Kind, actor != nil)
		if (want == CandidateMajor) != (p.RC == "rc/2") {
			t.Fatalf("%s: WriterMajor %d for a vector in %s", p.Name, want, p.RC)
		}
		if want == CandidateMajor {
			if d, err = IdentityDraft(d, actor, marker); err != nil {
				t.Fatalf("%s: %v", p.Name, err)
			}
		} else {
			d.Body = body
		}
		k := keys[p.Signer]
		line, id := Sign(d, k)
		wantLine, _ := canon.Parse([]byte(p.Line))
		if id != p.ID || !bytes.Equal(line, canon.Encode(wantLine)) {
			t.Fatalf("%s: the writer signed %s (id %s), the vector is %s (id %s)", p.Name, line, id, p.Line, p.ID)
		}
		ts := env.Members["ts"].(canon.String)
		now, _ := time.Parse(time.RFC3339, string(ts))
		st, err := Write(d, k, now)
		if err != nil || st.ID != p.ID || string(st.Status) != p.Status {
			t.Fatalf("%s: Write read back %v %v, want %s", p.Name, st, err, p.Status)
		}
		if actor != nil && (st.Actor == nil || st.Actor.Identity != p.ActorIdentity || st.Actor.Grant != p.ActorGrant) {
			t.Fatalf("%s: actor not read back: %+v", p.Name, st.Actor)
		}
		n++
	}
	if n < 16 {
		t.Fatalf("only %d positive vectors rebuilt", n)
	}
}
