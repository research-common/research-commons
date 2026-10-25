package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/research-common/research-commons/internal/canon"
)

// The reader's policy as the read commands see it today. A hub clone is a store (its root holds rc-store),
// and the hub's admission policy `hub-policy.json` at that root is the one policy file the format has
// published (hub-template docs/hub-policy.md, schema rc-hub-policy/1). Every command that reads a store
// checks it before any work: absent means the defaults; present and unreadable, unparseable, or carrying a
// field the schema does not define is exit 2 (claims-model note §13, C-core-133a). The read commands apply
// none of its fields (they gate admission, which `hub check` and `pull` do); its digest is part of the policy
// digest `explain` prints, so two answers under different policies say so (P-08).
//
// A reader-local policy (trust, execution, time backend) has no published file format yet; when it does, it
// is one more entry in policyFiles and the same check covers it.

// PolicyFile is the hub policy file name at the store root.
const PolicyFile = "hub-policy.json"

// Policy is the checked policy in force.
type Policy struct {
	Source string // "defaults (no hub-policy.json)" or the file name
	Digest string // sha256 of the canonical encoding of the file's value, or of the defaults
	Value  *canon.Object
}

var hubPolicyFields = map[string]func(canon.Value) bool{
	"policy":     func(v canon.Value) bool { return v == canon.String("rc-hub-policy/1") },
	"blobs":      func(v canon.Value) bool { return v == canon.String("stored") || v == canon.String("external-only") },
	"limits":     isIntMap,
	"not_served": isNotServed,
	"series":     isSeries,
}

func isIntMap(v canon.Value) bool {
	o, ok := v.(*canon.Object)
	if !ok {
		return false
	}
	for _, k := range o.Keys {
		if n, ok := o.Members[k].(canon.Int); !ok || n < 0 || !limitName(k) {
			return false
		}
	}
	return true
}

func limitName(k string) bool {
	if len(k) == 0 || len(k) > 64 || k[0] < 'a' || k[0] > 'z' {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

func isNotServed(v canon.Value) bool {
	a, ok := v.(canon.Array)
	if !ok {
		return false
	}
	seen := map[string]bool{}
	for _, e := range a {
		o, ok := e.(*canon.Object)
		if !ok {
			return false
		}
		d, ok := o.Members["digest"].(canon.String)
		if !ok || !isDigest(string(d)) || seen[string(d)] {
			return false
		}
		seen[string(d)] = true
		for _, k := range o.Keys {
			if k == "reason" {
				if _, ok := o.Members[k].(canon.String); !ok {
					return false
				}
			} else if k != "digest" {
				return false
			}
		}
	}
	return true
}

func isSeries(v canon.Value) bool {
	o, ok := v.(*canon.Object)
	if !ok {
		return false
	}
	for _, k := range o.Keys {
		if _, ok := o.Members[k].(canon.Bool); k != "refuse_premature_freeze" || !ok {
			return false
		}
	}
	return true
}

// defaultPolicy is the value an absent file means.
var defaultPolicy = `{"blobs":"stored","limits":{},"not_served":[],"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":false}}`

// loadPolicy checks the policy file at the store root. Any problem is exit 2 with nothing done.
func loadPolicy(root string) (*Policy, *Problem) {
	p := filepath.Join(root, PolicyFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		v, _ := canon.Parse([]byte(defaultPolicy))
		return &Policy{Source: "defaults (no " + PolicyFile + ")", Digest: digestOf(canon.Encode(v)), Value: v.(*canon.Object)}, nil
	}
	bad := func(detail string, peer string) *Problem {
		return usage("policy-unreadable", "the policy file could not be used", detail, "policy file "+PolicyFile,
			"fix or remove "+PolicyFile+" at the store root (absent means the defaults), then run the command again", peer)
	}
	if err != nil {
		return nil, bad("the file is present and cannot be read", err.Error())
	}
	v, err := canon.Parse(b)
	if err != nil {
		return nil, bad("the file is present and is not strict JSON (duplicate keys, non-integer numbers and invalid UTF-8 are refused)", err.Error())
	}
	o, ok := v.(*canon.Object)
	if !ok {
		return nil, bad("the file is not a JSON object", "")
	}
	if _, ok := o.Members["policy"]; !ok {
		return nil, bad("the required member policy is missing", "")
	}
	keys := slices.Clone(o.Keys)
	slices.Sort(keys)
	for _, k := range keys {
		check, known := hubPolicyFields[k]
		if !known {
			return nil, bad("the file carries a field this version does not define", k)
		}
		if !check(o.Members[k]) {
			return nil, bad("a field has a value the schema rc-hub-policy/1 does not allow", k)
		}
	}
	return &Policy{Source: PolicyFile, Digest: digestOf(canon.Encode(o)), Value: o}, nil
}

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
