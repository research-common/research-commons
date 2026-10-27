package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/research-common/research-commons/internal/gate"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/refusal"
)

// The policies a command runs under. Two files, two parsers, one place that reads them:
//
//   - the hub policy `hub-policy.json` at the store root (hub-template docs/hub-policy.md, schema
//     rc-hub-policy/1). A hub clone is a store, and its admission policy sits at that root. It is parsed by
//     gate.ParseHubPolicy, the one parser `hub check`, `pull` and every store command share: absent means the
//     defaults; present and unreadable, unparseable, or carrying a field or limit name the schema does not
//     define is exit 2 before any work (claims-model note §13, C-core-133a). Its digest is the sha256 of the
//     file's bytes (of the canonical defaults when absent).
//   - the reader policy (`reader-policy-v1`, fixed-root identity note §6), parsed by policy.Parse. It is read
//     only from a file the invocation names: `--policy <file>`, else $COMMONS_POLICY. Nothing is read
//     implicitly (no file in the home directory, none in the store). Commands that take it declare
//     ReaderPolicy; `hub check` does not (hub template H-13: signer trust is not an input to the check).
//
// `explain` and `status` print both digests, so two answers under different policies say which policy differed
// (P-08, P-11).

// PolicyFile is the hub policy file name at the store root.
const PolicyFile = "hub-policy.json"

// PolicyEnv names the reader policy file when --policy is not given.
const PolicyEnv = "COMMONS_POLICY"

// Policy is the checked policy in force.
type Policy struct {
	Source string // "defaults (no hub-policy.json)" or the file name
	Digest string // gate.Policy.Digest: sha256 of the file's bytes, or of the canonical defaults
	Hub    *gate.Policy
	// Reader is the reader policy; nil when none is configured (every answer is then the no-policy answer).
	Reader       *policy.Policy
	ReaderSource string // "option --policy <file>", "environment COMMONS_POLICY", or "" when none
}

func policyProblem(slug, title, scope, next, peer string) *Problem {
	return &Problem{Slug: slug, Title: title, Class: refusal.Policy, Scope: scope, Next: next, Peer: peer,
		Detail: "the reader's own configuration could not be used; nothing was done", Exit: ExitDidNotStart}
}

// readCapped reads at most max bytes of a regular file; a larger file is an error naming the limit.
func readCapped(p string, max int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(io.LimitReader(f, max+1)); err != nil {
		return nil, err
	}
	if int64(b.Len()) > max {
		return nil, errors.New("larger than the policy file size limit")
	}
	return b.Bytes(), nil
}

// loadHubPolicy checks the hub policy file at the store root. Any problem is exit 2 with nothing done.
func loadHubPolicy(root string) (*Policy, *Problem) {
	bad := func(peer string) *Problem {
		return policyProblem("policy-unreadable", "the policy file could not be used", "policy file "+PolicyFile,
			"fix or remove "+PolicyFile+" at the store root (absent means the defaults), then run the command again", peer)
	}
	b, err := readCapped(filepath.Join(root, PolicyFile), policy.MaxInput)
	if errors.Is(err, fs.ErrNotExist) {
		hp, _ := gate.ParseHubPolicy(nil, "store root")
		return &Policy{Source: "defaults (no " + PolicyFile + ")", Digest: hp.Digest, Hub: hp}, nil
	}
	if err != nil {
		return nil, bad(err.Error())
	}
	hp, err := gate.ParseHubPolicy(b, "store root")
	if err != nil {
		var d *gate.DidNotStart
		if errors.As(err, &d) {
			return nil, bad(d.Detail)
		}
		return nil, bad(err.Error())
	}
	return &Policy{Source: PolicyFile, Digest: hp.Digest, Hub: hp}, nil
}

// loadReaderPolicy reads the reader policy the invocation names, if any: --policy, else $COMMONS_POLICY.
func loadReaderPolicy(flags map[string]string, env *Env) (*policy.Policy, string, *Problem) {
	path, scope := "", ""
	if p, ok := flags["policy"]; ok {
		path, scope = p, "option --policy"
	} else if p := env.Getenv(PolicyEnv); p != "" {
		path, scope = p, "environment "+PolicyEnv
	}
	if path == "" {
		return nil, "", nil
	}
	next := "fix the reader policy file, or drop " + scope + " to read with no reader policy"
	b, err := readCapped(path, policy.MaxInput)
	if err != nil {
		return nil, "", policyProblem("reader-policy-unreadable", "the reader policy file could not be read", scope, next, err.Error())
	}
	p, err := policy.Parse(b)
	if err != nil {
		return nil, "", policyProblem("reader-policy-unreadable", "the reader policy file is not a usable reader-policy-v1 document", scope, next, err.Error())
	}
	return p, scope, nil
}

// readerPolicyObj is the reader policy as explain and status print it.
func (p *Policy) readerObj() *Obj {
	if p.Reader == nil {
		return newObj().set("source", textV("none configured (no --policy, no "+PolicyEnv+"): every answer is the no-policy answer"))
	}
	return newObj().set("source", textV(p.ReaderSource)).set("digest", refV(p.Reader.Digest))
}

// readerPolicyFlag is the flag every ReaderPolicy command declares.
var readerPolicyFlag = Flag{Name: "policy", Value: "file",
	Help: "the reader policy (reader-policy-v1) to answer under (default: $" + PolicyEnv + "; none when neither is set; nothing is read implicitly)"}

func digestOf(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}
