package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// package show, key sign: the signing side of the external-signing package (identity profile §8). The custody
// model they serve keeps a root key on a machine that holds the binary and the key file and no store: the package
// is carried there by hand, checked, signed, and the signature carried back to the store for --complete.
//
//   - package show runs the one package check --complete runs (inspectPackage): the PAE, the id, the alg, the
//     signer, the log head's shape and the summary are recomputed from the envelope and compared with the
//     package's copies. It prints what a signature would cover. It reads no store, so it cannot say whether the
//     log head is still the signer's head: --complete checks that.
//   - key sign runs the same check, refuses unless the key file is the package's signer, signs the recomputed PAE
//     with the writer's own signing code (wire.Key.Sign: RFC 8032 Ed25519, or EIP-191 personal_sign), verifies the
//     signature as every reader does, and writes it in the statement encoding --complete --signature reads. It
//     signs only the PAE of an envelope the tool would prepare, never bytes given to it.
//
// Neither reads a store; both are store-less by construction (Command.Store is false, so --store is refused and
// $COMMONS_STORE is not read).

func init() {
	Register(&Command{Name: "package show", Summary: "check an external-signing package and print what its signature would cover (reads no store)",
		Args: []Arg{{Name: "file", Shape: ShapeText}},
		Flags: []Flag{
			{Name: "pae-out", Value: "file", Help: "write the exact PAE bytes a signature covers (the decoded pae member, no newline) to this new file, for a signer that is not this tool; never overwritten; written only when every check passes"},
			expectPAEFlag,
		},
		Help: "Reads a package written by --prepare (" + SigningPackageFormat + ", provisional) and recomputes, from its envelope alone, " +
			"everything the package derives from it: the PAE bytes, the statement id, the alg, the signer, the log head's shape and the summary, exactly as --complete does. " +
			"Exit 0 when every derived member matches, printing the summary, the signer, the alg, the proposed id, pae_sha256 and pae_bytes; " +
			"exit 1 naming the first member that differs (and listing every one); exit 2 when the file is unreadable or not a package. " +
			"It reads no store, so the log head is not checked against one: --complete checks it. " +
			"Compare its pae_sha256 with the one --prepare printed, carried by a separate channel. " +
			"When the envelope's ts is more than 300 s ahead of this machine's clock it adds an advisory (the store refuses such a ts at --complete); the exit is unchanged. " +
			"--pae-out <file> writes the PAE bytes themselves for a signer that is not this tool. " +
			"--expect-pae-sha256 <hex> compares the sha256 of the PAE bytes with a digest you carried by a separate channel: a match prints \"pae sha256: matches expected\"; " +
			"a different digest is exit 1 naming both, and --pae-out then writes nothing.",
		Run: packageShowCmd})
	Register(&Command{Name: "key sign", Summary: "sign an external-signing package's PAE bytes with a key file (reads no store)",
		Flags: []Flag{
			{Name: "package", Value: "file", Help: "the package written by --prepare; checked exactly as package show checks it, and refused, nothing written, when any derived member differs"},
			{Name: "key", Value: "file", Help: "the key file (else $" + KeyEnv + "); its signer must be the package's signer"},
			{Name: "out", Value: "file|-", Help: "the new file to write the signature to (never overwritten); - (the default) writes the signature line to standard output and the summary to standard error"},
			expectPAEFlag,
			{Name: "dry-run", Help: "check the package and the key and print what would be signed; sign nothing, write nothing"},
		},
		Help: "Signs, with a key file, the PAE bytes recomputed from a package written by --prepare, on a machine that holds no store: " +
			"the package is checked as package show checks it, the key must be the package's signer, the signature is made by the code the writer signs with " +
			"and verified over the recomputed bytes before it is written, in the statement encoding --complete --signature reads (ed25519: 128 lowercase hex; " +
			"eip191-secp256k1: 0x + 130 lowercase hex), newline-terminated. Every refusal writes nothing. There is no prompt: review the summary with package show " +
			"(or --dry-run) first. It signs only the PAE of a statement the tool would prepare, never bytes it is given. " +
			"--expect-pae-sha256 <hex> refuses, exit 1 and nothing signed or written, unless the sha256 of the PAE bytes is that digest. " +
			"Carry the signature back and run the prepared command with --complete <package> --signature <file|->. A key file is not a hardware or wallet connector. " +
			"Like package show it adds an advisory, and still signs, when the envelope's ts is more than 300 s ahead of this machine's clock.",
		Run: keySignCmd})
}

// expectPAEFlag is --expect-pae-sha256, shared by package show and key sign.
var expectPAEFlag = Flag{Name: "expect-pae-sha256", Value: "hex", Help: "the sha256 of the PAE bytes (64 lowercase hex) that --prepare printed, carried by a separate channel: " +
	"a match prints \"pae sha256: matches expected\"; a different digest is exit 1 naming both, and nothing is written"}

// expectedPAE reads --expect-pae-sha256: ("", false, nil) when absent; a value that is not 64 lowercase hex is exit 2.
func expectedPAE(c *Ctx) (string, bool, *Problem) {
	v, ok := c.Flag("expect-pae-sha256")
	if !ok {
		return "", false, nil
	}
	if len(v) != 64 || strings.Trim(v, "0123456789abcdef") != "" {
		return "", true, usage("bad-pae-digest", "--expect-pae-sha256 is not a sha256 digest", "the digest is 64 lowercase hex characters; nothing was done",
			"option --expect-pae-sha256", "give the pae_sha256 that --prepare printed, unchanged", v)
	}
	return v, true, nil
}

// checkExpectedPAE compares the sha256 of the recomputed PAE with the digest the caller expects: a different digest
// is exit 1 (the class of a failed check), naming both.
func checkExpectedPAE(st *wire.Statement, want, path string) *Problem {
	sum := sha256.Sum256(st.SignedString)
	got := hex.EncodeToString(sum[:])
	if got == want {
		return nil
	}
	p := usage("pae-digest-mismatch", "the PAE's sha256 is not the one expected",
		"the PAE bytes recomputed from the package's envelope hash to "+got+", but --expect-pae-sha256 is "+want+"; nothing was done",
		"option --expect-pae-sha256", "do not sign: the package is not the one that was prepared; ask for the package again by a trusted channel", path)
	p.Exit = ExitWrong
	return p
}

// logHeadUnchecked is what package show and key sign say about the log head.
const logHeadUnchecked = "log head not checked: no store; --complete checks it"

// completeCommand is the command that completes a package of this kind.
func completeCommand(st *wire.Statement) string {
	switch st.Kind {
	case "identity_inception":
		return "commons identity new --complete <package> --signature <file|->"
	case "identity_grant":
		return "commons identity grant --complete <package> --signature <file|->"
	case "identity_cut":
		return "commons identity cut --complete <package> --signature <file|->"
	}
	return "commons publish --complete <package> --signature <file|-> (an act about bytes also takes --content <file>)"
}

// shownPackage reads and checks a package for package show and key sign: a malformed package is exit 2 scoped to
// scope; a derived member that differs is exit 1, naming it.
func shownPackage(path, scope string) (*wire.Statement, *Problem) {
	pkg, prob := readJSONFile(path, scope)
	if prob != nil {
		return nil, prob
	}
	st, mm, prob := inspectPackage(pkg, path, scope)
	if prob != nil {
		return nil, prob
	}
	if len(mm) > 0 {
		return nil, mm[0].problem(mm, path, ExitWrong)
	}
	return st, nil
}

// futureSkewAdvisory is the advisory package show and key sign print when the envelope's ts is further ahead of
// this machine's clock than the writer's future-skew bound: the store refuses such a statement at --complete
// (wire.Write), so a signature over it would be wasted. It is advice, not a check: the signing machine's clock is a
// weaker reference than the store's, so the exit and the signing are unchanged. "" when there is nothing to say.
func futureSkewAdvisory(st *wire.Statement) string {
	now := Now()
	limit := now.Add(wire.MaxFutureSkew)
	if rctime.Compare(st.TS, rctime.Time{Sec: limit.Unix(), Nanos: int32(limit.Nanosecond())}) <= 0 {
		return ""
	}
	ahead := time.Duration(st.TS.Sec-now.Unix()) * time.Second
	return "ts " + st.TS.Text + " is " + itoa(int(ahead/time.Second)) + " s ahead of this machine's clock: the store refuses this at --complete " +
		"(writer's future-skew bound, " + itoa(int(wire.MaxFutureSkew/time.Second)) + " s); re-prepare with a current --ts"
}

// packageObj is what a checked package says: the statement a signature would cover, and what was not checked.
func packageObj(out *Obj, path string, st *wire.Statement) *Obj {
	sum := sha256.Sum256(st.SignedString)
	out.set("package", peerV(path)).set("format", textV(SigningPackageFormat)).
		set("checked", textV("every derived member (pae, statement, alg, signer, log_head shape, summary) is what the envelope gives")).
		set("log_head_check", textV(logHeadUnchecked)).
		set("statement", refV(st.ID)).set("kind", peerV(st.Kind)).set("signer", refV(st.Signer)).set("alg", textV(st.Alg)).
		set("seq", intV(st.Seq)).set("ts_signer_declared", refV(st.TS.Text)).set("log_head", rawV{logHead(head{seq: st.Seq, prev: st.Prev})}).
		set("pae_sha256", refV(hex.EncodeToString(sum[:]))).set("pae_bytes", intV(int64(len(st.SignedString)))).
		set("summary", rawV{summaryOf(st)})
	if adv := futureSkewAdvisory(st); adv != "" {
		out.set("advisories", texts(adv))
	}
	return out
}

func packageShowCmd(c *Ctx) (*Obj, int, error) {
	path := c.Args["file"]
	paeOut, _ := c.Flag("pae-out")
	want, expecting, prob := expectedPAE(c)
	if prob != nil {
		return nil, 0, prob
	}
	if paeOut != "" {
		if _, err := os.Lstat(paeOut); err == nil {
			return nil, 0, usage("pae-file-exists", "the PAE file already exists", "a PAE file is never overwritten; nothing was done",
				"option --pae-out", "name a new file", paeOut)
		}
	}
	st, prob := shownPackage(path, "argument file")
	if prob != nil {
		return nil, 0, prob
	}
	if expecting {
		if prob := checkExpectedPAE(st, want, path); prob != nil {
			return nil, 0, prob
		}
	}
	out := packageObj(newObj(), path, st)
	if expecting {
		out.set("pae_check", textV("pae sha256: matches expected"))
	}
	if paeOut != "" {
		// only after every check passed: the bytes are the recomputed PAE (equal to the decoded pae member), no newline
		if p := writeNewFile(paeOut, st.SignedString, "option --pae-out", "pae-file-exists", "a PAE file is never overwritten"); p != nil {
			return nil, 0, p
		}
		out.set("pae_written", peerV(paeOut))
	}
	return out.
		set("next", textV("compare pae_sha256 with the one --prepare printed; sign the decoded pae bytes with "+st.Signer+" ("+st.Alg+
			"), for example commons key sign --package <package> --key <file>; then run "+completeCommand(st))), ExitOK, nil
}

func keySignCmd(c *Ctx) (*Obj, int, error) {
	path, ok := c.Flag("package")
	if !ok || path == "" {
		return nil, 0, usage("missing-argument", "--package is missing", "key sign signs a package written by --prepare; nothing was done",
			"option --package", "give --package <file>", "")
	}
	out, ok := c.Flag("out")
	if !ok || out == "" {
		out = "-"
	}
	_, dry := c.Flag("dry-run")
	want, expecting, prob := expectedPAE(c)
	if prob != nil {
		return nil, 0, prob
	}
	if out == "-" && c.JSON && !dry {
		return nil, 0, conflicting("json", "--json and --out - both write standard output",
			"--out - writes the signature line there for --complete --signature - to read", "give --out <file> with --json, or drop --json")
	}
	if out != "-" {
		if _, err := os.Lstat(out); err == nil {
			return nil, 0, usage("signature-file-exists", "the signature file already exists", "a signature file is never overwritten; nothing was done",
				"option --out", "name a new file", out)
		}
	}
	st, prob := shownPackage(path, "option --package")
	if prob != nil {
		return nil, 0, prob
	}
	if expecting {
		if prob := checkExpectedPAE(st, want, path); prob != nil {
			return nil, 0, prob
		}
	}
	lk, prob := signingKey(c)
	if prob != nil {
		return nil, 0, prob
	}
	if lk.Key.Signer() != st.Signer || lk.Key.Alg() != st.Alg {
		return nil, 0, &Problem{Slug: "key-not-signer", Title: "the key file is not the package's signer", Class: refusal.Intrinsic, Scope: "option --key",
			Detail: "the package is prepared for " + st.Signer + " (" + st.Alg + "); the key file is " + lk.Key.Signer() + " (" + lk.Key.Alg() + "); nothing was signed or written",
			Next:   "name the key file of " + st.Signer + ", or prepare the statement again with --signer <your key>", Peer: lk.Path, Exit: ExitDidNotStart}
	}
	if dry {
		return packageObj(newObj(), path, st).set("key_file", peerV(lk.Path)).
			set("dry_run", boolV(true)).set("signed", boolV(false)).set("written", boolV(false)).
			set("would", textV("sign the "+itoa(len(st.SignedString))+" PAE bytes above with "+st.Signer+" ("+st.Alg+") and write the signature")), ExitOK, nil
	}
	// the summary is printed before anything is signed: on standard error on the human surface (standard output
	// may be the signature), in the one result object with --json
	res := newObj()
	if c.JSON {
		res = packageObj(res, path, st).set("key_file", peerV(lk.Path))
	} else if c.Env.Stderr != nil {
		io.WriteString(c.Env.Stderr, human(packageObj(newObj(), path, st).set("key_file", peerV(lk.Path)).
			set("signing", textV("the PAE bytes above, with "+st.Signer+" ("+st.Alg+")"))))
	}
	// the writer's own signing code over the recomputed bytes, then the reader's check of the signed line
	sig := lk.Key.Sign(st.SignedString)
	env := envelopeOf(st).(*canon.Object)
	if why := verifyOver(env, st, sig); why != "" {
		return nil, 0, failed(errors.New("the signature made does not verify: "+why), "option --key", false, "report the bug with the package")
	}
	res.set("statement", refV(st.ID)).set("signature", refV(sig)).set("signed", boolV(true)).set("dry_run", boolV(false))
	line := []byte(sig + "\n")
	if out == "-" {
		if _, err := c.Env.Stdout.Write(line); err != nil {
			return nil, 0, failed(err, "standard output", false, "run the command again")
		}
		if c.Env.Stderr != nil {
			io.WriteString(c.Env.Stderr, human(newObj().set("written", textV("standard output")).set("next", textV("carry the signature back and run "+completeCommand(st)))))
		}
		return nil, ExitOK, nil
	}
	if p := writeNewFile(out, line, "option --out", "signature-file-exists", "a signature file is never overwritten"); p != nil {
		return nil, 0, p
	}
	return res.set("written", peerV(out)).
		set("next", textV("carry the signature file back and run "+completeCommand(st))), ExitOK, nil
}

// writeNewFile writes b to a new file at path (never overwriting), synced; on failure nothing is left behind.
func writeNewFile(path string, b []byte, scope, existsSlug, existsDetail string) *Problem {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return usage(existsSlug, "the file already exists", existsDetail+"; nothing was written", scope, "name a new file", path)
		}
		return usage("unwritable-file", "the file cannot be created", "nothing was written", scope, "check the path and the directory's permissions", path)
	}
	_, werr := f.Write(b)
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(path)
		p := failed(errors.New("writing the file failed"), scope, false, "check free space, then run the command again")
		p.Peer = path
		return p
	}
	return nil
}
