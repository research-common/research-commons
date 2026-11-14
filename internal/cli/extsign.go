package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// External signing (identity profile §8): identity new, identity grant, identity cut and publish --as can stop
// before the signature and write an external-signing package instead (--prepare), and later commit a package
// with a signature made elsewhere, on a device or another machine (--complete). The tool never needs the key.
//
//   - --prepare resolves every reference exactly as the signing path does (the identity, the grant, the delegate's
//     first line, --last-good, the signer's log head), builds the unsigned envelope the signature will cover, checks
//     that every reader would hold it valid once signed (wire.CheckUnsigned), and writes one package file: the
//     envelope, the exact PAE bytes, the algorithm, the signer, the proposed statement id, the log head it was
//     prepared at and a human summary. Nothing is appended. An existing file is never overwritten.
//   - --complete re-reads the package and trusts none of its derived fields: the PAE and the id are recomputed from
//     the envelope and must equal the package's, as must the alg, signer, log head and summary (each mismatch is
//     named). The signature is verified over the recomputed PAE under the envelope's signer. The command then runs
//     as if invoked directly with the envelope's inputs: every eligibility and admission check runs again, the
//     signer's log must still be at the prepared head (else stale-prepare, exit 1), and the statement the command
//     builds must be the prepared envelope byte for byte. Only then is the line committed, through the same commit
//     unit as direct signing. Every refusal leaves the store unchanged.
//
// The package format is this tool's own and provisional, like the key file format.

// SigningPackageFormat is the format tag of an external-signing package.
const SigningPackageFormat = "rc-signing-package/0"

// maxSignatureInput bounds the --signature input: the longest encoding is 132 bytes plus a line ending.
const maxSignatureInput = 256

var extFlags = []Flag{
	{Name: "prepare", Value: "file", Help: "do not sign: write an external-signing package (" + SigningPackageFormat + ", provisional) to this new file: the unsigned statement, the exact bytes to sign (PAE, base64), the signer, the proposed id, your log's head and a summary; needs --signer, takes no --key, appends nothing; an existing file is never overwritten"},
	{Name: "signer", Value: "key", Help: "with --prepare: the public form of the key that will sign (ed25519:<64 hex> or 0x<40 hex>); the algorithm follows from the form", Check: func(v string) error {
		if !reGrantee.MatchString(v) {
			return errString("not a key (ed25519: + 64 lowercase hex, or 0x + 40 lowercase hex)")
		}
		return nil
	}},
	{Name: "complete", Value: "file", Help: "commit a package written by --prepare, with --signature: the bytes signed are recomputed from the package, the signature verified, every check of direct signing run again; refused, nothing appended, when your log moved since the package was prepared (stale-prepare)"},
	{Name: "signature", Value: "file|-", Help: "with --complete: the signature over the package's PAE bytes in the statement encoding (ed25519: 128 lowercase hex; eip191-secp256k1: 0x + 130 lowercase hex); - reads standard input"},
}

// extHelp is the sentence each command's help gains.
const extHelp = " External signing (identity profile §8): --prepare <file> --signer <key> writes an external-signing package and appends nothing; " +
	"sign its PAE bytes with the key elsewhere, then --complete <file> --signature <file|-> verifies the signature over the recomputed bytes, " +
	"runs every check again, and commits only when your log has not moved since (else stale-prepare, exit 1)."

// externalKey stands for a key the tool does not hold: its public form, and the signature given with --complete
// ("" while preparing). It signs nothing itself: Sign returns the given signature, which the reader then verifies.
type externalKey struct {
	signer, alg string
	sig         string
	// env is the prepared envelope (--complete): the statement the command builds now must be these bytes.
	env *canon.Object
}

func (k *externalKey) Alg() string        { return k.alg }
func (k *externalKey) Signer() string     { return k.signer }
func (k *externalKey) Sign([]byte) string { return k.sig }

// extSign is an invocation's external-signing mode, kept in Ctx.state from Prepare to Run.
type extSign struct {
	prepare  string // the package file to write; "" when completing
	complete string // the package file read; "" when preparing
	key      *externalKey
	// draft is the {kind, body} an act's package carries, for publish --complete (the body without its marker).
	draft *canon.Object
}

func extOf(c *Ctx) *extSign {
	x, _ := c.state.(*extSign)
	return x
}

func preparing(c *Ctx) bool {
	x := extOf(c)
	return x != nil && x.prepare != ""
}

func algOfSigner(s string) string {
	if strings.HasPrefix(s, "0x") {
		return wire.AlgEIP191
	}
	return wire.AlgEd25519
}

func conflicting(flag, title, detail, next string) *Problem {
	return usage("conflicting-options", title, detail+"; nothing was done", "option --"+flag, next, "")
}

// beginExternal reads --prepare / --complete for a command whose statement kind is kind ("" for publish, whose
// prepared statement must act for an identity). With --complete it reads and checks the package and the signature
// and sets the command's own options from the envelope, so the command's Prepare runs on exactly the inputs that
// were prepared. Without either option it does nothing.
func beginExternal(c *Ctx, kind string) *Problem {
	prep, hasPrep := c.Flag("prepare")
	comp, hasComp := c.Flag("complete")
	_, hasSigner := c.Flag("signer")
	_, hasSig := c.Flag("signature")
	switch {
	case hasPrep && hasComp:
		return conflicting("complete", "--prepare and --complete are two steps", "give one of them per invocation", "prepare first, sign the PAE bytes, then complete")
	case hasSigner && !hasPrep:
		return conflicting("signer", "--signer goes with --prepare", "a key file names its own signer, and a package carries it", "drop --signer, or add --prepare <file>")
	case hasSig && !hasComp:
		return conflicting("signature", "--signature goes with --complete", "a signature is given for a prepared package", "add --complete <package>, or drop --signature")
	case !hasPrep && !hasComp:
		return nil
	}
	if hasPrep {
		if _, ok := c.Flag("key"); ok {
			return conflicting("key", "--prepare takes no key", "preparing signs nothing; the package names the signer by its public form", "drop --key and give --signer <key>")
		}
		if _, ok := c.Flag("dry-run"); ok {
			return conflicting("dry-run", "--prepare is already a dry run", "it writes the package and appends nothing", "drop --dry-run")
		}
		signer, ok := c.Flag("signer")
		if !ok {
			return usage("missing-argument", "--prepare needs --signer", "the package names the key that will sign it; nothing was done", "option --signer",
				"give --signer <key> (ed25519:<64 hex> or 0x<40 hex>; commons key show <file> prints it)", "")
		}
		if kind == "" {
			if _, ok := c.Flag("as"); !ok {
				return usage("missing-argument", "publish --prepare needs --as", "external signing is built for identity statements: an act for an identity, or the identity commands; nothing was done",
					"option --as", "give --as <identity> --grant <grant id>", "")
			}
		}
		if _, err := os.Lstat(prep); err == nil {
			return usage("package-exists", "the package file already exists", "a package is never overwritten; nothing was done", "option --prepare", "name a new file", prep)
		}
		c.state = &extSign{prepare: prep, key: &externalKey{signer: signer, alg: algOfSigner(signer)}}
		return nil
	}
	allowed := []string{"complete", "signature", "prev", "json", "store"}
	if kind == "" {
		allowed = append(allowed, "content")
	}
	for name := range c.Flags {
		if !slices.Contains(allowed, name) {
			return conflicting(name, "--complete takes its inputs from the package",
				"the statement is the prepared one; only --signature, --prev (the line prepared on) and, for an act about bytes, --content are given beside it",
				"drop --"+name)
		}
	}
	sigArg, ok := c.Flag("signature")
	if !ok {
		return usage("missing-argument", "--complete needs --signature", "nothing was done", "option --signature",
			"give the signature over the package's PAE bytes: --signature <file>, or - for standard input", "")
	}
	pkg, prob := readJSONFile(comp, "option --complete")
	if prob != nil {
		return prob
	}
	st, prob := checkPackage(pkg, comp)
	if prob != nil {
		return prob
	}
	switch {
	case kind != "" && st.Kind != kind:
		return badPackage("the package is not for this command", "it prepares a "+st.Kind+"; this command completes a "+kind, comp, "run the command the package was prepared with")
	case kind == "" && st.Actor == nil:
		return badPackage("the package is not for this command", "it prepares a "+st.Kind+" that acts for no identity; publish --complete completes an act (publish --as)", comp,
			"run the command the package was prepared with")
	}
	sig, prob := readSignature(c, sigArg, st.Alg)
	if prob != nil {
		return prob
	}
	// the signature, verified over the recomputed bytes under the envelope's own signer and algorithm
	env := pkg.Members["envelope"].(*canon.Object)
	full := &canon.Object{Keys: append(slices.Clone(env.Keys), "sig"), Members: map[string]canon.Value{"sig": canon.String(sig)}}
	for k, v := range env.Members {
		full.Members[k] = v
	}
	signedSt, err := wire.NewIdentityReader().Read(canon.Encode(full))
	if err != nil || !signedSt.Verified || signedSt.ID != st.ID {
		why := "it does not verify"
		if err != nil {
			why = err.Error()
		}
		return &Problem{Slug: "signature-does-not-verify", Title: "the signature does not verify over the prepared bytes", Class: refusal.Intrinsic,
			Scope: "option --signature", Detail: "checked over the PAE recomputed from the package's envelope, under signer " + st.Signer + " (" + st.Alg + "): " + why + "; nothing was appended",
			Next: "sign the package's pae bytes (base64-decoded) with the key " + st.Signer + ", unchanged, and give that signature", Peer: sig, Exit: ExitDidNotStart}
	}
	x := &extSign{complete: comp, key: &externalKey{signer: st.Signer, alg: st.Alg, sig: sig, env: env}}
	c.state = x
	var setErr *Problem
	setFlag := func(k, v string) {
		c.Flags[k] = v
		for _, f := range c.Cmd.Flags {
			if f.Name == k && f.Check != nil && setErr == nil {
				if err := f.Check(v); err != nil {
					setErr = badPackage("the package's envelope does not give a valid --"+k, err.Error(), comp, "prepare the statement again")
				}
			}
		}
	}
	setFlag("ts", st.TS.Text)
	body := st.Body
	str := func(o *canon.Object, k string) string {
		s, _ := o.Members[k].(canon.String)
		return string(s)
	}
	switch st.Kind {
	case "identity_inception":
	case "identity_grant":
		d, _ := body.Members["delegate"].(*canon.Object)
		setFlag("identity", str(body, "identity"))
		setFlag("delegate", str(d, "key"))
		setFlag("delegate-inception", str(d, "inception"))
		setFlag("permissions", string(canon.Encode(body.Members["permissions"])))
	case "identity_cut":
		setFlag("identity", str(body, "identity"))
		setFlag("grant", str(body, "grant"))
		lg := str(body, "last_good")
		if lg == "" {
			lg = lastGoodNone
		}
		setFlag("last-good", lg)
		setFlag("reason", str(body, "reason"))
	default: // an act: publish with the package's body as its draft
		plain := &canon.Object{Members: map[string]canon.Value{}}
		for _, k := range body.Keys {
			if k != wire.IdentityCrit {
				plain.Keys = append(plain.Keys, k)
				plain.Members[k] = body.Members[k]
			}
		}
		x.draft = &canon.Object{Keys: []string{"kind", "body"}, Members: map[string]canon.Value{"kind": canon.String(st.Kind), "body": plain}}
		setFlag("draft", comp)
		setFlag("as", st.Actor.Identity)
		setFlag("grant", st.Actor.Grant)
		if st.Kind == "authored" {
			setFlag("no-holds", "") // prepared without its holds (one statement per package)
		}
		if m, ok := body.Members[wire.IdentityCrit].(*canon.Object); ok {
			if a, ok := m.Members["amends"].(canon.Array); ok {
				var ids []string
				for _, v := range a {
					s, _ := v.(canon.String)
					ids = append(ids, string(s))
				}
				setFlag("amends", strings.Join(ids, ","))
			}
		}
	}
	return setErr
}

func badPackage(title, detail, path, next string) *Problem {
	return usage("malformed-package", title, detail+"; nothing was done", "option --complete", next, path)
}

var packageMembers = []string{"alg", "envelope", "format", "log_head", "pae", "signer", "statement", "summary"}

// checkPackage checks a package's shape and recomputes everything derived from its envelope: the PAE, the id,
// the alg and signer, the log head and the summary must all be what the envelope gives. It returns the envelope
// read unsigned.
func checkPackage(pkg *canon.Object, path string) (*wire.Statement, *Problem) {
	if pkg.Members["format"] != canon.String(SigningPackageFormat) {
		return nil, badPackage("not an external-signing package", "the format member is not "+SigningPackageFormat, path, "name a file written by --prepare")
	}
	keys := slices.Clone(pkg.Keys)
	slices.Sort(keys)
	if !slices.Equal(keys, packageMembers) {
		return nil, badPackage("the package's members are not the format's", "a package has exactly "+strings.Join(packageMembers, ", "), path, "name a file written by --prepare, unchanged")
	}
	env, ok := pkg.Members["envelope"].(*canon.Object)
	if !ok {
		return nil, badPackage("the package's envelope is not an object", "", path, "name a file written by --prepare, unchanged")
	}
	st, err := wire.CheckUnsigned(env)
	if err != nil {
		return nil, badPackage("the package's envelope is not a statement this tool prepares", err.Error(), path, "prepare the statement again")
	}
	if st.Status != wire.Valid {
		return nil, badPackage("the package's envelope would not be valid once signed", "it reads "+string(st.Status)+": "+st.Why, path, "prepare the statement again")
	}
	mismatch := func(member, detail string) *Problem {
		return usage("package-mismatch", "the package's "+member+" is not what its envelope gives",
			detail+"; the tool recomputes it from the envelope and never trusts the package's copy; nothing was done", "package member "+member,
			"prepare the statement again; do not edit a package", path)
	}
	paeS, _ := pkg.Members["pae"].(canon.String)
	pae, err := base64.StdEncoding.Strict().DecodeString(string(paeS))
	switch {
	case err != nil:
		return nil, mismatch("pae", "it is not standard padded base64")
	case !bytes.Equal(pae, st.SignedString):
		return nil, mismatch("pae", "it differs from the PAE recomputed from the envelope")
	case pkg.Members["statement"] != canon.String(st.ID):
		return nil, mismatch("statement", "the recomputed id is "+st.ID)
	case pkg.Members["alg"] != canon.String(st.Alg):
		return nil, mismatch("alg", "the envelope's alg is "+st.Alg)
	case pkg.Members["signer"] != canon.String(st.Signer):
		return nil, mismatch("signer", "the envelope's signer is "+st.Signer)
	case !bytes.Equal(canon.Encode(pkg.Members["log_head"]), canon.Encode(logHead(head{seq: st.Seq, prev: st.Prev}))):
		return nil, mismatch("log_head", "the envelope extends "+string(canon.Encode(logHead(head{seq: st.Seq, prev: st.Prev}))))
	case !bytes.Equal(canon.Encode(pkg.Members["summary"]), canon.Encode(summaryOf(st))):
		return nil, mismatch("summary", "a summary is a display of the envelope, never the signed payload")
	}
	return st, nil
}

var (
	reSigEd  = regexp.MustCompile(`^[0-9a-f]{128}$`)
	reSigEIP = regexp.MustCompile(`^0x[0-9a-f]{130}$`)
)

// readSignature reads --signature (a file, or - for standard input): one signature in the statement encoding of
// alg, optionally followed by one line ending. Anything else exits 2.
func readSignature(c *Ctx, arg, alg string) (string, *Problem) {
	var r io.Reader
	if arg == "-" {
		if c.Env.Stdin == nil {
			return "", usage("unreadable-file", "no standard input to read the signature from", "nothing was done", "option --signature", "give --signature <file>", "")
		}
		r = c.Env.Stdin
	} else {
		f, err := os.Open(arg)
		if err != nil {
			return "", usage("unreadable-file", "the signature file cannot be read", "nothing was done", "option --signature", "check the path", arg)
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, maxSignatureInput+1))
	if err != nil || len(b) > maxSignatureInput {
		return "", usage("malformed-signature", "the signature input is unreadable or too long", "nothing was done", "option --signature", "give the signature alone", "")
	}
	s := string(b)
	s = strings.TrimSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\r")
	ok, want := reSigEd.MatchString(s), "128 lowercase hex (64 bytes R ‖ S), no 0x"
	if alg == wire.AlgEIP191 {
		ok, want = reSigEIP.MatchString(s), "0x + 130 lowercase hex (65 bytes r ‖ s ‖ v)"
	}
	if !ok {
		return "", usage("malformed-signature", "the signature is not in the statement encoding", "an "+alg+" signature is "+want+"; nothing was done",
			"option --signature", "give the signature in that encoding", s)
	}
	return s, nil
}

// logHead is the package's log_head: "genesis" for a seq-0 line, else the line it extends.
func logHead(h head) canon.Value {
	if h.prev == "" {
		return canon.String("genesis")
	}
	return &canon.Object{Keys: []string{"seq", "statement"}, Members: map[string]canon.Value{"seq": canon.Int(h.seq - 1), "statement": canon.String(h.prev)}}
}

// summaryOf is what a human reviews before signing: who acts, for which identity, what it grants or cuts. It is
// computed from the envelope only, both when preparing and when completing.
func summaryOf(st *wire.Statement) *canon.Object {
	b := st.Body
	get := func(k string) canon.Value {
		if v, ok := b.Members[k]; ok {
			return v
		}
		return canon.Null{}
	}
	switch st.Kind {
	case "identity_inception":
		return objOf("action", canon.String("create a fixed-root identity"), "identity", canon.String(st.ID), "root", canon.String(st.Signer),
			"profile", get("profile"), "custody", canon.String("this key becomes the identity's only administrator; fixed-root-v1 has no recovery if it is lost or stolen"))
	case "identity_grant":
		d, _ := b.Members["delegate"].(*canon.Object)
		var key, inc canon.Value = canon.Null{}, canon.Null{}
		if d != nil {
			key, inc = d.Members["key"], d.Members["inception"]
		}
		return objOf("action", canon.String("grant a delegate key the right to act for the identity"), "identity", get("identity"),
			"delegate", key, "delegate_inception", inc, "permissions", get("permissions"))
	case "identity_cut":
		lg := get("last_good")
		if _, none := lg.(canon.Null); none {
			lg = canon.String("none: every act under the grant stops counting")
		}
		return objOf("action", canon.String("cut a grant"), "identity", get("identity"), "grant", get("grant"), "last_good", lg, "reason", get("reason"),
			"irreversible", canon.String("a cut cannot be undone: the delegate's acts under this grant after last_good count toward nothing for the identity, for every reader that holds the cut"))
	}
	o := objOf("action", canon.String("act for an identity: "+st.Kind), "identity", canon.String(st.Actor.Identity), "grant", canon.String(st.Actor.Grant))
	if m, ok := b.Members[wire.IdentityCrit].(*canon.Object); ok {
		if a, ok := m.Members["amends"]; ok {
			o.Keys = append(o.Keys, "amends")
			o.Members["amends"] = a
		}
	}
	return o
}

// signExternal is signAll for a key the tool does not hold. Preparing: the one draft is placed at h and checked
// unsigned, and returned with no line. Completing: the draft placed at h must be the prepared envelope (the log has
// not moved and the inputs rebuild the same statement), then it is "signed" with the given signature and read back
// as every writer's line is.
func signExternal(k *externalKey, h head, ts string, drafts []wire.Draft) ([]signed, error) {
	if len(drafts) != 1 {
		return nil, usage("external-signing-one-statement", "an external-signing package carries one statement",
			"this invocation signs "+itoa(len(drafts))+"; nothing was done", "invocation", "for authored, add --no-holds and publish the holds separately", "")
	}
	d := drafts[0]
	d.Seq, d.Prev, d.TS = h.seq, h.prev, ts
	env := d.Envelope(k)
	if k.env == nil {
		st, err := wire.CheckUnsigned(env)
		if err != nil {
			return nil, err
		}
		if st.Status != wire.Valid {
			return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: "not valid", Detail: "the statement would read " + string(st.Status) + ": " + st.Why}
		}
		return []signed{{st: st}}, nil
	}
	ph := head{seq: int64(k.env.Members["seq"].(canon.Int)), prev: prevOf(k.env)}
	if ph.seq != h.seq || ph.prev != h.prev {
		return nil, stalePrepare(ph, h)
	}
	if got, want := canon.Encode(env), canon.Encode(k.env); !bytes.Equal(got, want) {
		member := "envelope"
		for _, m := range canon.SortedKeys(k.env) {
			if !bytes.Equal(canon.Encode(k.env.Members[m]), canon.Encode(env.Members[m])) {
				member = m
				break
			}
		}
		if member == "envelope" {
			for _, m := range env.Keys {
				if _, ok := k.env.Members[m]; !ok {
					member = m
				}
			}
		}
		return nil, &Problem{Slug: "stale-prepare", Title: "refused: the statement this store would sign now is not the prepared one",
			Class: refusal.Policy, Scope: "envelope member " + member,
			Detail: "built again from the package's inputs over the statements held now, the statement differs at " + member + "; nothing was appended",
			Next:   "prepare the statement again and sign the new package", Exit: exitWriterRefused}
	}
	st, err := wire.Write(d, k, Now())
	if err != nil {
		return nil, err
	}
	if st.Status != wire.Valid {
		return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: "not valid", Detail: "the signed line reads back as " + string(st.Status)}
	}
	return []signed{{st, st.Line()}}, nil
}

func prevOf(env *canon.Object) string {
	p, _ := env.Members["prev"].(canon.String)
	return string(p)
}

func stalePrepare(prepared, now head) *Problem {
	at := func(h head) string {
		if h.prev == "" {
			return "genesis (no line)"
		}
		return "seq " + itoa(int(h.seq-1)) + " " + h.prev
	}
	return &Problem{Slug: "stale-prepare", Title: "refused: your log moved since the package was prepared", Class: refusal.Policy, Scope: "this key's log",
		Detail: "the package was prepared at " + at(prepared) + "; the next line here now goes after " + at(now) + "; the signature covers the old position, so it is not appended; nothing was appended",
		Next:   "prepare the statement again over the statements held now and sign the new package (or name the prepared line with --prev to fork deliberately)", Exit: exitWriterRefused}
}

// checkPrepared refuses a completion whose signer's log is not at the prepared head, before the command's own
// checks: the placement the command would use now (--prev honoured) must be the one the package was prepared at.
func (v *view) checkPrepared(c *Ctx, signer string) *Problem {
	x := extOf(c)
	if x == nil || x.key.env == nil {
		return nil
	}
	ph := head{seq: int64(x.key.env.Members["seq"].(canon.Int)), prev: prevOf(x.key.env)}
	h, prob := v.placeLine(c, signer)
	if prob != nil {
		return prob
	}
	if h.seq != ph.seq || h.prev != ph.prev {
		return stalePrepare(ph, h)
	}
	return nil
}

// preparedResult writes the package for the one prepared statement s and prints what it says. Nothing is appended.
func preparedResult(c *Ctx, out *Obj, s signed, h head) (*Obj, int, error) {
	x := extOf(c)
	sum := summaryOf(s.st)
	pkg := objOf("format", canon.String(SigningPackageFormat), "envelope", envelopeOf(s.st),
		"pae", canon.String(base64.StdEncoding.EncodeToString(s.st.SignedString)), "alg", canon.String(s.st.Alg), "signer", canon.String(s.st.Signer),
		"statement", canon.String(s.st.ID), "log_head", logHead(h), "summary", sum)
	f, err := os.OpenFile(x.prepare, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, 0, usage("package-exists", "the package file already exists", "a package is never overwritten; nothing was done", "option --prepare", "name a new file", x.prepare)
		}
		return nil, 0, failed(err, "option --prepare", false, "check the directory, then run the command again")
	}
	_, werr := f.Write(append(canon.Encode(pkg), '\n'))
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(x.prepare)
		return nil, 0, failed(werr, "option --prepare", false, "check free space, then run the command again")
	}
	sum2 := sha256.Sum256(s.st.SignedString)
	out.set("prepared", peerV(x.prepare)).set("format", textV(SigningPackageFormat)).set("statement", refV(s.st.ID)).
		set("kind", peerV(s.st.Kind)).set("signer", refV(s.st.Signer)).set("alg", textV(s.st.Alg)).set("seq", intV(s.st.Seq)).
		set("ts_signer_declared", refV(s.st.TS.Text)).set("log_head", rawV{logHead(h)}).
		set("pae_sha256", refV(hex.EncodeToString(sum2[:]))).set("pae_bytes", intV(int64(len(s.st.SignedString)))).
		set("summary", rawV{sum}).set("committed", boolV(false)).
		set("next", textV("review the summary; sign the package's pae bytes (base64-decoded, unchanged) with "+s.st.Signer+" ("+s.st.Alg+"); then run this command with --complete "+x.prepare+" --signature <file|->"))
	return out, ExitOK, nil
}

// envelopeOf is the unsigned envelope of a statement read by wire.CheckUnsigned.
func envelopeOf(st *wire.Statement) canon.Value {
	full, _ := canon.Parse(st.Line())
	o := full.(*canon.Object)
	env := &canon.Object{Members: map[string]canon.Value{}}
	for _, k := range o.Keys {
		if k != "sig" {
			env.Keys = append(env.Keys, k)
			env.Members[k] = o.Members[k]
		}
	}
	return env
}
