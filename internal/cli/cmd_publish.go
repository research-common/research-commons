package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/rctime"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// publish: the writer path (claims-model note §8, §11, §13; storage note §3.1, §3.2). One invocation signs one
// atomic unit with the invocation's key and commits it through the store's journal: `authored` (+ `holds`
// when this store keeps the bytes) with the blob, or a `holds`, `describes` or `retracts`, or a draft of any
// kind §5 lists. `publish task` is genesis + first edition, or a new edition of a task the key controls.
//
// Order: every input checked (exit 2, nothing done) → the key's log read from the store (seq, prev; a fork
// is refused, never rebased) → the pre-pin check `intended_for` names (refuses on fail, records ok or
// unchecked) → signed through wire.Write (future ts refused; the line read back through the one validation
// core) → --dry-run stops here → the blob installed, then the statements committed as one journal record.

// Now is the writer's clock (the ts default and the future-skew bound). Tests replace it.
var Now = time.Now

// ruleDialects are the rule dialects the publisher's pre-pin check compiles edition rules with. No dialect
// ships (none is specified, claims-model note §8): a rule in an unknown dialect evaluates to unchecked, so
// production records `unchecked`, never `ok`, for any edition with rules. Tests add one.
var ruleDialects []resolve.Dialect

// maxScan bounds the bytes the pre-pin content reader reads per blob; past it the unit is unscanned (I15).
const maxScan = 64 << 20

// publishDisclosures maps each `authored` disclosure (run.Disclosure, wire §5) to its flag and value shape.
// intended_for is the pre-pin request (--intended-for <resource>/<edition>), not a value.
var publishDisclosures = []struct{ Field, Shape string }{
	{"attribution", "text"}, {"availability", "object"}, {"comparator", "digest"}, {"description", "text"},
	{"extends", "digest"}, {"fulfills", "object"}, {"intended_for", "pre-pin"}, {"licence", "text"},
	{"licence_texts", "object"}, {"pre_registration", "text"}, {"replication", "text"}, {"sampling", "object"},
	{"shelf_life_days", "integer"}, {"supersedes", "digest"},
}

func flagOf(field string) string { return strings.ReplaceAll(field, "_", "-") }

func checkJSONObject(v string) error {
	o, err := canon.Parse([]byte(v))
	if err != nil {
		return errors.New("not strict JSON")
	}
	if _, ok := o.(*canon.Object); !ok {
		return errors.New("not a JSON object")
	}
	return nil
}

func checkDigestFlag(v string) error {
	if !isDigest(v) {
		return errors.New("not a content digest (sha256:<64 lowercase hex>)")
	}
	return nil
}

func checkIDFlag(v string) error {
	if !isID(v) {
		return errors.New("not a statement id (64 lowercase hex)")
	}
	return nil
}

func checkInt(v string) error {
	if _, err := strconv.ParseInt(v, 10, 64); err != nil {
		return errors.New("not an integer")
	}
	return nil
}

func checkTS(v string) error {
	if _, err := rctime.ParseUTC(v); err != nil {
		return errors.New("not an RFC 3339 UTC time (…Z)")
	}
	return nil
}

func checkIntendedFor(v string) error {
	r, e, ok := strings.Cut(v, "/")
	if !ok || !isID(r) || !isID(e) {
		return errors.New("not <resource id>/<edition id>")
	}
	return nil
}

var writerFlags = []Flag{
	{Name: "key", Value: "file", Help: "the signing key file (else $" + KeyEnv + "); there is no default"},
	{Name: "prev", Value: "id", Help: "the line of your log to extend; needed when your log has a FORK, and makes a fork when it is not a tip", Check: checkIDFlag},
	{Name: "ts", Value: "time", Help: "the signer-declared time (RFC 3339 UTC); default now; more than 300 s ahead is refused", Check: checkTS},
	{Name: "dry-run", Help: "print what would be signed and committed, sign nothing, write nothing"},
}

func init() {
	flags := slices.Clone(writerFlags)
	flags = append(flags,
		Flag{Name: "draft", Value: "file", Help: "a JSON draft {\"kind\":…,\"body\":{…}}; the tool fills signer, seq, prev, ts and sig"},
		Flag{Name: "kind", Value: "kind", Help: "authored, holds, describes or retracts (without --draft)", Check: func(v string) error {
			if !slices.Contains([]string{"authored", "holds", "describes", "retracts"}, v) {
				return errors.New("publish builds authored, holds, describes or retracts from flags; use --draft for another kind")
			}
			return nil
		}},
		Flag{Name: "content", Value: "file", Help: "the bytes the statement is about; installed in the store with the statements"},
		Flag{Name: "media-type", Value: "type", Help: "content.media_type"},
		Flag{Name: "type", Value: "type", Help: "authored type (default dataset)"},
		Flag{Name: "provenance", Value: "json", Help: "authored provenance object {workflow, inputs[, environment]}", Check: checkJSONObject},
		Flag{Name: "no-holds", Help: "authored only: keep the bytes in the store but write no holds (a withheld artifact)"},
		Flag{Name: "about", Value: "digest|id", Help: "describes: the blob or statement described", Check: func(v string) error {
			if !isDigest(v) && !isID(v) {
				return errors.New("not a digest or a statement id")
			}
			return nil
		}},
		Flag{Name: "note", Value: "text", Help: "describes: the note"},
		Flag{Name: "of", Value: "id", Help: "retracts: the statement retracted", Check: checkIDFlag},
		Flag{Name: "reason", Value: "text", Help: "retracts: the reason"},
	)
	for _, d := range publishDisclosures {
		f := Flag{Name: flagOf(d.Field), Value: d.Shape, Help: "authored disclosure " + d.Field}
		switch d.Shape {
		case "object":
			f.Value, f.Check = "json", checkJSONObject
		case "digest":
			f.Check = checkDigestFlag
		case "integer":
			f.Check = checkInt
		case "pre-pin":
			f.Value, f.Check = "resource/edition", checkIntendedFor
			f.Help = "run the edition's rules on the bytes before they are pinned (your own policy, chosen by naming the edition); fail refuses, ok or unchecked is recorded"
		}
		flags = append(flags, f)
	}
	Register(&Command{Name: "publish", Summary: "sign and commit a statement (authored with its bytes, holds, describes, retracts, or a draft)",
		Store: true, Writes: true, Flags: flags, Prepare: preparePublish, Run: publishCmd,
		Help: "Signs with --key (or $" + KeyEnv + ") and commits through the store's journal: the blob and its statements land together or not at all. A draft is never stored unsigned. Your log's next seq and prev come from the statements this store holds; a FORK in your log is refused until you name --prev. --intended-for runs the named edition's rules first and refuses on fail."})
	tflags := append(slices.Clone(writerFlags),
		Flag{Name: "name", Value: "text", Help: "a new task's name"},
		Flag{Name: "task", Value: "id", Help: "an existing task (its genesis id): publish a new edition after its current one", Check: checkIDFlag},
		Flag{Name: "contract", Value: "file", Help: "the edition's contract, a JSON object (the contract grammar is provisional)"},
	)
	Register(&Command{Name: "publish task", Summary: "create a task (genesis + first edition) or publish a new edition of one",
		Store: true, Writes: true, Flags: tflags, Prepare: preparePublishTask, Run: publishTaskCmd,
		Help: "A new task: --name and --contract; your key is its one controller (any one approves). A new edition: --task and --contract. Prints how the edition will be settled: by counting (its quorum), or by review when the contract has no quorum predicate, or readiness unchecked when this reader cannot read the contract."})
}

// pubPrep is what Prepare read.
type pubPrep struct {
	key     *loadedKey
	kind    string
	body    *canon.Object // the draft body, without content when --content fills it
	content string        // the content file, "" when none
	ts      string
	// intended is the pre-pin request: resource and edition ids.
	resource, edition string
	holds             bool
	// task
	taskName, taskID string
	contract         *canon.Object
}

func readJSONFile(path, scope string) (*canon.Object, *Problem) {
	f, err := os.Open(path)
	if err != nil {
		return nil, usage("unreadable-file", "a file named on the command line cannot be read", "nothing was done", scope, "check the path", path)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return nil, usage("unreadable-file", "a file named on the command line cannot be read or is over 1 MiB", "nothing was done", scope, "check the file", path)
	}
	v, err := canon.Parse(bytes.TrimRight(b, "\n"))
	o, ok := v.(*canon.Object)
	if err != nil || !ok {
		return nil, usage("malformed-file", "a file named on the command line is not a strict JSON object", "nothing was done", scope,
			"fix the file (strict JSON: no duplicate keys, integers only)", path)
	}
	return o, nil
}

func newBody() *canon.Object { return &canon.Object{Members: map[string]canon.Value{}} }

func setMember(o *canon.Object, k string, v canon.Value) {
	if _, ok := o.Members[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.Members[k] = v
}

// prepareCommon loads the key and the ts: the inputs every writer has.
func prepareCommon(c *Ctx, p *pubPrep) *Problem {
	k, prob := signingKey(c)
	if prob != nil {
		return prob
	}
	p.key = k
	ts, given := c.Flag("ts")
	if !given {
		ts = Now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	}
	p.ts = ts
	// the write-time bound (wire §2, C-core-105), checked before any work; wire.Write checks it again at signing
	t, _ := rctime.ParseUTC(ts)
	limit := Now().Add(wire.MaxFutureSkew)
	if rctime.Compare(t, rctime.Time{Sec: limit.Unix(), Nanos: int32(limit.Nanosecond())}) > 0 {
		return &Problem{Slug: "future-timestamp", Title: "refused: future timestamp", Class: refusal.Policy, Scope: "this statement",
			Detail: "ts is more than 300 s ahead of the writer's clock (writer policy: max future skew 300 s); nothing was signed or appended",
			Next:   "give a ts no later than now, or check the system clock", Peer: ts, Exit: ExitDidNotStart}
	}
	return nil
}

func preparePublish(c *Ctx) *Problem {
	p := &pubPrep{}
	_, hasDraft := c.Flag("draft")
	kind, hasKind := c.Flag("kind")
	var bodyFlags []string
	for _, f := range c.Cmd.Flags {
		if _, ok := c.Flags[f.Name]; ok && !slices.ContainsFunc(writerFlags, func(w Flag) bool { return w.Name == f.Name }) &&
			!slices.Contains([]string{"draft", "kind", "content", "intended-for", "no-holds"}, f.Name) {
			bodyFlags = append(bodyFlags, f.Name)
		}
	}
	switch {
	case hasDraft == hasKind:
		return usage("missing-argument", "give exactly one of --draft and --kind", "nothing was done", "invocation",
			"commons publish --kind authored --content <file> --key <file>, or commons publish --draft <file> --key <file>", "")
	case hasDraft && len(bodyFlags) > 0:
		return usage("malformed-argument", "a draft carries its own body", "body options cannot be combined with --draft; nothing was done",
			"option --"+bodyFlags[0], "put the field in the draft, or publish from options without --draft", "")
	}
	if hasDraft {
		path, _ := c.Flag("draft")
		d, prob := readJSONFile(path, "option --draft")
		if prob != nil {
			return prob
		}
		for _, k := range d.Keys {
			if k != "kind" && k != "body" {
				return usage("malformed-draft", "a draft carries kind and body only",
					"the tool fills signer, alg, seq, prev, ts and sig at signing (and ts comes from --ts); nothing was done", "draft field "+k,
					"remove the field from the draft", k)
			}
		}
		kv, ok1 := d.Members["kind"].(canon.String)
		bv, ok2 := d.Members["body"].(*canon.Object)
		if !ok1 || !ok2 {
			return usage("malformed-draft", "a draft needs a kind (string) and a body (object)", "nothing was done", "option --draft",
				"fix the draft", path)
		}
		kind, p.body = string(kv), bv
		if !wireKind(kind) {
			return usage("malformed-draft", "the draft's kind is not a kind the format lists",
				"a statement of an unknown kind grants nothing; this writer does not sign one; nothing was done", "draft field kind",
				"use a kind of wire-format note §5", kind)
		}
		if slices.Contains([]string{"genesis", "edition"}, kind) {
			if t, ok := bv.Members["type"].(canon.String); kind == "genesis" && ok && t == "task" {
				return usage("malformed-draft", "use publish task for a task", "a task's genesis and first edition are one unit; nothing was done",
					"draft field kind", "commons publish task --name <name> --contract <file>", "")
			}
		}
		if iv, ok := bv.Get("intended_for"); ok {
			io, ok := iv.(*canon.Object)
			r, _ := io.Members["resource"].(canon.String)
			e, _ := io.Members["edition"].(canon.String)
			if !ok || !isID(string(r)) || !isID(string(e)) {
				return usage("malformed-draft", "intended_for needs resource and edition ids", "nothing was done", "draft field intended_for",
					"name the resource and edition", "")
			}
			p.resource, p.edition = string(r), string(e)
		}
	} else {
		p.body = newBody()
		switch kind {
		case "authored":
			t, ok := c.Flag("type")
			if !ok {
				t = "dataset"
			}
			setMember(p.body, "type", canon.String(t))
			for _, d := range publishDisclosures {
				v, ok := c.Flag(flagOf(d.Field))
				if !ok || d.Shape == "pre-pin" {
					continue
				}
				switch d.Shape {
				case "text", "digest":
					setMember(p.body, d.Field, canon.String(v))
				case "integer":
					n, _ := strconv.ParseInt(v, 10, 64)
					setMember(p.body, d.Field, canon.Int(n))
				case "object":
					o, _ := canon.Parse([]byte(v))
					setMember(p.body, d.Field, o)
				}
			}
			if v, ok := c.Flag("provenance"); ok {
				o, _ := canon.Parse([]byte(v))
				setMember(p.body, "provenance", o)
			}
			if _, ok := c.Flag("content"); !ok {
				return usage("missing-argument", "authored needs the bytes", "give --content <file>; nothing was done", "option --content",
					"commons publish --kind authored --content <file>", "")
			}
		case "holds":
			if _, ok := c.Flag("content"); !ok {
				return usage("missing-argument", "holds needs the bytes", "give --content <file>; nothing was done", "option --content",
					"commons publish --kind holds --content <file>", "")
			}
		case "describes":
			about, ok := c.Flag("about")
			if !ok {
				return usage("missing-argument", "describes needs --about", "nothing was done", "option --about", "name a digest or a statement id", "")
			}
			k := "statement"
			if isDigest(about) {
				k = "content"
			}
			setMember(p.body, "about", &canon.Object{Keys: []string{k}, Members: map[string]canon.Value{k: canon.String(about)}})
			if n, ok := c.Flag("note"); ok {
				setMember(p.body, "note", canon.String(n))
			}
		case "retracts":
			of, ok := c.Flag("of")
			if !ok {
				return usage("missing-argument", "retracts needs --of", "nothing was done", "option --of", "name the statement retracted", "")
			}
			setMember(p.body, "of", canon.String(of))
			if r, ok := c.Flag("reason"); ok {
				setMember(p.body, "reason", canon.String(r))
			}
		}
		// options that belong to another kind are refused, not ignored
		own := map[string][]string{"authored": {"type", "provenance", "media-type", "no-holds"}, "holds": {"media-type"},
			"describes": {"about", "note"}, "retracts": {"of", "reason"}}
		for _, f := range bodyFlags {
			if !slices.Contains(own[kind], f) && !(kind == "authored" && slices.ContainsFunc(publishDisclosures, func(d struct{ Field, Shape string }) bool { return flagOf(d.Field) == f })) {
				return usage("malformed-argument", "an option does not apply to this kind", "nothing was done", "option --"+f,
					"drop it, or publish the kind it belongs to", kind)
			}
		}
		if _, ok := c.Flag("no-holds"); ok && kind != "authored" {
			return usage("malformed-argument", "an option does not apply to this kind", "nothing was done", "option --no-holds", "drop it", kind)
		}
	}
	p.kind = kind
	if v, ok := c.Flag("intended-for"); ok {
		if kind != "authored" && kind != "observed" {
			return usage("malformed-argument", "intended_for applies to authored and observed only", "nothing was done", "option --intended-for",
				"drop it", kind)
		}
		p.resource, p.edition, _ = strings.Cut(v, "/")
	}
	if path, ok := c.Flag("content"); ok {
		if kind != "authored" && kind != "holds" && kind != "observed" && kind != "reproduced" {
			return usage("malformed-argument", "this kind is not about bytes", "--content applies to authored, holds, observed and reproduced; nothing was done",
				"option --content", "drop --content", kind)
		}
		fi, err := os.Stat(path)
		if err != nil || !fi.Mode().IsRegular() {
			return usage("unreadable-file", "the content file cannot be read", "nothing was done", "option --content", "check the path", path)
		}
		f, err := os.Open(path)
		if err != nil {
			return usage("unreadable-file", "the content file cannot be read", "nothing was done", "option --content", "check its permissions", path)
		}
		f.Close()
		p.content = path
	}
	_, noHolds := c.Flag("no-holds")
	p.holds = kind == "authored" && !noHolds
	if prob := prepareCommon(c, p); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

// wireKind reports whether kind is a statement kind wire-format note §5 lists (the writer signs no other).
func wireKind(kind string) bool {
	return slices.Contains([]string{"authored", "observed", "holds", "describes", "reproduced", "corroborates", "refutes", "retracts",
		"anchors", "genesis", "edition", "intent", "withdraw", "progress", "submit", "decide", "withdraw_approval", "rotate_key", "revoke_key"}, kind)
}

func preparePublishTask(c *Ctx) *Problem {
	p := &pubPrep{kind: "task"}
	name, hasName := c.Flag("name")
	task, hasTask := c.Flag("task")
	if hasName == hasTask {
		return usage("missing-argument", "give exactly one of --name (a new task) and --task (a new edition)", "nothing was done", "invocation",
			"commons publish task --name <name> --contract <file>", "")
	}
	path, ok := c.Flag("contract")
	if !ok {
		return usage("missing-argument", "a task edition needs its contract", "give --contract <file>; nothing was done", "option --contract",
			"write the contract as a JSON object", "")
	}
	ct, prob := readJSONFile(path, "option --contract")
	if prob != nil {
		return prob
	}
	p.taskName, p.taskID, p.contract = name, task, ct
	if prob := prepareCommon(c, p); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

// --- the key's log -------------------------------------------------------------------------------------------

// head is where the next line of the signer's log goes.
type head struct {
	seq  int64
	prev string
	fork bool // the chosen prev is not a tip: this line makes a fork
}

func (v *view) nextLine(c *Ctx, signer string) (head, *Problem) {
	lv := v.logs.Log(signer).View()
	placed := map[string]keylog.Line{}
	for _, l := range lv.Lines {
		placed[l.St.ID] = l
	}
	if prev, ok := c.Flag("prev"); ok {
		l, held := placed[prev]
		if !held || l.State != keylog.Chained {
			return head{}, &Problem{Slug: "prev-not-held", Title: "the line named by --prev is not a chained line of your log here",
				Class: refusal.Policy, Scope: "option --prev", Detail: "nothing was signed or appended",
				Next: "name a chained line of this key's log (commons show <id>), or omit --prev", Peer: prev, Exit: ExitCouldNot}
		}
		return head{seq: l.St.Seq + 1, prev: prev, fork: !slices.Contains(lv.Tips, prev)}, nil
	}
	switch {
	case len(lv.Lines) == 0 && len(lv.Retained) == 0:
		return head{}, nil
	case len(lv.Tips) == 1:
		return head{seq: placed[lv.Tips[0]].St.Seq + 1, prev: lv.Tips[0]}, nil
	case len(lv.Tips) > 1:
		return head{}, &Problem{Slug: "log-fork", Title: "your log has a FORK", Class: refusal.Policy, Scope: "this key's log",
			Detail: "this store holds " + strconv.Itoa(len(lv.Tips)) + " tips of this key's log (" + shortList(lv.Tips) +
				"); the writer does not pick one or merge them silently; nothing was signed or appended",
			Next: "name the line to extend with --prev <id> (commons show <id> for each tip)", Exit: ExitCouldNot}
	}
	return head{}, &Problem{Slug: "log-detached", Title: "your log's first line is not held here", Class: refusal.Policy, Scope: "this key's log",
		Detail: "this store holds lines of this key, none chained to the first; the next seq is unknown; nothing was signed or appended",
		Next:   "fetch the key's earlier lines, or name --prev <id>", Exit: ExitCouldNot}
}

func shortList(ids []string) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = keylog.Short(id)
	}
	return strings.Join(s, ", ")
}

// --- content ------------------------------------------------------------------------------------------------

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), n, nil
}

// prepinContent gives edition rules the bytes: the draft's own file for its digest (not installed yet: a refused
// draft leaves nothing behind), the store's blobs otherwise. A whole blob is one unit: no archive is opened.
type prepinContent struct {
	st     *store.Store
	digest string
	file   string
}

func (p prepinContent) Units(d string) ([]resolve.ContentUnit, bool) {
	var r io.ReadCloser
	if d == p.digest && p.file != "" {
		f, err := os.Open(p.file)
		if err != nil {
			return nil, false
		}
		r = f
	} else {
		f, err := p.st.OpenBlob(store.Digest(d))
		if err != nil {
			return nil, false
		}
		r = f
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, maxScan+1))
	if err != nil {
		return nil, false
	}
	if len(b) > maxScan {
		return []resolve.ContentUnit{{Name: keylog.Short(strings.TrimPrefix(d, "sha256:")), Unscanned: "size limit=" + strconv.Itoa(maxScan)}}, true
	}
	return []resolve.ContentUnit{{Name: keylog.Short(strings.TrimPrefix(d, "sha256:")), Data: b}}, true
}

// --- run ----------------------------------------------------------------------------------------------------

// signed is one statement ready to commit.
type signed struct {
	st   *wire.Statement
	line []byte
}

func signAll(k wire.Key, h head, ts string, drafts []wire.Draft) ([]signed, error) {
	var out []signed
	prev, seq := h.prev, h.seq
	for _, d := range drafts {
		d.Seq, d.Prev, d.TS = seq, prev, ts
		st, err := wire.Write(d, k, Now())
		if err != nil {
			return nil, err
		}
		if st.Status != wire.Valid {
			return nil, &refusal.Refusal{Class: refusal.Intrinsic, Reason: "not valid", Detail: "the signed line reads back as " + string(st.Status)}
		}
		out = append(out, signed{st, st.Line()})
		prev, seq = st.ID, seq+1
	}
	return out, nil
}

// writeRefused is a refusal from signing (the body fails §5, a future ts): nothing appended.
func writeRefused(err error) *Problem {
	p := &Problem{Slug: "refused", Title: "the statement was not signed", Class: refusal.Intrinsic, Scope: "this statement",
		Detail: "the body or envelope fails a rule every reader applies; its text is in peer_text; nothing was signed or appended",
		Next:   "fix the named field and run the command again", Peer: err.Error(), Exit: ExitDidNotStart}
	var r *refusal.Refusal
	if errors.As(err, &r) {
		p.Class = r.Class
		p.Title = "refused: " + r.Reason
	}
	return p
}

func publishCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*pubPrep)
	var opts []resolve.Option
	for _, d := range ruleDialects {
		opts = append(opts, resolve.WithDialect(d))
	}
	digest, size := "", int64(0)
	if p.content != "" {
		var err error
		if digest, size, err = hashFile(p.content); err != nil {
			return nil, 0, failed(err, "option --content", false, "check the file and run the command again")
		}
	}
	opts = append(opts, resolve.WithContent(prepinContent{st: c.Store, digest: digest, file: p.content}))
	v, err := loadView(c.Store, nil, opts...)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run status, then fsck")
	}
	signer := p.key.Key.Signer()
	h, prob := v.nextLine(c, signer)
	if prob != nil {
		return nil, 0, prob
	}
	body := p.body
	if digest != "" {
		co := &canon.Object{Keys: []string{"digest", "size"}, Members: map[string]canon.Value{"digest": canon.String(digest), "size": canon.Int(size)}}
		if mt, ok := c.Flag("media-type"); ok {
			setMember(co, "media_type", canon.String(mt))
		}
		if have, ok := body.Get("content"); ok {
			ho, _ := have.(*canon.Object)
			if ho == nil || ho.Members["digest"] != canon.String(digest) {
				return nil, 0, usage("content-mismatch", "the draft's content digest is not the digest of --content", "nothing was signed or appended",
					"draft field content", "give the file the draft names, or drop content from the draft", digest)
			}
		} else {
			setMember(body, "content", co)
		}
	} else if d := contentOf(&wire.Statement{Body: body}); d != "" && (p.kind == "authored" || p.kind == "holds") && !c.Store.HasBlob(store.Digest(d)) {
		return nil, 0, usage("content-not-held", "the bytes the draft names are not in this store",
			"publishing authored or holds installs the bytes with the statements (storage note §3.2); nothing was signed or appended",
			"draft field content", "give the bytes with --content <file>", d)
	}
	if d := contentOf(&wire.Statement{Body: body}); d != "" {
		digest = d
	}
	out := newObj()
	// the pre-pin check (claims-model note §8): the publisher's own policy, chosen by naming the edition
	if p.resource != "" {
		pp, err := v.r.CheckIntendedFor(body, p.resource, p.edition)
		if err != nil {
			return nil, 0, prepinRefused(err, p)
		}
		body = pp.Body
		pin := newObj().set("resource", refV(pp.Resource)).set("edition", refV(pp.Edition)).set("state", tokV(tok(string(pp.Outcome))))
		var why []string
		for _, e := range pp.Evals {
			why = append(why, e.String())
		}
		if len(why) > 0 {
			pin.set("evaluations", texts(why...))
		}
		if pp.Outcome == resolve.RuleUnchecked {
			pin.set("note", textV("a rule could not finish; the statement records unchecked, never ok, and a reader re-applies the rules itself"))
		}
		out.set("intended_for", pin)
	}
	drafts := []wire.Draft{{Kind: p.kind, Body: body}}
	if p.holds {
		hb := &canon.Object{Keys: []string{"content"}, Members: map[string]canon.Value{"content": body.Members["content"]}}
		drafts = append(drafts, wire.Draft{Kind: "holds", Body: hb})
	}
	sts, err := signAll(p.key.Key, h, p.ts, drafts)
	if err != nil {
		return nil, 0, writeRefused(err)
	}
	var blobs []store.Digest
	if digest != "" && (p.content != "" || c.Store.HasBlob(store.Digest(digest))) {
		blobs = append(blobs, store.Digest(digest))
	}
	return commitUnit(c, out, "publish", sts, blobs, p.content, h)
}

func prepinRefused(err error, p *pubPrep) *Problem {
	var r *refusal.Refusal
	if !errors.As(err, &r) {
		return failed(err, "this statement", false, "run the command again")
	}
	pr := &Problem{Slug: "refused", Title: "refused: " + r.Reason, Class: r.Class, Scope: "this statement", Peer: r.Detail}
	switch r.Reason {
	case resolve.EditionNotHeld:
		pr.Detail = "the edition --intended-for names is not held here, so its rules cannot run; the statement is never written with outcome ok; nothing was pinned or appended"
		pr.Next = "fetch resource " + p.resource + " (edition " + p.edition + "), then publish again"
		pr.Exit = ExitCouldNot
	case resolve.RuleFailed:
		pr.Detail = "the named edition's rules fail these bytes (your own policy, chosen by naming the edition); nothing was pinned or appended"
		pr.Next = "change the bytes, or drop --intended-for if they are not meant for that edition"
		pr.Exit = ExitWrong
	default:
		pr.Detail = "the pre-pin check could not run; nothing was pinned or appended"
		pr.Next = "see peer_text"
		pr.Exit = ExitCouldNot
	}
	return pr
}

// commitUnit prints a dry run, or installs the blob and commits the statements as one journal record.
func commitUnit(c *Ctx, out *Obj, op string, sts []signed, blobs []store.Digest, content string, h head) (*Obj, int, error) {
	l := listV{}
	var lines [][]byte
	for _, s := range sts {
		so := newObj().set("statement", refV(s.st.ID)).set("kind", peerV(s.st.Kind)).set("signer", refV(s.st.Signer)).
			set("seq", intV(s.st.Seq)).set("ts_signer_declared", refV(s.st.TS.Text))
		if s.st.Prev != "" {
			so.set("prev", refV(s.st.Prev))
		}
		if _, dry := c.Flag("dry-run"); dry {
			so.set("body", rawV{s.st.Body})
		}
		l = append(l, so)
		lines = append(lines, s.line)
	}
	out.set("statements", l)
	if h.fork {
		out.set("line", tokV(tok("FORK"))).set("fork_note", textV("--prev names a line that is not a tip of your log: this line makes a FORK; readers show both"))
	}
	var effects []string
	for _, b := range blobs {
		if c.Store.HasBlob(b) {
			effects = append(effects, "blob "+string(b)+" already held")
		} else {
			effects = append(effects, "install blob "+string(b))
		}
	}
	effects = append(effects, "append "+strconv.Itoa(len(sts))+" statement(s) to "+sts[0].st.Signer+"'s log in one journal record")
	if _, dry := c.Flag("dry-run"); dry {
		out.set("dry_run", boolV(true)).set("committed", boolV(false)).set("would", texts(effects...)).
			set("note", textV("dry run: the ids above are of signatures that were discarded; nothing was written"))
		return out, ExitOK, nil
	}
	for _, b := range blobs {
		if c.Store.HasBlob(b) {
			continue
		}
		f, err := os.Open(content)
		if err != nil {
			return nil, 0, failed(err, "option --content", false, "check the file and run the command again")
		}
		_, _, err = c.Store.InstallBlob(f, b)
		f.Close()
		if err != nil {
			return nil, 0, failed(err, "option --content", false, "the file changed while publishing? run the command again")
		}
	}
	res, err := c.Store.Commit(op, lines, blobs)
	if err != nil {
		if res.Committed {
			ids := make([]string, len(sts))
			for i, s := range sts {
				ids[i] = s.st.ID
			}
			return nil, 0, &Problem{Slug: "committed-pending-install", Title: "committed, pending install", Class: refusal.Operational,
				Scope: "operation " + res.Op, Committed: true,
				Detail: "the operation reached its commit point (journal record " + res.Op + ", statements " + strings.Join(ids, ", ") +
					") and installing its statements failed; the record is kept and the next open of this store replays it; the error is in peer_text",
				Next: "fix the cause in peer_text, then run commons status (any command that opens the store finishes the install); do not publish again",
				Peer: err.Error(), Exit: ExitCouldNot}
		}
		return nil, 0, failed(err, "store", false, "nothing was committed; run the command again")
	}
	out.set("committed", boolV(true)).set("operation", refV(res.Op)).set("did", texts(effects...))
	if res.NeedsRepair != nil {
		out.set("store_state", tokV(tok("committed, needs repair"))).set("repair", peerV(res.NeedsRepair.Error()))
	}
	return out, ExitOK, nil
}

// --- publish task -------------------------------------------------------------------------------------------

func publishTaskCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*pubPrep)
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	signer := p.key.Key.Signer()
	h, prob := v.nextLine(c, signer)
	if prob != nil {
		return nil, 0, prob
	}
	contents := &canon.Object{Keys: []string{"contract"}, Members: map[string]canon.Value{"contract": p.contract}}
	var drafts []wire.Draft
	if p.taskName != "" {
		g := &canon.Object{Members: map[string]canon.Value{"type": canon.String("task"), "name": canon.String(p.taskName),
			"controllers": canon.Array{canon.String(signer)}, "rule": &canon.Object{Keys: []string{"any_one"}, Members: map[string]canon.Value{"any_one": canon.Bool(true)}}},
			Keys: []string{"controllers", "name", "rule", "type"}}
		drafts = append(drafts, wire.Draft{Kind: "genesis", Body: g})
	} else {
		t, ok := v.r.Task(p.taskID)
		switch {
		case !ok:
			return nil, 0, &Problem{Slug: "task-not-held", Title: "the task is not held here", Class: refusal.Policy, Scope: "option --task",
				Detail: "no task genesis with that id is in this store; nothing was signed or appended", Next: "fetch the task, then publish again",
				Peer: p.taskID, Exit: ExitCouldNot}
		case t.Current == "":
			return nil, 0, &Problem{Slug: "task-fork", Title: "the task has no current edition", Class: refusal.Policy, Scope: "option --task",
				Detail: "its editions FORK (" + shortList(t.Tips) + "); a new edition after one tip would not settle that; nothing was signed or appended",
				Next:   "merge the tips by an edition naming them all (a draft), then publish again", Exit: ExitCouldNot}
		}
	}
	// the first edition's predecessor is the genesis; its id is known only after signing, so sign in two steps
	sts, err := signAll(p.key.Key, h, p.ts, drafts)
	if err != nil {
		return nil, 0, writeRefused(err)
	}
	task, pred := p.taskID, ""
	if p.taskName != "" {
		task, pred = sts[0].st.ID, sts[0].st.ID
	} else {
		t, _ := v.r.Task(p.taskID)
		pred = t.Current
	}
	eb := &canon.Object{Keys: []string{"contents", "predecessors", "resource"}, Members: map[string]canon.Value{
		"resource": canon.String(task), "predecessors": canon.Array{canon.String(pred)}, "contents": contents}}
	eh := h
	if len(sts) > 0 {
		eh = head{seq: sts[0].st.Seq + 1, prev: sts[0].st.ID, fork: h.fork}
	}
	es, err := signAll(p.key.Key, eh, p.ts, []wire.Draft{{Kind: "edition", Body: eb}})
	if err != nil {
		return nil, 0, writeRefused(err)
	}
	sts = append(sts, es...)
	edition := resolve.EditionID(eb)

	// how the edition will be settled: the reader's own resolution of the store plus these lines
	out := newObj().set("task", refV(task)).set("edition", refV(edition))
	rd, state, why := v.readinessWith(c, sts, task, edition)
	if state != string(resolve.Authorized) {
		return nil, 0, &Problem{Slug: "edition-not-authorized", Title: "the edition would not be authorized", Class: refusal.Policy,
			Scope: "this statement", Detail: "resolved with the statements this store holds, the new edition's state is " + strconv.Quote(state) +
				" (only a controller's approval authorizes an edition); nothing was signed or appended",
			Next: "publish with a controller's key", Peer: why, Exit: ExitCouldNot}
	}
	out.set("readiness", rd)
	return commitUnit(c, out, "publish", sts, nil, "", h)
}

// readinessWith resolves the task with the new lines added and reports the new edition's readiness: how it will
// be settled (by counting a quorum, by review, or unchecked when the contract cannot be read).
func (v *view) readinessWith(c *Ctx, sts []signed, task, edition string) (*Obj, string, string) {
	lines, _ := c.Store.Statements()
	logs := keylog.NewStore()
	add := func(l []byte) {
		if st, err := wire.Read(l); err == nil {
			logs.Log(st.Signer).Add(l)
		}
	}
	for _, l := range lines {
		add(l)
	}
	for _, s := range sts {
		add(s.line)
	}
	r := resolve.New(logs, resolve.WithContractReader(resolve.ProvisionalContract{}))
	t, ok := r.Task(task)
	if !ok {
		return nil, "not held", "the task does not resolve"
	}
	b, ok := t.Bindings[edition]
	if !ok {
		for _, e := range t.Editions {
			if e.ID == edition {
				return nil, string(e.State), strings.Join(e.Explain, "; ")
			}
		}
		return nil, "not held", "the edition does not resolve"
	}
	o := newObj()
	for _, rd := range t.Readiness {
		if rd.Edition != edition {
			continue
		}
		switch {
		case b.Terms == nil:
			o.set("state", tokV(tok("unchecked"))).set("why", textV("readiness unchecked: the contract is not read by this reader: "+b.TermsWhy))
		case b.Terms.Quorum == nil:
			o.set("state", tokV(tok(resolve.ByReview))).set("why", textV("no quorum predicate: "+resolve.ByReview))
		default:
			o.set("state", tokV(tok(rd.Token))).set("quorum", intV(int64(rd.K))).set("counted", textV(resolve.CountedAs)).
				set("why", textV("settled by counting: "+strconv.Itoa(rd.K)+" distinct signing keys"))
		}
		if b.Terms != nil && b.Terms.Provisional {
			o.set("contract_profile", textV(b.Terms.Profile+" (provisional: the contract grammar is pending)"))
		}
	}
	return o, b.State, ""
}
