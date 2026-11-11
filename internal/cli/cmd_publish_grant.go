package cli

import (
	"regexp"
	"slices"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// publish grant: a task coordinator's grant (task-contracts note §4.1), as sugar over a `grant` draft. The writer
// signs one only when this reader resolves the named edition as an authorized edition of the task whose contract
// it reads and whose coordinator is the signing key: a grant anyone else signs is shown as its signer's statement
// with no effect, so the writer refuses to make one (publish --draft stays the raw path). After the grant it
// prints the edition's readiness, as publish task does.

var reGrantee = regexp.MustCompile(`^(0x[0-9a-f]{40}|ed25519:[0-9a-f]{64})$`)

func init() {
	flags := append(slices.Clone(writerFlags),
		Flag{Name: "task", Value: "id", Help: "the task (its genesis id)", Check: checkIDFlag},
		Flag{Name: "edition", Value: "id", Help: "the task edition the grant is for (an edition id); a grant does not carry to a later edition", Check: checkIDFlag},
		Flag{Name: "grantee", Value: "key", Help: "the key granted (ed25519:<64 hex> or 0x<40 hex>)", Check: func(v string) error {
			if !reGrantee.MatchString(v) {
				return errString("not a key (ed25519: + 64 lowercase hex, or 0x + 40 lowercase hex)")
			}
			return nil
		}},
		Flag{Name: "note", Value: "text", Help: "an optional note carried in the grant"},
	)
	Register(&Command{Name: "publish grant", Summary: "sign a task coordinator's grant for one edition",
		Store: true, Writes: true, Flags: flags, Prepare: preparePublishGrant, Run: publishGrantCmd,
		Help: "Signs a grant naming --task, --edition and --grantee with --key (or $" + KeyEnv + "). Refused, with nothing signed (exit 2; exit 3 when the task or edition is not held as authorized), unless the statements this store holds resolve --edition as an authorized edition of --task whose contract this reader reads and names your key as its coordinator: any other grant has no effect. A grant counts for that edition only and whether published before or after the grantee's submission. Prints the edition's readiness with the grant added. To sign a grant anyway, use publish --draft."})
}

type errString string

func (e errString) Error() string { return string(e) }

type grantPrep struct {
	pubPrep
	task, edition, grantee, note string
	hasNote                      bool
}

func preparePublishGrant(c *Ctx) *Problem {
	p := &grantPrep{}
	var ok bool
	for _, f := range []struct {
		name string
		dst  *string
	}{{"task", &p.task}, {"edition", &p.edition}, {"grantee", &p.grantee}} {
		if *f.dst, ok = c.Flag(f.name); !ok {
			return usage("missing-argument", "a grant names --task, --edition and --grantee", "give --"+f.name+"; nothing was done", "option --"+f.name,
				"commons publish grant --task <id> --edition <id> --grantee <key>", "")
		}
	}
	p.note, p.hasNote = c.Flag("note")
	if prob := prepareCommon(c, &p.pubPrep); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

// grantRefused is the refusal of a grant this reader would show with no effect: nothing was signed or appended.
// The edition's own terms decide it (the signer is not its coordinator, it names none, or this reader does not
// read them): exit 2, as decided for this writer. What more statements could change (the task or the edition not
// held, the edition not authorized yet) exits 3, as publish task does for the same states.
func grantRefused(detail, next, peer string) *Problem {
	return &Problem{Slug: "grant-without-effect", Title: "refused: the grant would have no effect", Class: refusal.Policy, Scope: "option --edition",
		Detail: detail + "; nothing was signed or appended", Next: next, Peer: peer, Exit: ExitDidNotStart}
}

func grantNotHeld(detail, next, peer string) *Problem {
	p := grantRefused(detail, next, peer)
	p.Slug, p.Title, p.Exit = "grant-edition-not-held", "refused: the edition is not held as an authorized edition of the task", ExitCouldNot
	return p
}

func publishGrantCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*grantPrep)
	signer := p.key.Key.Signer()
	wl := lockFor(c, signer)
	defer wl.Unlock()
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	t, ok := v.r.Task(p.task)
	if !ok {
		return nil, 0, grantNotHeld("no task genesis with that id is in this store", "fetch the task, then publish again", p.task)
	}
	var ed *resolve.Edition
	for _, e := range t.Editions {
		if e.ID == p.edition {
			ed = e
		}
	}
	switch {
	case ed == nil:
		why := "the task holds no edition with that id"
		if _, ok := t.Edition(p.edition); ok {
			why = "that id is the statement id of an approval, not an edition id"
		}
		if why != "the task holds no edition with that id" {
			return nil, 0, grantRefused(why, "name the edition id (show <task> lists them)", p.edition)
		}
		return nil, 0, grantNotHeld(why, "fetch the edition, or name an edition id (show <task> lists them)", p.edition)
	case ed.State != resolve.Authorized:
		return nil, 0, grantNotHeld("the edition is "+string(ed.State)+", not an authorized edition: a grant bound to it counts toward nothing",
			"grant on an authorized edition", string(ed.State))
	}
	b := bindingOf(t, ed)
	switch {
	case b.Terms == nil:
		return nil, 0, grantRefused("this reader does not read the edition's contract ("+b.TermsWhy+"), so no coordinator is known",
			"publish a new edition whose contract this reader reads", b.TermsWhy)
	case b.Terms.Coordinator == "":
		return nil, 0, grantRefused("the edition's contract names no coordinator: no grant is required and none counts",
			"no grant is needed; every eligible issuer's submission may count", "")
	case b.Terms.Coordinator != signer:
		return nil, 0, grantRefused("your key is not the edition's coordinator ("+b.Terms.Coordinator+"); only the coordinator's grants count",
			"sign with the coordinator's key", signer)
	}
	h, prob := v.nextLine(c, signer, "grant")
	if prob != nil {
		return nil, 0, prob
	}
	afterHead()
	body := newBody()
	setMember(body, "edition", canon.String(p.edition))
	setMember(body, "grantee", canon.String(p.grantee))
	if p.hasNote {
		setMember(body, "note", canon.String(p.note))
	}
	setMember(body, "task", canon.String(p.task))
	sts, err := signAll(p.key.Key, h, p.ts, []wire.Draft{{Kind: "grant", Body: body}})
	if err != nil {
		return nil, 0, writeRefused(err)
	}
	out := newObj().set("task", refV(p.task)).set("edition", refV(p.edition)).set("grantee", refV(p.grantee))
	noteLock(out, wl)
	rd, _, _ := v.readinessWith(c, sts, p.task, p.edition)
	if rd != nil {
		out.set("readiness", rd)
	}
	return v.scopedResult(commitUnit(c, out, "publish", sts, nil, "", h))
}

// bindingOf is the edition's binding as the task view reads it: the view's own when a statement (or currency)
// bound it, else its terms read under the same contract reader the read commands use (viewOf).
func bindingOf(t *resolve.Task, e *resolve.Edition) resolve.Binding {
	if b, ok := t.Bindings[e.ID]; ok {
		return b
	}
	b := resolve.Binding{Edition: e.ID, State: string(e.State)}
	c := contractOf(e.Body)
	if c == nil {
		b.TermsWhy = "the edition carries no contract"
		return b
	}
	b.Terms, b.TermsWhy, _ = resolve.ContractProfiles{}.Read(c)
	return b
}

func contractOf(body *canon.Object) *canon.Object {
	if body == nil {
		return nil
	}
	ct, ok := body.Get("contents")
	if !ok {
		return nil
	}
	co, ok := ct.(*canon.Object)
	if !ok {
		return nil
	}
	x, ok := co.Get("contract")
	if !ok {
		return nil
	}
	o, _ := x.(*canon.Object)
	return o
}
