package cli

import (
	"errors"
	"regexp"
	"slices"
	"strconv"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// identity new, identity grant, identity cut: the writer of the fixed-root identity profile's three administrative
// statements (docs/DESIGN-notes-fixed-root-identity.md §3, §4, §8). Each is a raw-key rc/2 statement signed by the
// identity's root key, written through the same path as publish (key file, --ts, --dry-run, one journal record),
// and read back through the identity reader before anything is appended: a line that reader would hold Invalid or
// Unsupported is refused, never written.
//
//   - identity new signs the inception (profile fixed-root-v1) as seq 0 of a FRESH root log: a root key that already
//     has any line here is refused, because the identity's lineage is the root key's whole log (§8: a dedicated
//     root). The identity's id is the inception's statement id.
//   - identity grant signs a grant from I's root to a delegate key K, pinned at K's seq-0 line D, carrying a
//     permission set the writer sorts and dedupes (1..64, the §3 table). K == root is refused.
//   - identity cut signs a cut of grant G with a MANDATORY --last-good <id|none> and a reason token: the delegate's
//     acts under G after last_good stop counting for I, those at or before it keep counting. A cut cannot be undone.

var reReasonToken = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func init() {
	nflags := append(slices.Clone(writerFlags), extFlags...)
	Register(&Command{Name: "identity new", Summary: "create a fixed-root identity: sign its inception with a fresh root key",
		Store: true, Writes: true, Flags: nflags, Prepare: prepareIdentityNew, Run: identityNewCmd,
		Help: "Signs an identity_inception (rc/2, profile " + wire.FixedRootProfile + ") with --key (or $" + KeyEnv + ") as the first line of that key's log; the identity's id is the inception's statement id. " +
			"The root key must be fresh: a key with any line in this store is refused (exit 1), since the identity's lineage is the root key's whole log. " +
			"Use the root key for administration only (identity grant, identity cut) and keep it offline: it is the identity's only administrator, and fixed-root-v1 has no recovery if it is lost or stolen. " +
			"--dry-run prints the exact statement and signs nothing; with --ts the dry run's id is the id the real run signs." + extHelp})
	gflags := append(slices.Clone(writerFlags), extFlags...)
	gflags = append(gflags,
		Flag{Name: "identity", Value: "id", Help: "the identity (its inception id); your key must be its root", Check: checkIDFlag},
		Flag{Name: "delegate", Value: "key", Help: "the delegate key K (ed25519:<64 hex> or 0x<40 hex>); never the root key", Check: func(v string) error {
			if !reGrantee.MatchString(v) {
				return errString("not a key (ed25519: + 64 lowercase hex, or 0x + 40 lowercase hex)")
			}
			return nil
		}},
		Flag{Name: "delegate-inception", Value: "id", Help: "D: the statement id of the delegate key's seq-0 line, which pins the grant to that key's log", Check: checkIDFlag},
		Flag{Name: "permissions", Value: "json", Help: "a JSON array of permissions, e.g. [{\"kind\":\"authored\",\"targets\":{\"any_content\":true},\"amend\":false}]; sorted and deduplicated by the writer, 1..64", Check: checkJSONArray},
	)
	Register(&Command{Name: "identity grant", Summary: "grant a delegate key the right to act for an identity",
		Store: true, Writes: true, Flags: gflags, Prepare: prepareIdentityGrant, Run: identityGrantCmd,
		Help: "Signs an identity_grant (rc/2) with the identity's root key naming --delegate and its seq-0 line --delegate-inception, with the permission set --permissions (profile §3: a kind, its targets, and for authored and observed an amend mode true, false or own). " +
			"Refused (exit 2) when the delegate is the root key, a permission is malformed, or this reader would not read the grant as valid; refused (exit 1) when your key is not the identity's root or the delegate-inception held here is not the delegate's seq-0 line; exit 3 when the identity is not held here. " +
			"When the delegate-inception line is not held here the grant is signed with a warning: a reader needs that line to place the delegate's acts. " +
			"The delegate acts with publish --as <identity> --grant <grant id>." + extHelp})
	cflags := append(slices.Clone(writerFlags), extFlags...)
	cflags = append(cflags,
		Flag{Name: "identity", Value: "id", Help: "the identity (its inception id); your key must be its root", Check: checkIDFlag},
		Flag{Name: "grant", Value: "id", Help: "the grant to cut (its statement id)", Check: checkIDFlag},
		Flag{Name: "last-good", Value: "id|none", Help: "required: the delegate's last act under the grant you vouch for (it and its ancestors keep counting), or none to keep nothing", Check: func(v string) error {
			if v != lastGoodNone && !isID(v) {
				return errString("not a statement id or none")
			}
			return nil
		}},
		Flag{Name: "reason", Value: "token", Help: "required: why (a token, e.g. key_compromise, superseded)", Check: func(v string) error {
			if !reReasonToken.MatchString(v) {
				return errString("not a reason token (lowercase letters, digits and _)")
			}
			return nil
		}},
	)
	Register(&Command{Name: "identity cut", Summary: "cut a grant: the delegate's acts after --last-good stop counting for the identity",
		Store: true, Writes: true, Flags: cflags, Prepare: prepareIdentityCut, Run: identityCutCmd,
		Help: "Signs an identity_cut (rc/2) with the identity's root key. It cannot be undone: the delegate's acts under the grant after --last-good count toward nothing for the identity, now and for every reader that holds the cut; the acts at or before it keep counting. --last-good is required (an id, or none to keep nothing); the tool never picks it. " +
			"Every held act under the grant is listed with what happens to it. --dry-run signs nothing and lists the same. " +
			"Refused (exit 2) without --last-good or --reason; (exit 1) when your key is not the identity's root, the grant is not the identity's, or --last-good names a line of another key; exit 3 when the identity, the grant or the --last-good line is not held here." + extHelp})
}

func checkJSONArray(v string) error {
	x, err := canon.Parse([]byte(v))
	if err != nil {
		return errors.New("not strict JSON")
	}
	if _, ok := x.(canon.Array); !ok {
		return errors.New("not a JSON array")
	}
	return nil
}

type identityPrep struct {
	pubPrep
	identity, delegate, delegateInception, grant, lastGood, reason string
	perms                                                          canon.Array
}

func needFlags(c *Ctx, synopsis string, names ...string) (map[string]string, *Problem) {
	out := map[string]string{}
	for _, n := range names {
		v, ok := c.Flag(n)
		if !ok {
			return nil, usage("missing-argument", "a required option is missing", "give --"+n+"; nothing was done", "option --"+n, synopsis, "")
		}
		out[n] = v
	}
	return out, nil
}

func prepareIdentityNew(c *Ctx) *Problem {
	if prob := beginExternal(c, "identity_inception"); prob != nil {
		return prob
	}
	p := &identityPrep{}
	if prob := prepareCommon(c, &p.pubPrep); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

func prepareIdentityGrant(c *Ctx) *Problem {
	if prob := beginExternal(c, "identity_grant"); prob != nil {
		return prob
	}
	f, prob := needFlags(c, "commons identity grant --identity <id> --delegate <key> --delegate-inception <id> --permissions <json>",
		"identity", "delegate", "delegate-inception", "permissions")
	if prob != nil {
		return prob
	}
	p := &identityPrep{identity: f["identity"], delegate: f["delegate"], delegateInception: f["delegate-inception"]}
	v, _ := canon.Parse([]byte(f["permissions"]))
	perms, why := normalizePermissions(v.(canon.Array))
	if why != "" {
		return usage("malformed-argument", "the permission set cannot be granted", why+"; nothing was done", "option --permissions",
			"give 1..64 permissions of the profile's table (identity profile §3)", f["permissions"])
	}
	p.perms = perms
	if prob := prepareCommon(c, &p.pubPrep); prob != nil {
		return prob
	}
	if p.key.Key.Signer() == p.delegate {
		return usage("self-grant", "the delegate is the root key", "a dedicated root never grants to itself (identity profile §3); nothing was done",
			"option --delegate", "create a separate delegate key with commons key new --out <file>", p.delegate)
	}
	c.Prep = p
	return nil
}

// normalizePermissions sorts and dedupes a permission list by canonical encoding (the order the reader requires)
// and checks its size. Each entry's schema is the reader's: the signed line is read back before anything is written.
func normalizePermissions(a canon.Array) (canon.Array, string) {
	seen := map[string]canon.Value{}
	for i, x := range a {
		if _, ok := x.(*canon.Object); !ok {
			return nil, "permission " + itoa(i) + " is not an object"
		}
		seen[string(canon.Encode(x))] = x
	}
	keys := make([]string, 0, len(seen))
	for k := range seen {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, canon.CompareKeys)
	out := canon.Array{}
	for _, k := range keys {
		out = append(out, seen[k])
	}
	switch {
	case len(out) == 0:
		return nil, "a grant needs at least one permission"
	case len(out) > 64:
		return nil, "a grant carries at most 64 permissions"
	}
	return out, ""
}

func prepareIdentityCut(c *Ctx) *Problem {
	if prob := beginExternal(c, "identity_cut"); prob != nil {
		return prob
	}
	f, prob := needFlags(c, "commons identity cut --identity <id> --grant <id> --last-good <id|none> --reason <token>",
		"identity", "grant", "last-good", "reason")
	if prob != nil {
		if prob.Scope == "option --last-good" {
			prob.Title = "a cut needs --last-good"
			prob.Detail = "only the delegate's acts up to last_good keep counting; the tool does not pick it for you; nothing was done"
			prob.Next = "give --last-good <id> (the last act you vouch for) or --last-good none (keep nothing)"
		}
		return prob
	}
	p := &identityPrep{identity: f["identity"], grant: f["grant"], lastGood: f["last-good"], reason: f["reason"]}
	if prob := prepareCommon(c, &p.pubPrep); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

// identityRefused is a refusal decided by the statements held: exit 1, nothing signed.
func identityRefused(slug, title, detail, scope, next, peer string) *Problem {
	return &Problem{Slug: slug, Title: title, Class: refusal.Policy, Scope: scope, Detail: detail + "; nothing was signed or appended",
		Next: next, Peer: peer, Exit: exitWriterRefused}
}

func identityNotHeld(title, detail, scope, next, peer string) *Problem {
	return &Problem{Slug: "identity-not-held", Title: title, Class: refusal.Policy, Scope: scope, Detail: detail + "; nothing was signed or appended",
		Next: next, Peer: peer, Exit: ExitCouldNot}
}

// rootOf checks that the identity is held, is a valid fixed-root inception, and that signer is its root key.
func (v *view) rootOf(identity, signer string) *Problem {
	pl, ok := v.r.Statement(identity)
	if !ok || pl.St.Kind != "identity_inception" {
		return identityNotHeld("the identity is not held here", "no identity_inception with that id is placed in this store", "option --identity",
			"fetch the identity's inception (pull from its root's store), then run again", identity)
	}
	if pl.St.Status != wire.Valid {
		return identityRefused("identity-unusable", "refused: the identity's inception is not valid", "it reads "+string(pl.St.Status)+": "+pl.St.Why,
			"option --identity", "create a new identity", identity)
	}
	if pl.St.Signer != signer {
		return identityRefused("not-identity-root", "refused: your key is not the identity's root",
			"only the inception's key ("+pl.St.Signer+") administers this identity; a grant or cut by another key has no effect", "option --identity",
			"sign with the identity's root key", signer)
	}
	return nil
}

// signIdentity prepares d for rc/2, signs it at h and refuses a line the identity reader would not hold valid.
func signIdentity(p *pubPrep, h head, d wire.Draft, actor *wire.Actor, marker *canon.Object) ([]signed, *Problem) {
	d, err := wire.IdentityDraft(d, actor, marker)
	if err != nil {
		return nil, writeRefused(err)
	}
	sts, err := signAll(p.key.Key, h, p.ts, []wire.Draft{d})
	if err != nil {
		return nil, writeRefused(err)
	}
	return sts, nil
}

const rootCustody = "keep the root key offline and use it only for identity grant and identity cut: it is this identity's only administrator, and fixed-root-v1 has no recovery if it is lost or stolen (a stolen root can grant and cut as you)"

func identityNewCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*identityPrep)
	signer := p.key.Key.Signer()
	wl := lockFor(c, signer)
	defer wl.Unlock()
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	if prob := v.checkPrepared(c, signer); prob != nil {
		return nil, 0, prob
	}
	if lv := v.logs.Log(signer).View(); len(lv.Lines) > 0 || len(lv.Retained) > 0 || len(lv.Refused) > 0 {
		return nil, 0, identityRefused("root-key-not-fresh", "refused: the root key already has a log",
			"this store holds "+itoa(len(lv.Lines)+len(lv.Retained)+len(lv.Refused))+" line(s) of this key; an identity's inception is the first line of a dedicated root key, because the identity's lineage is that key's whole log",
			"this key's log", "create a fresh root key with commons key new --out <file>, then run again", signer)
	}
	afterHead()
	sts, prob := signIdentity(&p.pubPrep, head{}, wire.Draft{Kind: "identity_inception", Body: objOf("profile", canon.String(wire.FixedRootProfile))}, nil, nil)
	if prob != nil {
		return nil, 0, prob
	}
	out := newObj().set("identity", refV(sts[0].st.ID)).set("root", refV(signer)).set("profile", textV(wire.FixedRootProfile)).
		set("custody", textV(rootCustody)).
		set("next", textV("each worker key signs its first line (commons publish), sends you its key and that line's id; then: commons identity grant --identity "+sts[0].st.ID+" --delegate <key> --delegate-inception <id> --permissions <json>"))
	noteLock(out, wl)
	return commitUnit(c, out, "publish", sts, nil, "", head{})
}

func identityGrantCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*identityPrep)
	signer := p.key.Key.Signer()
	wl := lockFor(c, signer)
	defer wl.Unlock()
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	if prob := v.checkPrepared(c, signer); prob != nil {
		return nil, 0, prob
	}
	if prob := v.rootOf(p.identity, signer); prob != nil {
		return nil, 0, prob
	}
	var warns []string
	if d, ok := v.r.Statement(p.delegateInception); ok {
		if d.St.Signer != p.delegate || d.St.Seq != 0 {
			return nil, 0, identityRefused("delegate-inception-mismatch", "refused: --delegate-inception is not the delegate's seq-0 line",
				"the line held here is seq "+itoa(int(d.St.Seq))+" of "+d.St.Signer+"; a grant pinned to it would place none of the delegate's acts",
				"option --delegate-inception", "name the delegate key's first line (its seq 0)", p.delegateInception)
		}
	} else {
		warns = append(warns, "the delegate-inception line is not held here: a reader needs it to place the delegate's acts; check the id with the delegate (it is the statement id of their key's seq-0 line)")
	}
	h, prob := v.nextLine(c, signer, "identity_grant")
	if prob != nil {
		return nil, 0, prob
	}
	afterHead()
	body := objOf("delegate", objOf("inception", canon.String(p.delegateInception), "key", canon.String(p.delegate)),
		"identity", canon.String(p.identity), "permissions", p.perms)
	sts, prob := signIdentity(&p.pubPrep, h, wire.Draft{Kind: "identity_grant", Body: body}, nil, nil)
	if prob != nil {
		return nil, 0, prob
	}
	out := newObj().set("identity", refV(p.identity)).set("grant", refV(sts[0].st.ID)).set("delegate", refV(p.delegate)).
		set("delegate_inception", refV(p.delegateInception)).set("permissions", rawV{p.perms}).
		set("next", textV("the delegate acts with commons publish --as "+p.identity+" --grant "+sts[0].st.ID+"; cut the grant with commons identity cut"))
	if len(warns) > 0 {
		out.set("warnings", texts(warns...))
	}
	noteLock(out, wl)
	return v.scopedResult(commitUnit(c, out, "publish", sts, nil, "", h))
}

func identityCutCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*identityPrep)
	signer := p.key.Key.Signer()
	wl := lockFor(c, signer)
	defer wl.Unlock()
	v, err := viewOf(c)
	if err != nil {
		return nil, 0, err
	}
	if prob := v.checkPrepared(c, signer); prob != nil {
		return nil, 0, prob
	}
	if prob := v.rootOf(p.identity, signer); prob != nil {
		return nil, 0, prob
	}
	g, ok := v.r.Statement(p.grant)
	if !ok || g.St.Kind != "identity_grant" {
		return nil, 0, identityNotHeld("the grant is not held here", "no identity_grant with that id is placed in this store", "option --grant",
			"name a grant of this identity (commons show <id>)", p.grant)
	}
	gid, _ := g.St.Body.Get("identity")
	if g.St.Signer != signer || gid != canon.String(p.identity) {
		return nil, 0, identityRefused("grant-not-of-identity", "refused: the grant is not this identity's",
			"the grant is signed by "+g.St.Signer+" for another identity or root; a cut of it by this root has no effect", "option --grant",
			"name a grant this identity's root signed", p.grant)
	}
	delegate := ""
	if dv, ok := g.St.Body.Get("delegate"); ok {
		if do, ok := dv.(*canon.Object); ok {
			if k, ok := do.Members["key"].(canon.String); ok {
				delegate = string(k)
			}
		}
	}
	var lastGood canon.Value = canon.Null{}
	if p.lastGood != lastGoodNone {
		lg, ok := v.r.Statement(p.lastGood)
		if !ok {
			return nil, 0, identityNotHeld("the --last-good line is not held here",
				"a cut at a line this store does not hold cannot be checked against the delegate's log", "option --last-good",
				"pull the delegate's lines, then run again (or --last-good none to keep nothing)", p.lastGood)
		}
		if lg.St.Signer != delegate {
			return nil, 0, identityRefused("last-good-other-key", "refused: --last-good is not a line of the grant's delegate",
				"it is signed by "+lg.St.Signer+", the grant's delegate is "+delegate+"; the cut would keep none of the delegate's acts", "option --last-good",
				"name the delegate's last act you vouch for, or none", p.lastGood)
		}
		lastGood = canon.String(p.lastGood)
	}
	h, prob := v.nextLine(c, signer, "identity_cut")
	if prob != nil {
		return nil, 0, prob
	}
	afterHead()
	body := objOf("grant", canon.String(p.grant), "identity", canon.String(p.identity), "last_good", lastGood, "reason", canon.String(p.reason))
	sts, prob := signIdentity(&p.pubPrep, h, wire.Draft{Kind: "identity_cut", Body: body}, nil, nil)
	if prob != nil {
		return nil, 0, prob
	}
	out := newObj().set("identity", refV(p.identity)).set("grant", refV(p.grant)).set("delegate", refV(delegate))
	if p.lastGood == lastGoodNone {
		out.set("last_good", textV("none: every act under the grant stops counting"))
	} else {
		out.set("last_good", refV(p.lastGood))
	}
	out.set("irreversible", textV("a cut cannot be undone: every reader that holds it reads the delegate's acts under this grant after last_good as counting toward nothing for the identity; a later grant to a new key does not restore them"))
	if preparing(c) {
		out.set("acts", textV("listed at --complete: an unsigned cut is not evidence, so its effect is read once it is signed"))
	} else {
		out.set("acts", v.cutEffects(c, delegate, p.grant, sts[0].line))
	}
	noteLock(out, wl)
	return v.scopedResult(commitUnit(c, out, "publish", sts, nil, "", h))
}

// cutEffects lists each held act under grant before and after the cut line is added: what keeps counting, what stops.
func (v *view) cutEffects(c *Ctx, delegate, grant string, cut []byte) listV {
	lines, _ := c.Store.Statements()
	before, after := heldActors(lines), heldActors(lines, cut)
	l := listV{}
	if before == nil || after == nil {
		return l
	}
	lv := v.logs.Log(delegate).View()
	for _, ln := range lv.Lines {
		st := ln.St
		if st.Actor == nil || st.Actor.Grant != grant {
			continue
		}
		_, b, _ := before.Eligible(st)
		_, a, why := after.Eligible(st)
		what := "keeps counting"
		switch {
		case a != policy.ActorEligible && b == policy.ActorEligible:
			what = "stops counting"
		case a != policy.ActorEligible:
			what = "was not counting"
		}
		o := newObj().set("statement", refV(st.ID)).set("seq", intV(st.Seq)).set("state", tokV(tok(a))).set("was", textV(b)).set("effect", textV(what))
		if a != policy.ActorEligible && len(why) > 0 {
			o.set("reasons", texts(why...))
		}
		l = append(l, o)
	}
	return l
}

// objOf builds a canon object from key/value pairs (values already canon).
func objOf(kv ...any) *canon.Object {
	o := &canon.Object{Members: map[string]canon.Value{}}
	for i := 0; i < len(kv); i += 2 {
		k := kv[i].(string)
		o.Keys = append(o.Keys, k)
		o.Members[k] = kv[i+1].(canon.Value)
	}
	return o
}

func itoa(n int) string { return strconv.Itoa(n) }
