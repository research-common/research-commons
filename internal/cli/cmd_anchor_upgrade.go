package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// anchor upgrade [<anchors-statement>]: the anchor writer's second slice (bitcoin-time note §2 "Upgrade", §10). A
// pending proof is a calendar's promise; once the calendar's commitment is in a Bitcoin block it answers
// `GET <calendar>/timestamp/<hex commitment>` with the path to the block header. This command asks the calendars of
// the author's local policy for each pending attestation of an anchors line of the signing key's own log, merges
// every answer into the proof (a union: the pending attestations are kept) and, only when the merged proof carries
// a Bitcoin attestation the stored one did not, commits the new proof blob and a new anchors line {covered: the
// same head, proof, proof_format, services: the calendars that answered} after the old anchor, signed by the same
// key, as one journal record. The old anchors line stays in the log; a reader prefers the verified bound.
//
// Calendars are the author's local policy (the same --calendar / $COMMONS_CALENDARS as anchor stamp): a pending
// attestation naming a calendar outside it is reported and not contacted. This package dials nothing: the calendar
// client comes from the binary (Env.Calendars).

func init() {
	flags := slices.Clone(writerFlags)
	flags = append(flags,
		Flag{Name: "calendar", Value: "url", Repeat: true, Help: "an OpenTimestamps calendar you allow to be asked (https only; repeatable); else $" + CalendarsEnv + ". A pending attestation naming another calendar is reported and not contacted"},
		Flag{Name: "timeout", Value: "duration", Help: "give up on one calendar request after this long (Go duration, e.g. 10s); default 10s", Check: positiveDuration},
		Flag{Name: "allow-private", Help: "allow a calendar on a loopback, private, link-local, shared or other non-global address (a local calendar or mirror); refused by default, checked on the address actually dialled"},
	)
	Register(&Command{Name: "anchor upgrade", Summary: "complete pending timestamps: ask the calendars for the Bitcoin path of each pending proof and commit an upgraded anchors statement",
		Args:  []Arg{{Name: "anchors-statement", Shape: ShapeID, Optional: true}},
		Store: true, Writes: true, Flags: flags, Prepare: prepareUpgrade, Run: upgradeCmd,
		Help: "Upgrades the anchors statement named (a line of your own log whose proof_format is " + btctime.ProofFormat + "), else every anchors line of your log that is the newest for its head and whose proof has no Bitcoin attestation yet. " +
			"For each pending attestation in the proof whose calendar is in your calendar policy (--calendar or $" + CalendarsEnv + "; the URL matches with or without one trailing slash), the calendar is asked GET <calendar>/timestamp/<hex commitment>: 404 means still pending; a 200 answer (at most 10000 bytes) is parsed strictly and merged into the proof, keeping the pending attestations; an answer that does not root at the pending node is refused for that calendar only. A pending attestation naming a calendar outside your policy is listed as not in local calendar policy and not contacted. " +
			"Only when the merged proof gains a Bitcoin attestation are the new proof blob and a new anchors statement {covered: the same head, proof, proof_format, services: the calendars that answered} appended after a line whose history holds the old anchor, all upgraded heads in one journal record. The old anchors line stays; readers verify the new proof against their synced headers (anchor headers sync). " +
			"Only https is dialled, with no proxy; non-global addresses are refused unless --allow-private; a calendar may redirect at most three times, only to https on its own host. --dry-run lists the pending commitments and which calendar would be asked, and contacts nothing. " +
			"Exit 0 upgraded at least one head, or every calendar asked said still pending (each head shows pending), or nothing needs upgrading; 1 refused after the check over your log (your key has a key event); 2 did not start (no calendar named, a calendar URL that is not https, the statement named is not an anchors line of your log or not " + btctime.ProofFormat + ", no usable key); 3 every calendar asked failed or no pending attestation names a calendar in your policy (nothing appended), the proof blob is not held, a forked log without --prev, or calendars not available in this build.",
	})
}

type upgradePrep struct {
	pubPrep
	urls []string
	cals []btctime.Calendar
}

func prepareUpgrade(c *Ctx) *Problem {
	p := &upgradePrep{}
	var prob *Problem
	if p.urls, p.cals, _, prob = prepareCalendars(c, "anchor upgrade asks only"); prob != nil {
		return prob
	}
	if prob := prepareCommon(c, &p.pubPrep); prob != nil {
		return prob
	}
	c.Prep = p
	return nil
}

// upgradeTarget is one anchors line to upgrade and its stored proof.
type upgradeTarget struct {
	anchor  *wire.Statement
	covered string
	proofID string
	proof   []byte
}

// readProof reads a held proof blob (re-hashed on open), bounded by the profile's proof limit.
func readProof(s *store.Store, d string) ([]byte, error) {
	f, err := s.OpenBlob(store.Digest(d))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lim := btctime.DefaultLimits().ProofBytes
	b, err := io.ReadAll(io.LimitReader(f, int64(lim)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > lim {
		return nil, errors.New("proof blob over the proof size limit")
	}
	return b, nil
}

// upgradeTargets is the named anchors line, or every own anchors line that is the newest in log order for its
// covered head (a prev-chain descendant; between forked branches the lower id) and whose proof carries no Bitcoin
// attestation. skipped lists the lines passed over and why.
func (v *view) upgradeTargets(c *Ctx, signer string) ([]upgradeTarget, []*Obj, *Problem) {
	lv := v.logs.Log(signer).View()
	chained := map[string]*wire.Statement{}
	for _, l := range lv.Lines {
		if l.State == keylog.Chained {
			chained[l.St.ID] = l.St
		}
	}
	load := func(st *wire.Statement) (upgradeTarget, string) {
		t := upgradeTarget{anchor: st, covered: bodyString(st.Body, "covered"), proofID: bodyString(st.Body, "proof")}
		if f := bodyString(st.Body, "proof_format"); f != btctime.ProofFormat {
			return t, "proof_format is " + quoteGraphic(f) + ", not " + btctime.ProofFormat
		}
		if !isDigest(t.proofID) {
			return t, "proof is not a blob digest"
		}
		b, err := readProof(v.st, t.proofID)
		if err != nil {
			return t, "the proof blob is not held here (or is unreadable): " + err.Error()
		}
		t.proof = b
		return t, ""
	}
	if id, named := c.Args["anchors-statement"]; named {
		st := chained[id]
		if st == nil || st.Kind != "anchors" {
			detail := "this store holds no statement with this id"
			switch p, ok := v.r.Statement(id); {
			case ok && p.St.Signer != signer:
				detail = "it is a statement of another key (" + p.St.Signer + "); you upgrade only your own log's anchors"
			case ok && p.St.Kind != "anchors":
				detail = "it is a " + p.St.Kind + " statement, not an anchors statement"
			case ok:
				detail = "it is a line of your log that is not chained to its first line here (detached)"
			}
			return nil, nil, usage("not-your-anchor", "the statement named is not a chained anchors line of your log",
				detail+"; nothing was contacted or appended", "argument anchors-statement", "name an anchors line your key signed (commons show <id>), or omit it to upgrade every pending one", id)
		}
		t, why := load(st)
		switch {
		case strings.HasPrefix(why, "proof_format") || strings.HasPrefix(why, "proof is not"):
			return nil, nil, usage("not-upgradable", "the anchors line does not name an "+btctime.ProofFormat+" proof",
				why+"; nothing was contacted or appended", "argument anchors-statement", "name an anchors line written by anchor stamp", id)
		case why != "":
			return nil, nil, &Problem{Slug: "proof-not-held", Title: "the anchors line's proof is not held here", Class: refusal.Operational,
				Scope: "argument anchors-statement", Detail: why + "; nothing was contacted or appended", Next: "fetch or pull the proof blob, then run anchor upgrade again", Peer: t.proofID, Exit: ExitCouldNot}
		}
		if pp, err := btctime.ParseProof(t.proof, btctime.DefaultLimits()); err == nil && len(pp.Bitcoin) > 0 {
			return nil, []*Obj{rowObj().set("anchor", refV(id)).set("covered", refV(t.covered)).
				set("why", textV("its proof already carries a Bitcoin attestation"))}, nil
		}
		return []upgradeTarget{t}, nil, nil
	}
	// newest anchors line per covered head
	byHead := map[string][]*wire.Statement{}
	for _, l := range lv.Lines {
		if l.State == keylog.Chained && l.St.Kind == "anchors" {
			cov := bodyString(l.St.Body, "covered")
			byHead[cov] = append(byHead[cov], l.St)
		}
	}
	var targets []upgradeTarget
	var skipped []*Obj
	heads := make([]string, 0, len(byHead))
	for h := range byHead {
		heads = append(heads, h)
	}
	slices.Sort(heads)
	for _, h := range heads {
		as := byHead[h]
		var newest []*wire.Statement
		for _, a := range as {
			superseded := false
			for _, b := range as {
				if b.ID != a.ID && ancestors(b.ID, chained)[a.ID] {
					superseded = true
					break
				}
			}
			if !superseded {
				newest = append(newest, a)
			}
		}
		slices.SortFunc(newest, func(a, b *wire.Statement) int { return strings.Compare(a.ID, b.ID) })
		t, why := load(newest[0])
		if why == "" {
			if p, err := btctime.ParseProof(t.proof, btctime.DefaultLimits()); err != nil {
				why = "the stored proof does not parse: " + err.Error()
			} else if len(p.Bitcoin) > 0 {
				continue // already upgraded: nothing to do, not a skip worth listing
			} else if p.PendingCount == 0 {
				why = "the proof has no pending attestation to upgrade"
			}
		}
		if why != "" {
			skipped = append(skipped, rowObj().set("anchor", refV(t.anchor.ID)).set("covered", refV(h)).set("why", textV(why)))
			continue
		}
		targets = append(targets, t)
	}
	return targets, skipped, nil
}

func upgradeCmd(c *Ctx) (*Obj, int, error) {
	p := c.Prep.(*upgradePrep)
	signer := p.key.Key.Signer()
	wl := lockFor(c, signer)
	defer wl.Unlock()
	v, err := loadView(c.Store, nil)
	if err != nil {
		return nil, 0, failed(err, "store", false, "run status, then fsck")
	}
	targets, skipped, prob := v.upgradeTargets(c, signer)
	if prob != nil {
		return nil, 0, prob
	}
	_, dry := c.Flag("dry-run")
	out := newObj()
	noteLock(out, wl)
	cl := listV{}
	for _, u := range p.urls {
		cl = append(cl, peerV(u))
	}
	out.set("calendar_policy", cl)
	if len(skipped) > 0 {
		out.set("skipped", listV(objList(skipped)))
	}
	if len(targets) == 0 {
		return out.set("heads", listV{}).set("committed", boolV(false)).
			set("note", textV("nothing to upgrade: no anchors line here is the newest for its head with a pending-only proof (see skipped); nothing was contacted or appended")), ExitOK, nil
	}
	// the placement: the line the new anchors lines extend; every old anchor must be in its history (or be it), so
	// each covered head stays in its new anchor's prefix (bitcoin-time note §1 rule 3)
	h, prob := v.placeLine(c, signer)
	if prob != nil {
		return nil, 0, prob
	}
	if prob := v.keyRetired(signer); prob != nil {
		return nil, 0, prob
	}
	lv := v.logs.Log(signer).View()
	chained := map[string]*wire.Statement{}
	for _, l := range lv.Lines {
		if l.State == keylog.Chained {
			chained[l.St.ID] = l.St
		}
	}
	inPrefix := ancestors(h.prev, chained)
	var placed []upgradeTarget
	for _, t := range targets {
		if t.anchor.ID != h.prev && !inPrefix[t.anchor.ID] {
			if _, named := c.Args["anchors-statement"]; named {
				return nil, 0, usage("head-not-in-prefix", "the anchors line named is not in the history of the line the upgrade extends",
					"the new anchors statement must have its covered head in its own prefix (bitcoin-time note §1 rule 3); nothing was contacted or appended",
					"option --prev", "name with --prev a line whose history holds the anchors line, or omit --prev", t.anchor.ID)
			}
			skipped = append(skipped, rowObj().set("anchor", refV(t.anchor.ID)).set("covered", refV(t.covered)).
				set("why", textV("not in the history of the line --prev names")))
			continue
		}
		placed = append(placed, t)
	}
	if len(skipped) > 0 {
		out.set("skipped", listV(objList(skipped)))
	}
	cals := map[string]btctime.Upgrader{}
	if p.cals != nil {
		for _, cal := range p.cals {
			u, ok := cal.(btctime.Upgrader)
			if !ok {
				p.cals = nil
				break
			}
			cals[btctime.TrimCalendarURI(cal.URI())] = u
		}
	}
	if p.cals == nil && !dry {
		return nil, 0, &Problem{Slug: "not-available", Title: "calendars are not available in this build", Class: refusal.Operational, Scope: "invocation",
			Detail: "this build has no calendar client; nothing was contacted or appended", Next: "use a build with network access", Exit: ExitCouldNot}
	}
	if p.cals == nil { // a dry run in a build without clients: match on the configured URLs alone
		for _, u := range p.urls {
			cals[btctime.TrimCalendarURI(u)] = nil
		}
	}
	var sts []signed
	var blobs []store.Digest
	proofs := map[store.Digest][]byte{}
	headsOut := listV{}
	contacted, failedN, upgraded := 0, 0, 0
	next := h
	for _, t := range placed {
		ho := newObj().set("covered", refV(t.covered)).set("anchor", refV(t.anchor.ID)).set("proof", refV(t.proofID))
		res, err := btctime.UpgradeProof(t.proof, cals, dry, btctime.Limits{})
		if err != nil {
			ho.set("result", textV("skipped")).set("why", textV("the stored proof does not parse: "+err.Error()))
			headsOut = append(headsOut, ho)
			continue
		}
		raw, _ := hex.DecodeString(t.covered)
		if pp, _ := btctime.ParseProof(t.proof, btctime.DefaultLimits()); pp != nil && !bytes.Equal(pp.FileDigest[:], raw) {
			ho.set("result", textV("skipped")).set("why", textV("the stored proof is not rooted at the covered head"))
			headsOut = append(headsOut, ho)
			continue
		}
		contacted += res.Contacted
		failedN += res.Failed
		ho.set("asks", asksList(res.Asks))
		switch {
		case dry:
			ho.set("result", textV("dry run"))
		case res.Proof != nil:
			sum := store.Digest(blobID(res.Proof))
			svc := canon.Array{}
			for _, s := range res.Services {
				svc = append(svc, canon.String(s))
			}
			body := &canon.Object{Keys: []string{"covered", "proof", "proof_format", "services"}, Members: map[string]canon.Value{
				"covered": canon.String(t.covered), "proof": canon.String(string(sum)), "proof_format": canon.String(btctime.ProofFormat), "services": svc,
			}}
			st, err := wire.Write(wire.Draft{Kind: "anchors", Seq: next.seq, Prev: next.prev, TS: p.ts, Body: body}, p.key.Key, Now())
			if err != nil {
				return nil, 0, writeRefused(err)
			}
			if st.Status != wire.Valid {
				return nil, 0, writeRefused(&refusal.Refusal{Class: refusal.Intrinsic, Reason: "not valid", Detail: "the signed line reads back as " + string(st.Status)})
			}
			sts = append(sts, signed{st, st.Line()})
			if _, held := proofs[sum]; !held {
				blobs = append(blobs, sum)
				proofs[sum] = res.Proof
			}
			next = head{seq: st.Seq + 1, prev: st.ID}
			upgraded++
			hs := listV{}
			for _, x := range res.Heights {
				hs = append(hs, intV(x))
			}
			ho.set("result", textV("upgraded")).set("new_proof", refV(string(sum))).set("new_anchor", refV(st.ID)).set("bitcoin_heights", hs)
		case res.Contacted > 0 && res.Failed == res.Contacted:
			ho.set("result", textV("failed"))
		case res.Contacted == 0:
			ho.set("result", textV("not asked")).set("why", textV("no pending attestation of this proof names a calendar in your policy"))
		default:
			ho.set("result", textV("pending"))
		}
		headsOut = append(headsOut, ho)
	}
	out.set("heads", headsOut)
	if dry {
		return out.set("dry_run", boolV(true)).set("committed", boolV(false)).
			set("note", textV("dry run: no calendar was contacted; nothing was written")), ExitOK, nil
	}
	if upgraded == 0 {
		out.set("committed", boolV(false))
		switch {
		case contacted == 0:
			return out.set("note", textV("no pending attestation names a calendar in your policy: nothing was contacted or appended; name the calendar with --calendar to ask it")), ExitCouldNot, nil
		case failedN == contacted:
			return out.set("note", textV("every calendar asked failed: nothing was appended; the heads stay pending")), ExitCouldNot, nil
		}
		return out.set("note", textV("still pending: no calendar has a Bitcoin attestation for these commitments yet; nothing was appended; run anchor upgrade again later")), ExitOK, nil
	}
	if failedN > 0 {
		out.set("warnings", texts("a calendar failed or its answer was refused beside one that answered; services names only the calendars whose answer was merged (see asks)"))
	}
	afterHead()
	open := func(d store.Digest) (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(proofs[d])), nil }
	return commitUnitFrom(c, out, "anchor", sts, blobs, open, "calendar response", h)
}

// blobID is the store's id for b: sha256: and the lowercase hex of its hash.
func blobID(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

func asksList(asks []btctime.UpgradeAsk) listV {
	l := listV{}
	for _, a := range asks {
		row := rowObj().set("calendar", peerV(a.URI)).set("commitment", refV(hex.EncodeToString(a.Commitment))).set("result", textV(string(a.Result)))
		if a.Err != nil {
			row.set("error", peerV(a.Err.Error()))
		}
		l = append(l, row)
	}
	return l
}

func objList(os []*Obj) []value {
	out := make([]value, len(os))
	for i, o := range os {
		out[i] = o
	}
	return out
}
