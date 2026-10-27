package cli

import (
	"slices"
	"strings"
)

// The closed vocabulary (claims-model note §13): every state token any surface prints, each with one meaning
// on every surface. This table is the single source: the human and JSON surfaces print tokens only through tok
// (which panics on a word not here), `commons help outputs` prints this table, and docs/CLI-OUTPUTS.md is
// generated from it. The resolver's, the store's and the time profile's own constants are checked against it
// by test, so a new token anywhere below the CLI fails the build until it is documented here.

// Token is one entry of the vocabulary.
type Token struct {
	Word    string
	Kind    string // what it qualifies: authorship, field, grade, verify, time, statement, line, store, …
	Meaning string
}

var vocabulary = []Token{
	// authorship (claims §5.1, §5.2)
	{"no authorship claim", "authorship", "no counted authored statement for the blob is held"},
	{"sole author", "authorship", "one claimant unit of one key"},
	{"derived", "authorship", "one derivation group of two or more keys; priority is not computed within it"},
	{"default author", "authorship", "several claimant units; one is strictly earliest at a quality this reader verified"},
	{"contested", "authorship", "several claimants (or several values of one field) and none is the default; every claimant is listed"},
	// claimant roles beside a unit
	{"author", "role", "the only claimant unit"},
	{"derivers", "role", "the keys of the one derivation group"},
	{"later claimant", "role", "a claimant after the default author; never shown as proven later"},
	{"claimant", "role", "a claimant of a contested blob"},
	// single-party fields and disclosures (claims §5.1, §7)
	{"default", "field", "the field's value from the default unit, agreed by its signers"},
	{"undeclared", "field", "no claimant declared the field; for pre-registration, not the same as exploratory"},
	{"unknown", "field", "for a licence: none declared, which is never read as open (C-core-67); elsewhere: nothing held establishes it"},
	{"no default (authorship contested)", "field", "authorship is contested, so no claimant's value is the default"},
	// grades and derivation steps (claims §7; execution note §5)
	{"T0", "grade", "byte-identical re-derivation"},
	{"T1", "grade", "re-derivation matched under the named comparator, run by this reader"},
	{"T2", "grade", "task-level replication"},
	{"no derivation (no provenance)", "grade", "the blob declares no provenance, so it is a leaf, not a derivation step"},
	{"not re-derived", "grade", "a derivation nobody else re-ran; unchecked until a second run or the reader's re-run"},
	{"identical bytes (protocol workflow)", "grade", "identical bytes under a protocol workflow: consistent with a re-run and with a copy, evidence of neither"},
	{"diverged", "grade", "a comparison ran to completion and the outputs disagree"},
	{"unchecked", "grade", "the check could not run (no comparator, no backend, a limit); never a pass. Also a rule evaluation that could not decide"},
	{"not comparable", "grade", "the comparator could not compare the outputs"},
	{"observation (not a tier)", "grade", "the blob is an observation; observations carry no tier"},
	{"no statement held", "grade", "this reader holds no statement about the blob or id"},
	// rule evaluations (claims §8, §13)
	{"ok", "rule", "a rule evaluation that passed"},
	{"fail", "rule", "a rule evaluation that failed"},
	// time evidence (claims §10; bitcoin-time note §8)
	{"none", "time", "no counting anchor covers the statement"},
	{"local", "time", "an anchor this reader did not verify; self-declared, orders nothing"},
	{"bitcoin", "time", "an anchor whose proof this reader verified against block evidence it trusts"},
	{"verified", "time", "the proof verified against the reader's chain view"},
	{"verified-historical", "time", "verified against an old view at less than the settled depth; priority not computed from it"},
	{"pending", "time", "only calendar attestations; a calendar's promise grants nothing"},
	{"insufficient-confirmations", "time", "below the reader's confirmation policy"},
	{"missing-proof", "time", "the proof blob is not held here (never fetched)"},
	{"invalid-proof", "time", "the proof does not commit to the covered statement"},
	{"invalid-anchor", "time", "the anchors statement itself is unusable"},
	{"unknown-height", "time", "the attested height is not in the reader's chain view"},
	{"orphaned", "time", "the attested block is not on the accepted chain"},
	{"stale-chain", "time", "the reader's chain view is not fresh under its policy"},
	{"backend-unconfigured", "time", "no chain backend is configured, so no bound is verified; a state, not a failed invocation (exit 3)"},
	{"backend-unavailable", "time", "the configured chain backend could not be read"},
	{"unsupported", "time", "a proof format, attestation, rc major, alg or critical extension this reader does not implement"},
	{"refused", "time", "an anchor refused under a limit of this reader; as a gate verdict, an object not admitted, with its class, reason and narrowest next step named"},
	// statements and log lines (wire §2, §7)
	{"valid", "statement", "signature verified and every rule this reader implements passed"},
	{"unknown kind", "statement", "a validly signed statement of a kind the format does not list; granted nothing"},
	{"chained", "line", "the line reaches its log's first line through prev and merges"},
	{"detached", "line", "a predecessor is not held; shown, attributed, counted toward nothing"},
	{"counted", "statement", "chained, verified, understood and not excluded by a key event"},
	{"not counted", "statement", "held and shown, counted toward nothing (the reason is named)"},
	{"retained", "line", "an unverified line kept and not placed"},
	{"FORK", "line", "two lines of one key's log from one sequence point, not yet merged"},
	{"retracted", "label", "the author signed a retraction; display only, the bytes may still be served"},
	{"held here", "bytes", "this store holds the blob's bytes and they hash correctly when read"},
	{"not held here", "bytes", "this store does not hold the blob's bytes"},
	{"unpinned", "verify", "a derivation names an input it did not pin; nothing to re-run"},
	// gate verdicts (claims §11; hub template H-50): one per object of a package, a change or a tree
	{"admitted", "gate", "the object passed every check of the gate and the receiver's policy"},
	{"admitted and labelled", "gate", "admitted, with a label the reader should see (already held, detached, below trust floor, …)"},
	{"could not check", "gate", "the gate could not decide about the object (a check that could not run); never a pass"},
	{"not applied", "gate", "a control-plane path: reviewed by the maintainers, never admitted as data"},
	// refusal classes (claims §11)
	{"intrinsic", "class", "no reader could admit it (bad signature, hash mismatch, unsafe path); no override applies"},
	{"reader policy", "class", "this reader's own policy refused it (trust floor, hub rules); a typed override naming the object may admit it"},
	{"operational", "class", "a limit or resource of this reader stopped it; raising the named limit is the next step"},
	// gate labels beside an admitted object (claims §11; gate)
	{"already held", "label", "the receiver already holds this statement; nothing new is installed"},
	{"incoherent", "label", "the key's log is inconsistent at this line; shown, counted toward nothing"},
	{"unreferenced", "label", "a blob no statement of the evaluated set names"},
	{"unavailable", "label", "a statement names a blob neither the package nor the receiver holds"},
	{"not held here (policy)", "label", "the receiver's policy does not serve the blob a statement names (not_served)"},
	{"layout marker", "label", "the rc-store layout marker"},
	{"control-plane change: needs maintainer review", "label", "a change to a hub's own files; not data, reviewed by the maintainers"},
	{"removed (not_served)", "label", "a blob the hub policy no longer serves was removed"},
	{"not served: still present", "label", "a blob the hub policy lists in not_served is still in the tree"},
	{"intended_for", "label", "the receiver's re-application of the statement's intended_for, beside the signer's record"},
	{"admitted by override", "label", "a reader-policy refusal lifted by a typed override that names this object"},
	{"series boundary", "label", "a series boundary the freeze policy could not decide"},
	{"below trust floor", "label", "the signer is not trusted for admission by this reader's policy; admitted and labelled (--below-floor label)"},
	// store and journal (storage note §3, §7)
	{"nothing pending", "store", "no journal record is waiting: every committed operation is installed and projected"},
	{"committed, pending install", "store", "the operation reached its commit point and its statements are not all installed yet"},
	{"committed, needs repair", "store", "the operation is installed and its projections are untrusted; run repair"},
	{"replayed", "recovery", "a pending operation was finished on open"},
	{"projected", "recovery", "a done operation's projections were rebuilt on open"},
	{"needs repair", "recovery", "a projection failed on open"},
	{"quarantined", "recovery", "a journal record failed to decode or verify and was moved aside; nothing from it installed"},
	{"replaced statement", "recovery", "a corrupt stored copy was quarantined and the verified line installed"},
	{"removed temporary", "recovery", "a stale temporary file was removed"},
}

// IsToken reports whether s is a word of the closed vocabulary.
func IsToken(s string) bool {
	return slices.ContainsFunc(vocabulary, func(t Token) bool { return t.Word == s })
}

// Vocabulary returns a copy of the table.
func Vocabulary() []Token { return slices.Clone(vocabulary) }

// tok returns s when it is a token and panics otherwise: a surface cannot print a state word that is not in
// the table, and the sweep over every command and fixture turns such a panic into a failed test.
func tok(s string) string {
	if !IsToken(s) {
		panic("cli: state token " + quoteGraphic(s) + " is not in the closed vocabulary")
	}
	return s
}

// tokenKeys are the JSON member names whose values are state tokens (a string, or an array of strings). Every
// surface puts tokens in these members only, so a consumer (and the C-core-132 sweep) finds them by name.
var tokenKeys = []string{"authorship", "role", "state", "grade", "step", "quality", "time_state", "status", "line",
	"counted", "labels", "bytes", "causes", "store_state", "what", "verdict", "class"}

// IsTokenKey reports whether a JSON member of that name carries tokens.
func IsTokenKey(k string) bool { return slices.Contains(tokenKeys, k) }

// causeToken is the token at the end of a verify cause ("authorship: contested" → "contested").
func causeToken(why string) string {
	if i := strings.LastIndex(why, ": "); i >= 0 {
		return why[i+2:]
	}
	return why
}
