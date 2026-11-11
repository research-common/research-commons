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
	{"contested", "authorship", "several claimants (or several values of one field) and none is the default; every claimant is listed. For an edition: authorized only if approvals a key event doubts are counted, or built on an edition that is; never current, authorizes nothing"},
	// the scope of a view's statuses (claims §6 (1), I4): every status a view prints holds within it, never as a
	// claim about statements the reader does not hold
	{"within statements you hold", "scope", "every status of the view is computed from the statements this reader holds; nothing is claimed about statements it never received"},
	{"within this hub", "scope", "every status of the view is computed from one hub's own holdings only"},
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
	{"pending", "time", "only calendar attestations; a calendar's promise grants nothing. For an edition: approved by controllers of every predecessor, not yet enough for one predecessor's rule"},
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
	{"detached", "line", "a predecessor is not held; shown, attributed, counted toward nothing. For an edition: every approval is on a detached line; shown, not evaluated"},
	{"counted", "statement", "chained, verified, understood and not excluded by a key event"},
	{"not counted", "statement", "held and shown, counted toward nothing (the reason is named)"},
	{"retained", "line", "an unverified line kept and not placed"},
	{"FORK", "line", "two lines of one key's log from one sequence point, not yet merged; for a resource, two authorized editions with one predecessor and no merge: no edition is current"},
	{"retracted", "label", "the author signed a retraction; display only, the bytes may still be served"},
	{"held here", "bytes", "this store holds the blob's bytes and they hash correctly when read"},
	{"not held here", "bytes", "this store does not hold the blob's bytes"},
	// fetch (storage note §9; claims §11): one state per blob and per location tried. The location itself is in
	// the row's location member, so "unavailable (holder's word: <location>)" stays one closed token.
	{"fetched-and-verified", "fetch", "the bytes were fetched from a location and installed after the size and full-hash check; equivalent to a blob from a package"},
	{"unavailable (not held locally)", "fetch", "not held here and no held holds names a location for it"},
	{"unavailable (holder's word)", "fetch", "a holder said the bytes are at the location; it could not be reached (or the transfer died midway, or made no progress for --idle-timeout, default 60s), so nothing was installed"},
	{"unavailable (hash mismatch)", "fetch", "the location served bytes whose full hash differs; refused (intrinsic), both hashes and the location named, nothing installed"},
	{"unavailable (size mismatch)", "fetch", "the location served a different number of bytes than the holds declares; refused (intrinsic) before the hash was relied on, nothing installed"},
	{"unavailable (size limit)", "fetch", "the declared size, or the stream when none is declared, exceeds the reader's fetch limit (max_fetch_bytes); refused (operational), a declared size before dialling"},
	{"unavailable (scheme not fetched)", "fetch", "the location's URI scheme is not one this reader fetches (https by default, http with --allow-http); refused before dialling"},
	{"unavailable (no transport in this build)", "fetch", "this build has no network transport, so nothing was dialled"},
	{"would fetch (dry run)", "fetch", "a dry run: the location would be dialled; nothing was"},
	{"stored copy corrupt", "fetch", "the blob file held here does not hash to its name; never used, replaced (and quarantined) only by verified bytes"},
	{"unpinned", "verify", "a pin the statement needs is missing: a derivation input it did not pin (nothing to re-run), or a referent field an observation's class requires (no class agreement model applied)"},
	// referent status of an observation (claims §5.3.1, §7): the reader's computation, shown beside the observer's
	// asserted state at capture. `provisional` is printed with its states ("provisional (3; final at 6)").
	{"final", "referent", "the reader's own re-check found the referent at a state that meets the declared finality rule"},
	{"final (as captured, not re-checked)", "referent", "the observer's asserted state at capture meets the rule and no re-check of this reader confirmed it; never shown as final (I4)"},
	{"provisional", "referent", "the finality rule is not met at the state shown (the state at capture, or this reader's re-check), with the state at which it would be"},
	{"revised", "referent", "a later capture of the same referent holds different bytes before finality; the observation stays true of what it pinned"},
	{"not canonical", "referent", "this reader's re-check found the referent replaced (a deep reorg, a dispute run); nothing counts against the observer"},
	{"still canonical", "referent", "this reader's re-check found the pinned referent unchanged (no finality rule declared)"},
	{"source still available", "referent", "this reader's re-check of a source referent returned it (no finality rule declared)"},
	{"source unavailable", "referent", "this reader's re-check could not reach the source; existing corroborations stand"},
	{"unknown (not re-checked by this reader)", "referent", "no finality rule declared and no re-check of this reader decided anything"},
	{"pinned", "referent", "a phenomenon or method referent: its fields are pinned and it has no re-check"},
	{"no referent (class none-yet)", "referent", "the observation's class names no referent yet"},
	// verify of an observation (claims §13): signature and pins only; corroboration never moves the exit
	{"finality unchecked", "verify", "the observation's declared finality rule cannot be evaluated by this reader"},
	{"body not interpreted", "verify", "the observation's body was kept opaque (an unsupported or critical member); nothing read from it"},
	{"counts toward nothing", "verify", "the statement is not placed in its signer's log (a fork branch left out, a revoked key); it is shown, never counted"},
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
	{"completeness claim", "label", "the receiver's check of an edition's completeness claim (selection.refuse_incomplete): holds, or could not be checked"},
	{"below trust floor", "label", "the signer is not trusted for admission by this reader's policy; admitted and labelled (--below-floor label)"},
	// the reader's own re-run (verify --rerun; execution note §5.2). The token's parameter (the exit status, the
	// cap, the environment fields) is in the cause's detail member, so the token itself stays closed.
	{"match", "rerun", "the re-run's output equals the pinned output (bytes), or the comparator said match (protocol)"},
	{"match (identical bytes)", "rerun", "a protocol workflow re-ran to identical bytes: consistent with a re-run and with a copy; no T0"},
	{"incomplete output", "rerun", "the step exited 0 and a declared output is missing"},
	{"failed", "rerun", "the step exited non-zero in an environment matching the pin (detail: the exit status)"},
	{"failed: operational", "rerun", "a cap of this reader stopped the step (detail: the cap); could not check"},
	{"timeout", "rerun", "the wall-time cap stopped the step; could not check"},
	{"environment mismatch", "rerun", "the re-run's environment differs from the pin on a field environment_match names, or the pinned environment is not available here (detail: the fields); nothing compared"},
	// what became of an edition proposal (claims-model note §8; wire-format note §3); `pending`, `detached` and
	// `contested` are the rows above, read for an edition
	{"edition", "edition", "an authorized edition of the resource: every predecessor's controllers approved this body under its rule"},
	{"unauthorized", "edition", "some predecessor's controllers did not approve this body (nobody elevates themselves)"},
	{"orphan", "edition", "a predecessor names nothing this reader holds as the genesis or an edition of the resource; never current"},
	{"invalid", "edition", "authorized approvals, but the body cannot be an edition (a rule no controller set meets, or a merge that does not declare differing controllers and rule)"},
	// task readiness (claims-model note §9.2, §9.3)
	{"settled by review, not by counting", "readiness", "the task edition has no quorum predicate: its beneficiary's decisions settle it; nothing is counted"},
	{"ready", "readiness", "the quorum is met by distinct signing keys under the edition's terms"},
	{"not ready", "readiness", "the quorum is not met yet"},
	// a task submission's state and a task decision (task-contracts note §5.1, §5.8); `counted`, `not counted`,
	// `unknown`, `unchecked` and `contested` are the rows above, read for a task
	{"undecided", "submission", "a condition of the edition's terms is unchecked for the submission and none failed: left out of the lower count, in the upper one; never a veto"},
	{"not shown", "submission", "a deadline outcome: no verified bound shows the submission existed by the deadline height (a ts or a local bound meets nothing); the submission is not counted"},
	{"accept", "decision", "the verdict of a `decide`: the beneficiary accepts the cited submissions; it settles only when the decision counts"},
	{"reject", "decision", "the verdict of a `decide`: the beneficiary rejects the cited submissions; it settles only when the decision counts"},
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
	// explain --since: each change between a saved explain and the answer now, with its cause (claims §13, I14, I5)
	{"answer changed", "since", "something explain prints beyond its causes (a token, a count, a view) differs from the saved explain"},
	{"answer unchanged", "since", "everything explain prints beyond its causes is as in the saved explain"},
	{"statement added", "since", "a statement is an input of the answer now and was not in the saved explain (its id)"},
	{"statement removed", "since", "a statement of the saved explain is no longer an input of the answer (its id)"},
	{"key event", "since", "a rotate_key or revoke_key of an input's signer arrived (its id and kind): it decides which of that key's lines count"},
	{"status changed", "since", "an input's statement status differs (its id, before and after)"},
	{"line changed", "since", "an input's place in its signer's log differs, e.g. detached to chained (its id, before and after)"},
	{"counted changed", "since", "whether an input counts differs (its id, before and after); a key event or a missing predecessor is the usual cause"},
	{"policy changed", "since", "the hub policy digest differs (before and after)"},
	{"reader policy changed", "since", "the reader policy digest differs; each entry one side has and the other lacks is named"},
	{"time policy changed", "since", "the time policy fingerprint differs"},
	{"evaluator changed", "since", "the tool version, commit or time verifier differs"},
	{"time context changed", "since", "the time context of the answer differs (a read time it depends on, or the clock no longer read)"},
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
	"counted", "labels", "bytes", "causes", "store_state", "what", "verdict", "class", "status_scope", "change", "answer"}

// IsTokenKey reports whether a JSON member of that name carries tokens.
func IsTokenKey(k string) bool { return slices.Contains(tokenKeys, k) }

// causeToken is the token at the end of a verify cause ("authorship: contested" → "contested").
func causeToken(why string) string {
	if i := strings.LastIndex(why, ": "); i >= 0 {
		return why[i+2:]
	}
	return why
}
