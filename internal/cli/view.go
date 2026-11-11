package cli

import (
	"io"
	"slices"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
	"github.com/research-common/research-commons/internal/wire"
)

// view is the reader's resolution of one store: every installed statement (storage note §3.3: readers
// resolve from installed statements only), delivered into per-key logs, and one resolver over them. Every
// command that answers about an artifact builds exactly one view, so every surface answers from the same
// statements, policy and evaluator (C-core-134).
type view struct {
	r     *resolve.Resolver
	logs  *keylog.Store
	st    *store.Store
	timeV *btctime.Verifier
	// evidence caches the time verifier's record per anchors statement, so one invocation reports one state
	// per anchor however many surfaces print it.
	evidence map[string]btctime.Evidence
}

// storeBlobs lets the time verifier read proof blobs from the store: re-hashed on open, never fetched.
type storeBlobs struct{ s *store.Store }

func (b storeBlobs) OpenBlob(d string) (io.ReadCloser, bool) {
	f, err := b.s.OpenBlob(store.Digest(d))
	if err != nil {
		return nil, false
	}
	return f, true
}

// verifiedBlobs tells the resolver which blobs this store holds intact: a blob counts as held only when its
// bytes re-hash to its digest (storage note §2), so a corrupt copy is never shown as a reveal.
type verifiedBlobs struct{ s *store.Store }

func (b verifiedBlobs) Has(d string) bool {
	f, err := b.s.OpenBlob(store.Digest(d))
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// The reader's time verifier with no chain backend: every anchor whose proof parses evaluates to
// backend-unconfigured, a state, exit 3 where a bound is needed, never a failed invocation (claims-model note §13,
// C-core-133a (e)). loadView uses it; the read commands build theirs from the persisted header database through
// timeVerifierFor (chain.go), which falls back to exactly this when the reader has none.
func newTimeVerifier(s *store.Store) *btctime.Verifier {
	return &btctime.Verifier{Policy: btctime.DefaultPolicy(), Blobs: storeBlobs{s}}
}

// loadView builds the view under the reader policy rp (nil = no reader policy: every answer is the no-policy
// answer) with no chain backend; opts are extra resolver options (publish's pre-pin check passes its rule dialects
// and content reader).
func loadView(s *store.Store, rp *policy.Policy, opts ...resolve.Option) (*view, error) {
	return buildView(s, rp, newTimeVerifier(s), opts...)
}

// buildView is loadView with the time verifier given: one verifier, over one immutable chain snapshot, answers
// every anchor of the invocation (bitcoin-time note §6.3).
func buildView(s *store.Store, rp *policy.Policy, tv *btctime.Verifier, opts ...resolve.Option) (*view, error) {
	lines, err := s.Statements()
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(lines))
	for id := range lines {
		ids = append(ids, id)
	}
	slices.Sort(ids) // order changes no answer (every answer is a function of the held set); sorted for repeatability
	logs := keylog.NewStore()
	for _, id := range ids {
		st, err := wire.Read(lines[id])
		if err != nil {
			continue // Statements already verified it; a line that no longer reads is fsck's to report
		}
		logs.Log(st.Signer).Add(lines[id]) // a log-relative refusal keeps the line; it is part of the view
	}
	// The read time is the writer/reader clock Now (tests replace it), passed in: the resolver reads no clock of
	// its own, so an answer that depends on time (a shelf-life age) is a function of the held set and this
	// time context (claims-model note I14; storage note §5.1). The blob index re-hashes on every question.
	base := []resolve.Option{resolve.WithTimeVerifier(btctime.TimeVerifier{V: tv}), resolve.WithPolicy(rp),
		resolve.WithBlobIndex(verifiedBlobs{s}), resolve.WithReadTime(Now())}
	r := resolve.New(logs, append(base, opts...)...)
	return &view{r: r, logs: logs, st: s, timeV: tv, evidence: map[string]btctime.Evidence{}}, nil
}

func (v *view) anchorEvidence(id string) (btctime.Evidence, bool) {
	if e, ok := v.evidence[id]; ok {
		return e, true
	}
	p, ok := v.r.Statement(id)
	if !ok || p.St.Kind != "anchors" {
		return btctime.Evidence{}, false
	}
	e := v.timeV.Evaluate(p.St)
	v.evidence[id] = e
	return e, true
}

// lineState is the log state of a statement: chained, detached or retained (not placed).
func (v *view) lineState(id string) string {
	p, ok := v.r.Statement(id)
	switch {
	case ok && p.Chained:
		return "chained"
	case ok:
		return "detached"
	}
	return "retained"
}

// scoped adds the view's footer: one status_scope member, last, saying what every status above it holds within
// (claims-model note §6 (1) "status is always scoped", I4). Authorship, a verify exit, a statement's counted
// state and the other tokens are printed bare; the scope is printed once per view, not inside each token, so
// the tokens stay closed and one scope line covers them all.
func (v *view) scoped(o *Obj) *Obj {
	return o.set("status_scope", tokV(tok(v.r.Scope())))
}
