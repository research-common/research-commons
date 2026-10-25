package cli

import (
	"io"
	"slices"

	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/keylog"
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

// The reader's time verifier. No chain backend is configured by any command yet (the receipt store and the
// header sync command are not built), so every anchor whose proof parses evaluates to backend-unconfigured:
// a state, exit 3 where a bound is needed, never a failed invocation (claims-model note §13, C-core-133a (e)).
func newTimeVerifier(s *store.Store) *btctime.Verifier {
	return &btctime.Verifier{Policy: btctime.DefaultPolicy(), Blobs: storeBlobs{s}}
}

func loadView(s *store.Store) (*view, error) {
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
	tv := newTimeVerifier(s)
	r := resolve.New(logs, resolve.WithTimeVerifier(btctime.TimeVerifier{V: tv}))
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
