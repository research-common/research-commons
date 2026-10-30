package wire_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// TestCriticalExtensionStillChains checks the public default-reader boundary without changing the log's
// reader configuration. Unsupported body semantics must not lose verified linkage or block a successor.
func TestCriticalExtensionStillChains(t *testing.T) {
	seed := sha256.Sum256([]byte("public disposable critical-extension chaining test key"))
	k := wire.Ed25519Key{Seed: seed[:]}
	parseBody := func(text string) *canon.Object {
		t.Helper()
		v, err := canon.Parse([]byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return v.(*canon.Object)
	}
	first, firstID := wire.Sign(wire.Draft{
		Kind: "observed", TS: "2026-10-15T00:00:00Z", Crit: []string{"x_test"},
		Body: parseBody(`{"x_test":true,"capture":{"at":"not a time"}}`),
	}, k)
	next, nextID := wire.Sign(wire.Draft{
		Kind: "retracts", Seq: 1, Prev: firstID, TS: "2026-10-15T00:00:01Z",
		Body: parseBody(`{"of":"` + firstID + `"}`),
	}, k)
	for _, order := range [][][]byte{{first, next}, {next, first}} {
		log := keylog.NewStore().Log(k.Signer())
		for _, line := range order {
			if _, err := log.Add(line); err != nil {
				t.Fatal(err)
			}
		}
		view := log.View()
		if len(view.Refused) != 0 || len(view.Retained) != 0 || len(view.Lines) != 2 || len(view.Tips) != 1 || view.Tips[0] != nextID {
			t.Fatalf("unsupported critical extension damaged chaining: %+v", view)
		}
		for _, line := range view.Lines {
			if line.State != keylog.Chained || !line.St.Verified {
				t.Fatalf("line not verified and chained: %+v", line)
			}
		}
		st := view.Lines[0].St
		if st.ID != firstID || st.Status != wire.Unsupported || st.Why != "crit x_test" || !bytes.Equal(st.Line(), first) {
			t.Fatalf("unsupported statement was not retained exactly: %+v", st)
		}
	}
}
