package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
)

// Response layouts through the commands (claims-model note §5.3.1a, "Response layouts"). Fixtures are synthetic
// settlement-shaped JSON, never real data.

var cliLayout = canon.Encode(obj("layout", resolve.ResponseLayoutTag, "records", "/data", "state", "/settlementRunType"))

func cliResponse(runs ...string) []byte {
	var rs []string
	for i, r := range runs {
		if r == "" {
			rs = append(rs, fmt.Sprintf(`{"settlementPeriod":%d,"quantity":0.5}`, i+1))
			continue
		}
		rs = append(rs, fmt.Sprintf(`{"settlementPeriod":%d,"settlementRunType":"%s","quantity":0.5}`, i+1, r))
	}
	return []byte(`{"data":[` + strings.Join(rs, ",") + `]}`)
}

// layoutStore is a store holding profile P (SF < R1 < R2 < RF < DF), which cites the layout in its documents when
// cite is true, the layout blob, the response resp (when not nil) and one source observation `run >= RF` citing P
// at asserted state; the store-root policy pins P.
func layoutStore(t *testing.T, cite bool, resp []byte, asserted string) (w *world, id string) {
	t.Helper()
	ld := dig(string(cliLayout))
	kv := []any{"profile", resolve.SourceProfileTag, "source", "https://api.example/settlement", "dialect", resolve.DialectOrderedLabel,
		"labels", []string{"SF", "R1", "R2", "RF", "DF"}}
	if cite {
		kv = append(kv, "documents", []string{ld})
	}
	prof := canon.Encode(obj(kv...))
	pd := dig(string(prof))
	w = newWorld(t)
	w.blob("p", prof)
	w.blob("l", cliLayout)
	rd := dig("a response this store does not hold")
	if resp != nil {
		rd = w.blob("r", resp)
	}
	if err := os.WriteFile(filepath.Join(w.root, PolicyFile),
		[]byte(`{"policy":"rc-hub-policy/1","series":{"source_profiles":[{"digest":"`+pd+`"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", "x"), "response_digest", rd)
	id = w.sign("O", "O", "observed", obj("content", content("x"), "class", "source", "referent", canon.Value(ref),
		"capture", obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"),
		"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", asserted))))
	return w, id
}

// TestObservationLayoutThroughCommands: C-core-104g through verify, show and explain. (a) the held response's
// records carry labels in the profile: the least record's state, read from the bytes, governs (`final (as held)`;
// provisional at the read state), records that differ are disclosed as a spread, and an asserted state that differs
// is disclosed beside it; (b) a record's label is outside the profile, a record lacks the field, the bytes are not
// JSON, or the response is not held: the layout read is unchecked naming why and the referent reads exactly as the
// same store without a layout (never upgraded); (c) no layout cited: the alpha output, no layout line. The layout
// read never moves verify's exit.
func TestObservationLayoutThroughCommands(t *testing.T) {
	conformance.Covers(t, "C-core-104g")
	for _, c := range []struct {
		name     string
		cite     bool
		resp     []byte
		asserted string
		want     []string
		not      []string
	}{
		{"(a) agree", true, cliResponse("RF", "RF"), "RF",
			[]string{"referent:\n  status: final (as held)\n", "state RF read from the held response"},
			[]string{"as captured", "disclosed"}},
		{"(a) agree, asserted differs", true, cliResponse("R1", "R1"), "RF",
			[]string{"  status: provisional\n  detail: R1; final at RF\n", "the observer asserted RF at capture (disclosed, does not govern)"},
			[]string{"as captured", "final (as held)"}},
		{"(a) mixed: the least record", true, cliResponse("R1", "RF"), "RF",
			[]string{"  status: provisional\n  detail: R1; final at RF\n", "state R1 read from the held response (records at R1..RF, read as R1); the observer asserted RF at capture (disclosed, does not govern)"},
			[]string{"as captured", "final (as held)"}},
		{"(a) mixed, every record final: final as held at the least", true, cliResponse("DF", "RF"), "DF",
			[]string{"referent:\n  status: final (as held)\n", "state RF read from the held response (records at RF..DF, read as RF)"},
			[]string{"as captured"}},
		{"(b) one record outside the profile", true, cliResponse("R1", "II", "RF"), "RF",
			[]string{"  status: final (as captured, not re-checked)\n", `unchecked (record 1 reads "II", which is not in the source profile's labels`},
			[]string{"as held"}},
		{"(b) field missing", true, cliResponse("RF", ""), "RF",
			[]string{"  status: final (as captured, not re-checked)\n", `unchecked (record 1: state pointer "/settlementRunType": no member`},
			[]string{"as held"}},
		{"(b) not JSON", true, []byte("settlementRunType\nRF\n"), "RF",
			[]string{"  status: final (as captured, not re-checked)\n", "unchecked (the response is not I-JSON"},
			[]string{"as held"}},
		{"(b) not held", true, nil, "R1",
			[]string{"  status: provisional\n  detail: R1; final at RF\n", "not held)"},
			[]string{"as held"}},
		{"(c) no layout cited", false, cliResponse("R1", "R1"), "RF",
			[]string{"  status: final (as captured, not re-checked)\n"},
			[]string{"layout", "as held"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, id := layoutStore(t, c.cite, c.resp, c.asserted)
			for _, cmd := range []string{"verify", "show", "explain"} {
				r := w.run(cmd, id)
				if cmd == "verify" && r.code != ExitOK {
					t.Fatalf("verify: exit %d, want 0 (a layout read is a disclosure):\n%s", r.code, r.stdout)
				}
				for _, s := range c.want {
					if !strings.Contains(r.stdout, s) {
						t.Fatalf("%s: want %q:\n%s", cmd, s, r.stdout)
					}
				}
				for _, s := range c.not {
					if strings.Contains(r.stdout, s) {
						t.Fatalf("%s: has %q:\n%s", cmd, s, r.stdout)
					}
				}
			}
		})
	}
	// never upgraded: an unchecked read gives the referent the same store without the layout cited gives
	for _, asserted := range []string{"RF", "R1"} {
		with, id1 := layoutStore(t, true, cliResponse("R1", "II"), asserted)
		without, id2 := layoutStore(t, false, cliResponse("R1", "II"), asserted)
		a, b := referentLines(with.run("verify", id1).stdout), referentLines(without.run("verify", id2).stdout)
		if a != b {
			t.Fatalf("asserted %s: with an unchecked layout read %q, without a layout %q", asserted, a, b)
		}
	}
}

// TestLayoutHeldCorruptThroughCommands: the store's copy of the layout the pinned profile cites hashes elsewhere.
// The layout read names the corrupt held copy (it was skipped silently before, reading as no layout); the referent
// reads exactly as with no layout cited (never upgraded); verify still exits 0.
func TestLayoutHeldCorruptThroughCommands(t *testing.T) {
	w, id := layoutStore(t, true, cliResponse("RF", "RF"), "RF")
	ld := dig(string(cliLayout))
	bp := filepath.Join(w.root, "blobs", "sha256", strings.TrimPrefix(ld, "sha256:"))
	if err := os.Chmod(bp, 0o644); err != nil { // blobs are installed read-only
		t.Fatal(err)
	}
	if err := os.WriteFile(bp,
		canon.Encode(obj("layout", resolve.ResponseLayoutTag, "records", "/data", "state", "/other")), 0o644); err != nil {
		t.Fatal(err)
	}
	r := w.run("verify", id)
	if r.code != ExitOK {
		t.Fatalf("verify: exit %d:\n%s", r.code, r.stdout)
	}
	for _, s := range []string{"  status: final (as captured, not re-checked)\n", "unchecked (document " + keylog.Short(ld) + " is held corrupt (its bytes hash elsewhere)"} {
		if !strings.Contains(r.stdout, s) {
			t.Fatalf("want %q:\n%s", s, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "as held") {
		t.Fatalf("a corrupt layout read the bytes:\n%s", r.stdout)
	}
}

// referentLines is verify's referent status and detail, without the layout line.
func referentLines(out string) string {
	var keep []string
	in := false
	for _, l := range strings.Split(out, "\n") {
		switch {
		case l == "referent:":
			in = true
		case in && strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "  layout:"):
			keep = append(keep, l)
		case in && !strings.HasPrefix(l, "  "):
			in = false
		}
	}
	return strings.Join(keep, "\n")
}

// TestPullLayoutAsHeld: C-core-104h through pull. The receiving store pins a profile citing the layout and holds
// both; the package carries a series whose segments all assert DF and whose responses read R2 for April and May.
// The premature edition (frozen_before 2025-06-01) is refused on the bytes, as held. Control: the same package
// under the profile without the layout is refused on the asserted states only (final to the last window, as
// captured), never as held.
func TestPullLayoutAsHeld(t *testing.T) {
	conformance.Covers(t, "C-core-104h")
	ld := dig(string(cliLayout))
	for _, cite := range []bool{true, false} {
		kv := []any{"profile", resolve.SourceProfileTag, "source", "https://api.example/settlement", "dialect", resolve.DialectOrderedLabel,
			"labels", []string{"SF", "R1", "R2", "RF", "DF"}}
		if cite {
			kv = append(kv, "documents", []string{ld})
		}
		prof := canon.Encode(obj(kv...))
		pd := dig(string(prof))
		src := newWorld(t)
		g := src.sign("G", "C", "genesis", obj("type", "series", "name", "settlements", "controllers", []string{src.signer("C")}, "rule", obj("any_one", true)))
		segs := canon.Array{}
		for i := 0; i < 5; i++ {
			m := fmt.Sprintf("2025-%02d", i+1)
			run := "RF"
			if i >= 3 {
				run = "R2"
			}
			resp := cliResponse(run, run)
			rd := src.blob("resp"+m, resp)
			ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", m), "response_digest", rd,
				"window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z"))
			id := src.sign("S"+m, "O", "observed", obj("content", obj("digest", rd, "size", len(resp)), "class", "source", "referent", canon.Value(ref),
				"capture", obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"),
				"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", "DF"))))
			segs = append(segs, obj("statement", id, "role", "segment"))
		}
		src.sign("E", "C", "edition", obj("resource", g, "predecessors", []string{g}, "contents", obj("members", segs, "frozen_before", obj("date", "2025-06-01"))))
		dst := newWorld(t)
		dst.blob("profile", prof)
		dst.blob("layout", cliLayout)
		os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(profilePin(pd)), 0o644)
		r := dst.run("pull", src.root, "--json")
		if !cite {
			if r.code != 1 || !strings.Contains(r.stdout, "members final to 2025-05-28 as captured, not re-checked") || strings.Contains(r.stdout, "as held") {
				t.Fatalf("control: exit %d\n%s", r.code, r.stdout)
			}
			continue
		}
		if r.code != 1 || !strings.Contains(r.stdout, "series.refuse_premature_freeze") ||
			!strings.Contains(r.stdout, "members final to 2025-04-01 as held (2 segments provisional)") || !strings.Contains(r.stdout, src.ids["E"]) {
			t.Fatalf("as held: exit %d\n%s", r.code, r.stdout)
		}
	}
}

// TestGCKeepsPinnedProfileLayout: the response layout a pinned profile cites is kept by `gc --apply` past the grace
// window (named as pinned by the policy) and is not unreferenced to fsck, so the profile's layout reads survive gc
// (C-core-147 extended to the layout). Control: the same layout blob under a pinned profile that does not cite it is
// collected.
func TestGCKeepsPinnedProfileLayout(t *testing.T) {
	ld := dig(string(cliLayout))
	for _, cite := range []bool{true, false} {
		w, _ := layoutStore(t, cite, cliResponse("RF"), "RF")
		r := w.run("gc", "--apply", "--grace", "0s", "--json")
		if r.code != 0 || w.s.HasBlob(store.Digest(ld)) != cite {
			t.Fatalf("cite %v: gc exit %d, layout held %v\n%s", cite, r.code, w.s.HasBlob(store.Digest(ld)), r.stdout)
		}
		if !cite {
			continue
		}
		if !strings.Contains(r.stdout, ld) || !strings.Contains(r.stdout, "pinned by "+PolicyFile+" series.source_profiles") {
			t.Fatalf("the kept layout is not named as pinned:\n%s", r.stdout)
		}
		if f := w.run("fsck", "--json"); strings.Contains(f.stdout, ld) {
			t.Fatalf("fsck lists the pinned profile's layout:\n%s", f.stdout)
		}
	}
}
