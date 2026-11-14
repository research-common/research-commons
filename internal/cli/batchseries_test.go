package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/reqlog"
	"github.com/research-common/research-commons/internal/resolve"
)

// TestPullBatchSegmentsAsHeld: C-core-104h, the batch variant, through pull. The receiving store pins a profile
// citing the layout and holds both; the package carries a series whose five segments are batch captures asserting DF,
// each an archive of its request log and two responses, the second reading R2 for April and May. Each segment reads
// at its least logged response through its log, so the premature edition (frozen_before 2025-06-01) is refused on the
// bytes, as held. Variant: April's archive lacks its second logged response (its log check fails): April's asserted
// DF is used, the boundary is the weaker `as captured, not re-checked` at May. Control: the same package under the
// profile without the layout is refused on the asserted states only, never as held.
func TestPullBatchSegmentsAsHeld(t *testing.T) {
	conformance.Covers(t, "C-core-104h")
	ld := dig(string(cliLayout))
	for _, c := range []struct {
		name string
		cite bool
		drop int // 1-based month whose archive lacks its second response; 0 none
		want string
	}{
		{"held", true, 0, "members final to 2025-04-01 as held (2 segments provisional)"},
		{"one log fails", true, 4, "members final to 2025-05-01 as captured, not re-checked (1 segment provisional)"},
		{"control", false, 0, "members final to 2025-05-28 as captured, not re-checked"},
	} {
		t.Run(c.name, func(t *testing.T) {
			kv := []any{"profile", resolve.SourceProfileTag, "source", "https://api.example/settlement", "dialect", resolve.DialectOrderedLabel,
				"labels", []string{"SF", "R1", "R2", "RF", "DF"}}
			if c.cite {
				kv = append(kv, "documents", []string{ld})
			}
			prof := canon.Encode(obj(kv...))
			pd := dig(string(prof))
			src := newWorld(t)
			g := src.sign("G", "C", "genesis", obj("type", "series", "name", "settlements", "controllers", []string{src.signer("C")}, "rule", obj("any_one", true)))
			segs := canon.Array{}
			for i := 0; i < 5; i++ {
				m := fmt.Sprintf("2025-%02d", i+1)
				second := "RF"
				if i >= 3 {
					second = "R2"
				}
				resps := [][]byte{cliResponse("RF", "RF"), cliResponse(second, "RF")}
				var es []reqlog.Entry
				files := [][2]string{{"requests.jsonl", ""}}
				for j, r := range resps {
					es = append(es, reqlog.Entry{Endpoint: batchLayoutEP, Parameters: obj("period", m, "part", fmt.Sprint(j+1)), Status: 200,
						Time: fmt.Sprintf("2026-01-02T00:00:0%dZ", j), ResponseDigest: dig(string(r))})
					if !(c.drop == i+1 && j == 1) {
						files = append(files, [2]string{fmt.Sprintf("r%d.json", j+1), string(r)})
					}
				}
				log := reqlog.Encode(es)
				files[0][1] = string(log)
				archive := tarOf(t, files...)
				cd := src.blob("archive"+m, archive)
				ref := obj("requests", obj("digest", dig(string(log)), "format", reqlog.Format, "count", len(resps), "endpoint", batchLayoutEP),
					"window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z"))
				id := src.sign("S"+m, "O", "observed", obj("content", obj("digest", cd, "size", len(archive)), "class", "source", "referent", canon.Value(ref),
					"capture", obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"),
					"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", "DF"))))
				segs = append(segs, obj("statement", id, "role", "segment"))
			}
			src.sign("E", "C", "edition", obj("resource", g, "predecessors", []string{g}, "contents", obj("members", segs, "frozen_before", obj("date", "2025-06-01"))))
			dst := newWorld(t)
			dst.blob("profile", prof)
			dst.blob("layout", cliLayout)
			if err := os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(profilePin(pd)), 0o644); err != nil {
				t.Fatal(err)
			}
			r := dst.run("pull", src.root, "--json")
			if r.code != 1 || !strings.Contains(r.stdout, "series.refuse_premature_freeze") || !strings.Contains(r.stdout, c.want) || !strings.Contains(r.stdout, src.ids["E"]) {
				t.Fatalf("%s: exit %d, want %q\n%s", c.name, r.code, c.want, r.stdout)
			}
			if c.name != "held" && strings.Contains(r.stdout, "as held (") {
				t.Fatalf("%s: the boundary is as held:\n%s", c.name, r.stdout)
			}
		})
	}
}
