package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/reqlog"
	"github.com/research-common/research-commons/internal/resolve"
)

// singleLayoutGoldenCases are the single-request response-layout fixtures of C-core-104g, whose outputs a batch read
// must leave byte for byte as they were: a batch read applies only to a capture that pins a request log.
var singleLayoutGoldenCases = []struct {
	name     string
	cite     bool
	resp     []byte
	asserted string
}{
	{"agree", true, cliResponse("RF", "RF"), "RF"},
	{"asserted-differs", true, cliResponse("R1", "R1"), "RF"},
	{"mixed", true, cliResponse("R1", "RF"), "RF"},
	{"mixed-final", true, cliResponse("DF", "RF"), "DF"},
	{"outside-profile", true, cliResponse("R1", "II", "RF"), "RF"},
	{"field-missing", true, cliResponse("RF", ""), "RF"},
	{"not-json", true, []byte("settlementRunType\nRF\n"), "RF"},
	{"not-held", true, nil, "R1"},
	{"no-layout", false, cliResponse("R1", "R1"), "RF"},
}

// TestSingleLayoutOutputsUnchanged: the batch layout read leaves every single-request observation's `verify`,
// `show` and `explain` output (text and --json) byte-identical to the goldens recorded before it existed.
// RC_UPDATE_GOLDEN=1 rewrites them.
func TestSingleLayoutOutputsUnchanged(t *testing.T) {
	for _, c := range singleLayoutGoldenCases {
		t.Run(c.name, func(t *testing.T) {
			w, id := layoutStore(t, c.cite, c.resp, c.asserted)
			var b bytes.Buffer
			for _, args := range [][]string{{"verify", id}, {"show", id}, {"explain", id}, {"verify", id, "--json"}, {"explain", id, "--json"}} {
				r := w.run(args...)
				b.WriteString("$ " + strings.Join(args[:1], " ") + " " + strings.Join(args[2:], " ") + "\n")
				b.WriteString("exit " + string(rune('0'+r.code)) + "\n")
				b.WriteString(strings.ReplaceAll(r.stdout, w.root, "$ROOT"))
			}
			p := filepath.Join("testdata", "single_layout_golden", c.name+".golden")
			if os.Getenv("RC_UPDATE_GOLDEN") == "1" {
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, b.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, b.Bytes()) {
				t.Fatalf("%s changed:\n--- want\n%s\n--- got\n%s", c.name, want, b.Bytes())
			}
		})
	}
}

const batchLayoutEP = "https://api.example/v1/settlements"

// batchLayoutStore is a store whose root policy pins profile P (SF < R1 < R2 < RF < DF), citing the layout when cite
// is true, holding one batch source observation `run >= RF` citing P at asserted state: its content is a tar of the
// rc-request-log/1 log and the responses (drop leaves the archive without the 0-based response drop; -1 keeps all;
// -2 keeps all but the store never holds the archive).
func batchLayoutStore(t *testing.T, cite bool, asserted string, drop int, resps ...[]byte) (w *world, id string) {
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
	var es []reqlog.Entry
	files := [][2]string{{"requests.jsonl", ""}}
	for i, r := range resps {
		es = append(es, reqlog.Entry{Endpoint: batchLayoutEP, Parameters: obj("period", string(rune('1'+i))), Status: 200,
			Time: "2026-10-16T05:00:0" + string(rune('0'+i)) + "Z", ResponseDigest: dig(string(r))})
		if i != drop {
			files = append(files, [2]string{"r" + string(rune('1'+i)) + ".json", string(r)})
		}
	}
	log := reqlog.Encode(es)
	files[0][1] = string(log)
	archive := tarOf(t, files...)
	cd := dig(string(archive))
	if drop != -2 {
		cd = w.blob("archive", archive)
	}
	if err := os.WriteFile(filepath.Join(w.root, PolicyFile),
		[]byte(`{"policy":"rc-hub-policy/1","series":{"source_profiles":[{"digest":"`+pd+`"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	id = w.sign("B", "O", "observed", obj("content", obj("digest", cd, "size", len(archive)), "class", "source",
		"referent", obj("requests", obj("digest", dig(string(log)), "format", reqlog.Format, "count", len(resps), "endpoint", batchLayoutEP)),
		"capture", obj("at", "2026-10-16T05:01:00Z", "evidence", "self-asserted"),
		"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", asserted))))
	return w, id
}

// TestBatchLayoutThroughCommands: C-core-104i through verify, show and explain. (a) every logged response is held
// and read: the batch reads at the least state over every response's least record, the spread across responses
// disclosed, independent of the responses' order in the log; (b) the archive lacks a logged response (the log check
// fails, exit 1), a response's record is outside the profile (the rest counted), or the content is not held (exit
// 3): the layout read is unchecked naming the first offending entry by index and endpoint, and the referent reads
// exactly as the same store with no layout cited. The layout read never moves verify's exit.
func TestBatchLayoutThroughCommands(t *testing.T) {
	conformance.Covers(t, "C-core-104i")
	r1, r2, r3 := cliResponse("RF", "RF"), cliResponse("R2", "RF"), cliResponse("DF")
	final := [][]byte{cliResponse("RF"), cliResponse("RF", "RF"), cliResponse("DF", "RF")}
	bad := [][]byte{cliResponse("RF"), cliResponse("RF", "II"), cliResponse("RF", "")}
	for _, c := range []struct {
		name     string
		asserted string
		drop     int
		resps    [][]byte
		exit     int
		want     []string
		not      []string
	}{
		{"(a) every response final", "RF", -1, final, ExitOK,
			[]string{"referent:\n  status: final (as held)\n", "state RF read from the 3 held responses (records at RF..DF across 3 responses, read as RF)"},
			[]string{"as captured", "disclosed"}},
		{"(a') mixed: the least response's least record", "RF", -1, [][]byte{r1, r2, r3}, ExitOK,
			[]string{"  status: provisional\n  detail: R2; final at RF\n",
				"state R2 read from the 3 held responses (records at R2..DF across 3 responses, read as R2); the observer asserted RF at capture (disclosed, does not govern)"},
			[]string{"as captured", "final (as held)"}},
		{"(a'') mixed, another log order", "RF", -1, [][]byte{r3, r1, r2}, ExitOK,
			[]string{"  status: provisional\n  detail: R2; final at RF\n", "(records at R2..DF across 3 responses, read as R2)"},
			[]string{"final (as held)"}},
		{"(b) a logged response missing from the archive", "RF", 1, [][]byte{r1, r2, r3}, ExitWrong,
			[]string{"  status: final (as captured, not re-checked)\n", "unchecked (request log fail (entry 2, endpoint " + batchLayoutEP + ": response"},
			[]string{"as held"}},
		{"(b') a response the layout cannot read", "RF", -1, bad, ExitOK,
			[]string{"  status: final (as captured, not re-checked)\n", "unchecked (entry 2, endpoint " + batchLayoutEP + ": response",
				`record 1 reads \"II\"`, "1 more of the 3 responses not read"},
			[]string{"as held"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			w, id := batchLayoutStore(t, true, c.asserted, c.drop, c.resps...)
			control, cid := batchLayoutStore(t, false, c.asserted, c.drop, c.resps...)
			for _, cmd := range []string{"verify", "show", "explain"} {
				r := w.run(cmd, id)
				if cmd == "verify" && r.code != c.exit {
					t.Fatalf("verify: exit %d, want %d (the request-log check decides):\n%s", r.code, c.exit, r.stdout)
				}
				out := strings.ReplaceAll(r.stdout, `\"`, `"`)
				for _, s := range c.want {
					if !strings.Contains(out, strings.ReplaceAll(s, `\"`, `"`)) {
						t.Fatalf("%s: want %q:\n%s", cmd, s, r.stdout)
					}
				}
				for _, s := range c.not {
					if strings.Contains(r.stdout, s) {
						t.Fatalf("%s: has %q:\n%s", cmd, s, r.stdout)
					}
				}
			}
			if cr := control.run("verify", cid); cr.code != c.exit || strings.Contains(cr.stdout, "layout") {
				t.Fatalf("control: exit %d\n%s", cr.code, cr.stdout)
			}
			if strings.Contains(c.name, "(b") {
				// never upgraded: the referent lines match the same store without the layout cited
				if a, b := referentStatusLines(w.run("verify", id).stdout), referentStatusLines(control.run("verify", cid).stdout); a != b {
					t.Fatalf("with an unchecked batch read %q, without a layout %q", a, b)
				}
			}
		})
	}
	// (b'') the content is not held: the log is unchecked (exit 3), so is the read
	w, id := batchLayoutStore(t, true, "RF", -2, final...)
	r := w.run("verify", id)
	if r.code != ExitCouldNot || !strings.Contains(r.stdout, "unchecked (request log unchecked (content not held): no response is read)") ||
		!strings.Contains(r.stdout, "  status: final (as captured, not re-checked)\n") {
		t.Fatalf("content not held: exit %d\n%s", r.code, r.stdout)
	}
}

// referentStatusLines is the referent's status and detail lines of a text output (the layout line excluded).
func referentStatusLines(out string) string {
	var keep []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "  status: ") || strings.HasPrefix(l, "  detail: ") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}
