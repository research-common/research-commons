package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestRepairMissingBlob: C-core-126 through the repair command. A publish commits and cannot install (its key's
// statement directory is read-only), so its record stays pending; status and repair still run (degraded open) and
// repair exits 3 naming the failure. Its blob is then removed and the permission fixed: the next open installs the
// statements and step 5 finds the blob missing, so the operation is `committed, needs repair` and every statement
// still resolves (nothing hidden, nothing rolled back). repair without the bytes exits 3 naming the blob, fetch and
// --blob; --blob with other bytes is refused before anything runs; a malformed id exits 2 and a well-formed unknown one
// is `nothing to repair` (exit 0). A tampered pending record is quarantined on open with nothing from it shown, and
// repair leaves quarantine/ as it is (printing the count). A statement file of the done record removed by hand is
// reinstalled. With the right bytes repair exits 0: the statement set is the one committed, status says `nothing
// pending`.
func TestRepairMissingBlob(t *testing.T) {
	conformance.Covers(t, "C-core-126")
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions; the fault cannot be injected")
	}
	p := newPubWorld(t)
	data := "the bytes the operation names"
	d := dig(data)
	blobPath := filepath.Join(p.root, "blobs", "sha256", strings.TrimPrefix(d, "sha256:"))
	sdir := filepath.Join(p.root, "statements", strings.ReplaceAll(p.signer, ":", "-"))
	stmts := filepath.Join(p.root, "statements")
	quar := filepath.Join(p.root, "quarantine")
	os.MkdirAll(sdir, 0o755)
	os.Chmod(sdir, 0o500) // step 3 fails after the record (step 2) is written, on every open until fixed
	t.Cleanup(func() { os.Chmod(sdir, 0o755) })

	r := p.publish("--kind", "authored", "--content", p.file("c", data))
	if r.code != ExitCouldNot || outObj(t, r).Members["committed"] != canon.Bool(true) {
		t.Fatalf("pending install: %d %s", r.code, r.stdout)
	}
	op := strings.TrimPrefix(string(outObj(t, r).Members["scope"].(canon.String)), "operation ")
	if !strings.Contains(r.stdout, "commons repair "+op) {
		t.Fatalf("the publish advice does not name repair: %s", r.stdout)
	}
	record, err := os.ReadFile(filepath.Join(p.root, "journal", "pending", op+".json"))
	if err != nil {
		t.Fatal(err)
	}

	// (1) a replay that fails: status and repair run (degraded open); repair exits 3 naming the operation, the error
	// and the next step, and changes nothing
	if st := p.run("status", "--json"); st.code != ExitOK || !strings.Contains(st.stdout, `"what":"replay failed"`) || !strings.Contains(st.stdout, op) {
		t.Fatalf("status under a failing replay: %d %s", st.code, st.stdout)
	}
	before := snapshot(t, p.root)
	for _, js := range []bool{true, false} {
		args := []string{"repair"}
		if js {
			args = append(args, "--json")
		}
		rp := p.run(args...)
		if rp.code != ExitCouldNot || !strings.Contains(rp.stdout, "replay failed") || !strings.Contains(rp.stdout, op) ||
			!strings.Contains(rp.stdout, "permission denied") || !strings.Contains(rp.stdout, "then run commons repair") {
			t.Fatalf("repair under a failing replay (json %v): %d %s", js, rp.code, rp.stdout)
		}
	}
	if snapshot(t, p.root) != before {
		t.Fatal("repair under a failing replay changed the store")
	}

	// (2) the blob goes missing and the permission is fixed: the next open installs the statements (steps 3, 4) and
	// step 5 finds the blob missing: committed, needs repair; every statement resolves
	if err := os.Remove(blobPath); err != nil {
		t.Fatal(err)
	}
	os.Chmod(sdir, 0o755)
	st := p.run("status", "--json")
	if st.code != ExitOK || !strings.Contains(st.stdout, `"store_state":"committed, needs repair"`) || !strings.Contains(st.stdout, `"what":"needs repair"`) {
		t.Fatalf("status with the blob missing: %d %s", st.code, st.stdout)
	}
	ents, _ := os.ReadDir(sdir)
	if len(ents) != 2 { // the authored and its holds
		t.Fatalf("statements installed: %v", ents)
	}
	var ids []string
	for _, e := range ents {
		ids = append(ids, e.Name())
	}
	showAll := func(when string) {
		t.Helper()
		for _, id := range ids {
			if s := p.run("show", id, "--json"); s.code == ExitDidNotStart || !strings.Contains(s.stdout, id) || strings.Contains(s.stdout, "no statement held") {
				t.Fatalf("%s: statement %s is not shown (hidden or rolled back): %d %s", when, id, s.code, s.stdout)
			}
		}
		if l := p.run("list", "--json"); l.code != ExitOK || !strings.Contains(l.stdout, d) {
			t.Fatalf("%s: list does not show the committed blob's statements: %d %s", when, l.code, l.stdout)
		}
	}
	showAll("needs repair")
	committed := snapshot(t, stmts)

	// (3) without the bytes: exit 3, naming the blob, fetch and --blob; nothing changes
	before = snapshot(t, p.root)
	for _, args := range [][]string{{"repair"}, {"repair", op}, {"repair", "--all"}} {
		rp := p.run(append(args, "--json")...)
		if rp.code != ExitCouldNot || !strings.Contains(rp.stdout, `"store_state":"committed, needs repair"`) || !strings.Contains(rp.stdout, `"missing_blobs":["`+d+`"]`) ||
			!strings.Contains(rp.stdout, "commons fetch "+d) || !strings.Contains(rp.stdout, "commons repair "+op+" --blob <file>") {
			t.Fatalf("%v without the bytes: %d %s", args, rp.code, rp.stdout)
		}
		if h := p.run(args...); h.code != ExitCouldNot || !strings.Contains(h.stdout, d) {
			t.Fatalf("%v human surface: %d %s", args, h.code, h.stdout)
		}
	}
	if snapshot(t, p.root) != before {
		t.Fatal("repair without the bytes changed the store")
	}

	// (4) other bytes: refused before the store is opened (exit 2), naming both digests; nothing changes
	wrong := p.file("wrong", "not the bytes the operation names")
	for _, args := range [][]string{{"repair", "--blob", wrong}, {"repair", op, "--blob", wrong}, {"repair", "--all", "--blob", wrong},
		{"repair", strings.Repeat("ab", 32), "--blob", p.file("right", data)}} {
		rp := p.run(append(args, "--json")...)
		o := outObj(t, rp)
		if rp.code != ExitDidNotStart || o.Members["type"] != canon.String(ProblemTypeBase+"blob-not-named") || o.Members["committed"] != canon.Bool(false) {
			t.Fatalf("%v: %d %s", args, rp.code, rp.stdout)
		}
	}
	if !strings.Contains(p.run("repair", "--blob", wrong, "--json").stdout, d) {
		t.Fatal("the refusal does not name the blob the record names")
	}
	// a malformed id, an id with --all: exit 2; a well-formed id no record has: nothing to repair, exit 0
	for _, args := range [][]string{{"repair", strings.ToUpper(op)}, {"repair", op[:12]}, {"repair", op, "--all"}, {"repair", "--blob", filepath.Join(p.dir, "absent")}} {
		if rp := p.run(append(args, "--json")...); rp.code != ExitDidNotStart {
			t.Fatalf("%v: %d %s", args, rp.code, rp.stdout)
		}
	}
	unknown := strings.Repeat("ab", 32)
	if rp := p.run("repair", unknown, "--json"); rp.code != ExitOK || !strings.Contains(rp.stdout, `"what":"nothing to repair"`) || !strings.Contains(rp.stdout, unknown) {
		t.Fatalf("an unknown operation: %d %s", rp.code, rp.stdout)
	}
	if snapshot(t, p.root) != before {
		t.Fatal("a refused or empty repair changed the store")
	}

	// (5) a tampered pending record (one line's bytes changed, its name the hash of what it now holds): the next open
	// quarantines it and installs nothing from it
	tampered := tamperRecord(t, record, d)
	tname := sha256.Sum256(bytes.TrimSuffix(tampered, []byte("\n")))
	if err := os.WriteFile(filepath.Join(p.root, "journal", "pending", hex.EncodeToString(tname[:])+".json"), tampered, 0o444); err != nil {
		t.Fatal(err)
	}
	if st := p.run("status", "--json"); st.code != ExitOK || !strings.Contains(st.stdout, `"what":"quarantined"`) || strings.Contains(st.stdout, "hashes to") {
		t.Fatalf("status over a tampered record: %d %s", st.code, st.stdout)
	}
	if snapshot(t, stmts) != committed {
		t.Fatal("a statement from the tampered record was installed")
	}
	if q, _ := os.ReadDir(quar); len(q) != 1 {
		t.Fatalf("quarantine: %v", q)
	}
	quarantined := snapshot(t, quar)

	// (6) a statement file of the done record removed by hand: repair reinstalls it from the record
	os.Remove(filepath.Join(sdir, ids[0]))

	// (7) the right bytes: exit 0; the statement set is the one committed (nothing deleted, nothing rolled back);
	// quarantine/ untouched and counted; status says nothing pending
	right := p.file("right", data)
	rp := p.run("repair", op, "--blob", right, "--json")
	if rp.code != ExitOK || !strings.Contains(rp.stdout, `"what":"projected"`) || !strings.Contains(rp.stdout, `"store_state":"nothing pending"`) ||
		!strings.Contains(rp.stdout, "1 item(s) under quarantine/") || !strings.Contains(rp.stdout, `"result":"installed"`) {
		t.Fatalf("repair with the bytes: %d %s", rp.code, rp.stdout)
	}
	if snapshot(t, stmts) != committed {
		t.Fatal("repair changed the committed statement set")
	}
	if snapshot(t, quar) != quarantined {
		t.Fatal("repair touched quarantine/")
	}
	if b, err := os.ReadFile(blobPath); err != nil || string(b) != data {
		t.Fatalf("blob not installed: %v", err)
	}
	if st := p.run("status", "--json"); st.code != ExitOK || !strings.Contains(st.stdout, `"store_state":"nothing pending"`) {
		t.Fatalf("status after repair: %d %s", st.code, st.stdout)
	}
	showAll("after repair")
	if rp := p.run("repair", "--json"); rp.code != ExitOK || !strings.Contains(rp.stdout, `"repaired":[]`) {
		t.Fatalf("repair of a clean store: %d %s", rp.code, rp.stdout)
	}
}

// tamperRecord changes one hex digit of digest d inside the record's lines (not its blobs list), keeping the record
// canonical: it still decodes, and the line no longer verifies.
func tamperRecord(t *testing.T, record []byte, d string) []byte {
	t.Helper()
	at := bytes.Index(record, []byte(`"lines":`))
	hexd := strings.TrimPrefix(d, "sha256:")
	i := bytes.Index(record[at:], []byte(hexd))
	if at < 0 || i < 0 {
		t.Fatalf("the record's lines do not name %s: %s", d, record)
	}
	out := bytes.Clone(record)
	c := &out[at+i]
	if *c == '0' {
		*c = '1'
	} else {
		*c = '0'
	}
	return out
}
