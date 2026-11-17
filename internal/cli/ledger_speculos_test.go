//go:build ledger_speculos

package cli

// The Ledger connector against a Speculos emulator running the official Ethereum app (Nano S Plus or Nano X model),
// not in CI. Set RC_LEDGER_SPECULOS=<host:port> (the APDU port) and RC_LEDGER_SPECULOS_API=<http://host:port> (the
// REST port, used to press the emulated buttons); the test skips when either is unset. Run with
//
//	go test -tags ledger_speculos -run TestLedgerSpeculos ./internal/cli
//
// It prepares an identity inception for the emulator's address at ledgerTestPath, rejects one key sign --ledger on
// the emulated device (exit 1, nothing written), approves the next (a goroutine walks the review to "Sign message"),
// and completes it: --complete runs the reader's verification, and the committed line carries the device's signature.
// Then it interrupts a review on the emulated screen (exit 3, review left open: ledger-busy) and rejects it there.

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/ledger"
)

type speculosAPI struct{ base string }

func (a speculosAPI) press(t *testing.T, which string) {
	r, err := http.Post(a.base+"/button/"+which, "application/json", strings.NewReader(`{"action":"press-and-release"}`))
	if err != nil {
		t.Errorf("button %s: %v", which, err)
		return
	}
	r.Body.Close()
}

func (a speculosAPI) screen(t *testing.T) string {
	r, err := http.Get(a.base + "/events?currentscreenonly=true")
	if err != nil {
		return ""
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	// Speculos writes "text": "…" with a space after the colon
	return strings.ReplaceAll(strings.ToLower(string(b)), `": "`, `":"`)
}

// walk presses right until the screen starts with target ("sign message" or "reject message"), then both.
func (a speculosAPI) walk(t *testing.T, target string, done <-chan struct{}) {
	time.Sleep(500 * time.Millisecond)
	for i := 0; i < 2000; i++ {
		select {
		case <-done:
			return
		default:
		}
		if strings.Contains(a.screen(t), `"text":"`+target) {
			a.press(t, "both")
			return
		}
		a.press(t, "right")
		time.Sleep(60 * time.Millisecond)
	}
	t.Errorf("never reached %q", target)
}

func TestLedgerSpeculos(t *testing.T) {
	apdu, api := os.Getenv("RC_LEDGER_SPECULOS"), os.Getenv("RC_LEDGER_SPECULOS_API")
	if apdu == "" || api == "" {
		t.Skip("RC_LEDGER_SPECULOS and RC_LEDGER_SPECULOS_API are not set")
	}
	spec := "tcp:" + apdu
	sp := speculosAPI{strings.TrimSuffix(api, "/")}
	machine := newSigningMachine(t)
	run := func(args ...string) result { return runLedger(machine.dir, ledger.Open, machine.env, args...) }

	r := run("key", "show", "--ledger", "--ledger-path", ledgerTestPath, "--ledger-device", spec, "--json")
	if r.code != ExitOK {
		t.Fatalf("key show: %d %s", r.code, r.stdout)
	}
	o := jsonOf(t, r)
	signer := string(o.Members["signer"].(canon.String))
	if !strings.Contains(r.stdout, "emulator") {
		t.Fatalf("not labelled an emulator: %s", r.stdout)
	}

	store := drillStore(t)
	pp := filepath.Join(t.TempDir(), "new.pkg")
	if r := runIn(store, nil, "identity", "new", "--ts", "2026-11-16T00:00:00Z", "--prepare", pp, "--signer", signer, "--json"); r.code != ExitOK {
		t.Fatalf("prepare: %d %s", r.code, r.stdout)
	}
	sign := func(target string, out string) result {
		done := make(chan struct{})
		go func() { sp.walk(t, target, done) }()
		r := run("key", "sign", "--package", pp, "--ledger", "--ledger-path", ledgerTestPath, "--ledger-device", spec, "--ledger-timeout", "2m", "--out", out, "--json")
		close(done)
		return r
	}
	// a rejection writes nothing, exit 1
	rej := filepath.Join(machine.dir, "rej.sig")
	if r := sign("reject message", rej); r.code != ExitWrong || !strings.Contains(r.stdout, ledger.Rejected) {
		t.Fatalf("reject: %d %s", r.code, r.stdout)
	}
	if _, err := os.Stat(rej); err == nil {
		t.Fatal("a rejection wrote a signature")
	}
	// approval: the signature verifies and --complete commits it
	sigF := filepath.Join(machine.dir, "new.sig")
	if r := sign("sign message", sigF); r.code != ExitOK {
		t.Fatalf("sign: %d %s%s", r.code, r.stdout, r.stderr)
	}
	sb, _ := os.ReadFile(sigF)
	r = runIn(store, nil, "identity", "new", "--complete", pp, "--signature", sigF, "--json")
	if r.code != ExitOK {
		t.Fatalf("complete: %d %s", r.code, r.stdout)
	}
	id := firstID(t, jsonOf(t, r))
	if line := lineOf(t, store, id); line == "" || !bytes.Contains([]byte(line), bytes.TrimSpace(sb)) {
		t.Fatalf("the committed line does not carry the device's signature")
	}

	// an interrupt while the review is on the emulated screen: the command closes the connection, says a review may
	// still be open and exits 3; the review stays open (the next command is ledger-busy) until the holder rejects it
	fire := make(chan struct{})
	intr := func() (<-chan string, func()) {
		out := make(chan string, 1)
		go func() { <-fire; out <- "SIGINT" }()
		return out, func() {}
	}
	go func() {
		for i := 0; i < 200 && !strings.Contains(sp.screen(t), "review message"); i++ {
			time.Sleep(50 * time.Millisecond)
		}
		close(fire)
	}()
	ir := runLedgerInterrupt(machine.dir, ledger.Open, intr, machine.env, "key", "sign", "--package", pp, "--ledger", "--ledger-path", ledgerTestPath,
		"--ledger-device", spec, "--out", filepath.Join(machine.dir, "intr.sig"), "--json")
	if ir.code != ExitCouldNot || !strings.Contains(ir.stderr, ReviewMayBeOpen) || !strings.Contains(ir.stdout, ledger.Interrupted) {
		t.Fatalf("interrupted: %d %s%s", ir.code, ir.stdout, ir.stderr)
	}
	if r := run("key", "show", "--ledger", "--ledger-path", ledgerTestPath, "--ledger-device", spec, "--json"); r.code != ExitCouldNot || !strings.Contains(r.stdout, ledger.Busy) {
		t.Fatalf("after the interrupt: %d %s", r.code, r.stdout)
	}
	// rejected on the device with no command connected: its answer goes nowhere, and the next command is answered
	sp.walk(t, "reject message", make(chan struct{}))
	time.Sleep(500 * time.Millisecond)
	if r := run("key", "show", "--ledger", "--ledger-path", ledgerTestPath, "--ledger-device", spec, "--json"); r.code != ExitOK {
		t.Fatalf("after the orphaned answer: %d %s", r.code, r.stdout)
	}
}
