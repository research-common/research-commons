//go:build ledger_hardware

package ledger_test

// A physical Ledger over USB (Linux hidraw or macOS IOKit), not in CI: the Ethereum app's message-size limit. Set
// RC_LEDGER_SIZES to a comma-separated list of message lengths and run with
//
//	go test -tags ledger_hardware -run TestLedgerHardwareMessageSize -v ./internal/ledger
//
// Each message is printable text at m/44'/60'/7'/0/0. A message the app cannot hold is refused before any review
// (ledger-message-too-long); one it can hold goes to review: reject it on the device. Every size is chunked into
// many exchanges, so a run also exercises the transport over a long request.

import (
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/sig"
)

func TestLedgerHardwareMessageSize(t *testing.T) {
	spec := os.Getenv("RC_LEDGER_SIZES")
	if spec == "" {
		t.Skip("RC_LEDGER_SIZES is unset")
	}
	p := mustPath(t, "m/44'/60'/7'/0/0")
	d, err := ledger.Open(os.Getenv("RC_LEDGER_DEVICE"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	app, err := ledger.AppAndVersion(d)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%s %s on %s (%s)", app.Name, app.Version, d.Model, d.Where)
	a, err := ledger.Address(d, p, false)
	if err != nil {
		t.Fatal(err)
	}
	addr, err := hex.DecodeString(strings.TrimPrefix(a, "0x"))
	if err != nil || len(addr) != 20 {
		t.Fatalf("address %q", a)
	}
	for _, f := range strings.Split(spec, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 1 {
			t.Fatalf("size %q", f)
		}
		msg := bytes.Repeat([]byte("DSSEv1 "), n/7+1)[:n]
		start := time.Now()
		s, err := ledger.PersonalSignWait(d, p, msg, 3*time.Minute)
		took := time.Since(start).Round(time.Millisecond)
		switch {
		case err == nil:
			if _, ok := sig.VerifyEIP191(msg, s, addr); !ok {
				t.Errorf("%d bytes: approved, but the signature does not verify", n)
			}
			t.Logf("%d bytes: reviewed and APPROVED (%v); verifies", n, took)
		case ledger.IsSlug(err, ledger.TooLong):
			t.Logf("%d bytes: refused before review (%v): %v", n, took, err)
		case ledger.IsSlug(err, ledger.Rejected):
			t.Logf("%d bytes: reviewed and rejected on the device (%v)", n, took)
		default:
			t.Errorf("%d bytes: %v (%v)", n, err, took)
		}
	}
}

// TestLedgerHardwareChunkTrace sends one message's chunks by hand, each with a long timeout, and logs how long each
// chunk's answer took and its status word: it tells a transport that loses an answer from an app that holds a
// chunk's answer until the holder acts. RC_LEDGER_TRACE=<length>. Reject the review on the device.
func TestLedgerHardwareChunkTrace(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv("RC_LEDGER_TRACE"))
	if err != nil || n < 1 {
		t.Skip("RC_LEDGER_TRACE is unset")
	}
	d, err := ledger.Open(os.Getenv("RC_LEDGER_DEVICE"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	msg := bytes.Repeat([]byte("DSSEv1 "), n/7+1)[:n]
	reqs := ledger.SignAPDUs(mustPath(t, "m/44'/60'/7'/0/0"), msg)
	t.Logf("%d bytes in %d chunks", n, len(reqs))
	for i, a := range reqs {
		d.SetTimeout(3 * time.Minute)
		start := time.Now()
		resp, err := d.Exchange(a)
		took := time.Since(start).Round(time.Millisecond)
		if err != nil {
			t.Logf("chunk %d/%d: %v after %v", i+1, len(reqs), err, took)
			return
		}
		sw := uint16(resp[len(resp)-2])<<8 | uint16(resp[len(resp)-1])
		t.Logf("chunk %d/%d: status %04x, %d data bytes, after %v", i+1, len(reqs), sw, len(resp)-2, took)
		if sw != ledger.SWOK {
			return
		}
	}
}
