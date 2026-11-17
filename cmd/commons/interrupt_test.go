//go:build unix

package main

import (
	"bytes"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/ledger/ledgertest"
)

// TestInterruptDuringDeviceReview: the binary wires SIGINT and SIGTERM around a device review. A signal while the
// (fake, emulator-protocol) device shows an address to confirm makes the command say a review may still be open,
// close its connection to the device, and exit 3 naming ledger-interrupted; the review stays open on the device.
// A build without the wiring would die from the signal with no message.
func TestInterruptDuringDeviceReview(t *testing.T) {
	bin := build(t)
	for _, s := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(s.String(), func(t *testing.T) {
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Skip("no loopback listener:", err)
			}
			defer l.Close()
			dev := ledgertest.New("bin")
			dev.Hold = true
			go dev.ServeTCP(l)
			cmd := exec.Command(bin, "key", "show", "--ledger", "--ledger-path", "m/44'/60'/7'/0/0", "--ledger-confirm",
				"--ledger-device", "tcp:"+l.Addr().String(), "--json")
			var o, e bytes.Buffer
			cmd.Stdout, cmd.Stderr = &o, &e
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-dev.Reviewing():
			case <-time.After(30 * time.Second):
				cmd.Process.Kill()
				t.Fatal("the review never reached the device")
			}
			cmd.Process.Signal(s)
			err = cmd.Wait()
			ee, ok := err.(*exec.ExitError)
			if !ok || ee.ExitCode() != 3 || !strings.Contains(e.String(), cli.ReviewMayBeOpen) || !strings.Contains(o.String(), ledger.Interrupted) {
				t.Fatalf("%v: %v\nstdout %s\nstderr %s", s, err, o.String(), e.String())
			}
			// the connection was closed: the fake's wait for it ended (the review itself stays open)
			deadline := time.Now().Add(5 * time.Second)
			for !closedOnce(dev) && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			if !closedOnce(dev) || !dev.IsPending() {
				t.Fatalf("closed %d pending %v", dev.ClosedCount(), dev.IsPending())
			}
			dev.Decide()
		})
	}
}

func closedOnce(d *ledgertest.App) bool { return d.ClosedCount() == 1 }
