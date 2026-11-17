// Command commons is the Research Commons tool. All logic lives in internal/cli; this is the process
// boundary only: it wires the one execution bridge (internal/clirun) that `verify --rerun` and `run` call and the one
// network transport that `fetch` dials through, the calendar client `anchor stamp` and `anchor upgrade` use, and the
// Ledger connector `key show --ledger` and `key sign --ledger` open.
package main

import (
	"os"
	"os/signal"
	"syscall"

	research "github.com/research-common/research-commons"
	"github.com/research-common/research-commons/internal/btctime"
	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/clirun"
	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/otscal"
	"github.com/research-common/research-commons/internal/store"
)

// Optional link-time stamps: go build -ldflags "-X main.version=1.0.0-rc.1 -X main.commit=$(git rev-parse HEAD)".
// An unstamped build reports the embedded VERSION file and the toolchain's vcs.revision.
var version, commit string

func main() {
	env := cli.OSEnv(cli.Build{Version: research.Version(version), Commit: commit})
	// The OCI sandbox runs a re-run only when the reader passes --rerun and an execution policy; nothing else
	// in the binary reaches it.
	bridge := clirun.Sandbox()
	env.Rerun = bridge
	// `run` executes through the same bridge, under the same explicit execution policy.
	env.Exec = bridge
	// The HTTPS transport is dialled only by `fetch`, the reader's explicit request; no other command reaches it.
	env.Fetch = transport
	// The OpenTimestamps calendar client is dialled only by `anchor stamp` and `anchor upgrade`, the author's explicit
	// requests.
	env.Calendars = calendar
	// The Ledger connector is opened only by `key show --ledger` and `key sign --ledger`, the signer's explicit
	// requests.
	env.Ledger = ledger.Open
	// SIGINT and SIGTERM are caught only while a device waits for the holder's review, so the command can close
	// the device cleanly and say that a review may still be open on it; anywhere else they act as the system's.
	env.Interrupt = interrupts
	os.Exit(cli.Main(os.Args[1:], env))
}

func transport(c cli.FetchConfig) store.Transport {
	return store.HTTPTransport{AllowHTTP: c.AllowHTTP, AllowPrivate: c.AllowPrivate, Timeout: c.Timeout, IdleTimeout: c.IdleTimeout}
}

func calendar(url string, c cli.CalendarConfig) (btctime.Calendar, error) {
	return otscal.New(url, otscal.Config{AllowPrivate: c.AllowPrivate, Timeout: c.Timeout})
}

// interrupts relays SIGINT and SIGTERM by name until stop, which restores the default handling.
func interrupts() (<-chan string, func()) {
	sig := make(chan os.Signal, 1)
	out := make(chan string, 1)
	quit := make(chan struct{})
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case s := <-sig:
			name := "SIGTERM"
			if s == os.Interrupt {
				name = "SIGINT"
			}
			out <- name
		case <-quit:
		}
	}()
	stopped := false
	return out, func() {
		if !stopped {
			stopped = true
			signal.Stop(sig)
			close(quit)
		}
	}
}
