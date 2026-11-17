package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/ledger/ledgertest"
	"github.com/research-common/research-commons/internal/wire"
)

const ledgerTestPath = "m/44'/60'/7'/0/0"

// runLedger runs args in wd with the given device opener (nil: a build without the connector) and environment.
func runLedger(wd string, open LedgerOpener, env map[string]string, args ...string) result {
	var o, e bytes.Buffer
	code := Main(args, &Env{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return env[k] },
		Getwd: func() (string, error) { return wd, nil }, Build: Build{Version: "test", Commit: "0000000"}, Ledger: open})
	return result{code, o.String(), e.String()}
}

// newLedgerHome is an extHome whose root key is the fake device's key at ledgerTestPath (its key file exists only
// for the direct-signing twin).
func newLedgerHome(t *testing.T, dev *ledgertest.App) *extHome {
	t.Helper()
	p, _ := ledger.ParsePath(ledgerTestPath)
	f := filepath.Join(t.TempDir(), "device.key")
	if prob := writeKeyFile(f, keyFileBytes(wire.AlgEIP191, dev.Key(p))); prob != nil {
		t.Fatal(prob)
	}
	lk, prob := loadKey(f, "test")
	if prob != nil {
		t.Fatal(prob)
	}
	if lk.Key.Signer() != dev.AddressAt(p) {
		t.Fatal("the fake's key file is not its address")
	}
	return &extHome{t: t, store: drillStore(t), dir: t.TempDir(), key: lk.Key, keyF: f, signer: lk.Key.Signer()}
}

// TestLedgerKeyShow: key show --ledger prints the device's address at the path with the app and path; with
// --ledger-confirm the device shows it, and a refusal there is exit 1 with no signer printed.
func TestLedgerKeyShow(t *testing.T) {
	dev := ledgertest.New("show")
	p, _ := ledger.ParsePath(ledgerTestPath)
	var specs []string
	wd := t.TempDir()
	r := runLedger(wd, dev.Opener(&specs), nil, "key", "show", "--ledger", "--ledger-path", ledgerTestPath, "--json")
	if r.code != ExitOK {
		t.Fatalf("%d %s", r.code, r.stdout)
	}
	o := jsonOf(t, r)
	d := o.Members["device"].(*canon.Object)
	if o.Members["signer"] != canon.String(dev.AddressAt(p)) || o.Members["alg"] != canon.String(wire.AlgEIP191) ||
		d.Members["app"] != canon.String("Ethereum") || d.Members["path"] != canon.String(ledgerTestPath) || dev.Shown != 0 {
		t.Fatalf("%s", r.stdout)
	}
	if len(specs) != 1 || specs[0] != "" {
		t.Fatalf("opened %q", specs)
	}
	// the path spelled with h, and a device named by the environment
	r = runLedger(wd, dev.Opener(&specs), map[string]string{LedgerDeviceEnv: "/dev/hidraw9"}, "key", "show", "--ledger", "--ledger-path", "m/44h/60h/7h/0/0", "--ledger-confirm", "--json")
	if r.code != ExitOK || jsonOf(t, r).Members["signer"] != canon.String(dev.AddressAt(p)) || dev.Shown != 1 || specs[1] != "/dev/hidraw9" {
		t.Fatalf("confirm: %d %s %q", r.code, r.stdout, specs)
	}
	dev.Reject = true
	r = runLedger(wd, dev.Opener(nil), nil, "key", "show", "--ledger", "--ledger-path", ledgerTestPath, "--ledger-confirm", "--json")
	if r.code != ExitWrong || strings.Contains(r.stdout, dev.AddressAt(p)) || !strings.Contains(r.stdout, ledger.Rejected) {
		t.Fatalf("refused: %d %s", r.code, r.stdout)
	}
	// human output names the device and says the address was not shown on it
	dev.Reject = false
	if r := runLedger(wd, dev.Opener(nil), nil, "key", "show", "--ledger", "--ledger-path", ledgerTestPath); r.code != ExitOK ||
		!strings.Contains(r.stdout, dev.AddressAt(p)) || !strings.Contains(r.stdout, "--ledger-confirm") {
		t.Fatalf("human: %d %s", r.code, r.stdout)
	}
}

// TestLedgerKeySignEndToEnd: an identity's root is a (fake) Ledger device; the inception and a grant are prepared
// on a store that never sees a key, signed with key sign --ledger on a machine with no store, and completed. Each
// committed line is byte-identical to direct signing with the same key at the same --ts on a twin store, whatever
// signature encoding the device returns. The device saw exactly the PAE bytes.
func TestLedgerKeySignEndToEnd(t *testing.T) {
	conformance.Partial(t, "C-id-40", "the Ledger connector (key sign --ledger) signs an identity's inception and a grant through the package against an in-process fake of the Ethereum app, each committed line equal to direct signing whatever encoding the device returns; the emulator run is opt-in (-tags ledger_speculos); a physical device is drilled by hand (§8), not by a test")
	forms := map[string]ledgertest.SigForm{"canonical": ledgertest.Canonical, "v01": ledgertest.V01, "high-s": ledgertest.HighS, "high-s-v01": ledgertest.HighSV01}
	for name, form := range forms {
		t.Run(name, func(t *testing.T) {
			dev := ledgertest.New("e2e")
			dev.Form = form
			root := newLedgerHome(t, dev)
			twin := &idHome{t: t, store: drillStore(t), key: root.keyF, signer: root.signer}
			machine := newSigningMachine(t)
			ts := []string{"--ts", "2026-11-16T00:00:00Z"}
			sign := func(pp string, extra ...string) result {
				return runLedger(machine.dir, dev.Opener(nil), machine.env, append([]string{"key", "sign", "--package", pp, "--ledger", "--ledger-path", ledgerTestPath}, extra...)...)
			}

			newCmd := append([]string{"identity", "new"}, ts...)
			pp, pkg := root.prepare("new.pkg", newCmd...)
			// a dry run checks the device and the address, and asks for nothing
			if r := sign(pp, "--out", filepath.Join(machine.dir, "dry.sig"), "--dry-run", "--json"); r.code != ExitOK || jsonOf(t, r).Members["signed"] != canon.Bool(false) || dev.Signed != 0 {
				t.Fatalf("dry run: %d %s", r.code, r.stdout)
			}
			sigF := filepath.Join(machine.dir, "new.sig")
			r := sign(pp, "--out", sigF)
			if r.code != ExitOK {
				t.Fatalf("key sign --ledger: %d %s%s", r.code, r.stdout, r.stderr)
			}
			// what the device shows was printed before it was asked: the PAE length, the text start and the hash
			pae := paeOf(t, pkg)
			for _, w := range []string{"DSSEv1", "message hash: 0x", "approve it there"} {
				if !strings.Contains(r.stderr, w) {
					t.Fatalf("standard error lacks %q:\n%s", w, r.stderr)
				}
			}
			// the device received exactly the PAE, chunked
			var got []byte
			for _, a := range dev.Received {
				if a[0] == 0xe0 && a[1] == 0x08 {
					if a[2] == 0 {
						got = append(got, a[5+21+4:]...)
					} else {
						got = append(got, a[5:]...)
					}
				}
			}
			if !bytes.Equal(got, pae) {
				t.Fatal("the device was not sent the PAE bytes")
			}
			sb, _ := os.ReadFile(sigF)
			if string(sb) != root.key.Sign(pae)+"\n" {
				t.Fatalf("the written signature is not the canonical encoding: %s", sb)
			}
			if r := root.complete(newCmd[:2:2], pp, sigF); r.code != ExitOK {
				t.Fatalf("complete: %d %s", r.code, r.stdout)
			}
			id := wire.ID(pae)
			if c := twin.ok(newCmd...); firstID(t, c) != id || lineOf(t, root.store, id) != lineOf(t, twin.store, id) || lineOf(t, root.store, id) == "" {
				t.Fatal("the inception signed on the device differs from direct signing")
			}

			// a grant, its signature on standard output into --complete --signature -
			worker := newIDHome(t, wire.AlgEd25519)
			d := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("c0", "w"), "--licence", "CC0-1.0"))
			root.pullFrom(worker.store)
			twin.pullFrom(worker)
			grantCmd := append([]string{"identity", "grant", "--identity", id, "--delegate", worker.signer, "--delegate-inception", d, "--permissions", anyContentPerm}, ts...)
			gp, gpkg := root.prepare("grant.pkg", grantCmd...)
			r = sign(gp, "--out", "-")
			if r.code != ExitOK || strings.TrimSpace(r.stdout) != root.key.Sign(paeOf(t, gpkg)) {
				t.Fatalf("grant sign: %d %q %s", r.code, r.stdout, r.stderr)
			}
			if c := root.runStdin(r.stdout, "identity", "grant", "--complete", gp, "--signature", "-"); c.code != ExitOK {
				t.Fatalf("grant complete: %d %s", c.code, c.stdout)
			}
			gid := wire.ID(paeOf(t, gpkg))
			if c := twin.ok(grantCmd...); firstID(t, c) != gid || lineOf(t, root.store, gid) != lineOf(t, twin.store, gid) {
				t.Fatal("the grant signed on the device differs from direct signing")
			}
			if dev.Signed != 2 {
				t.Fatalf("the device signed %d times", dev.Signed)
			}
		})
	}
}

// TestLedgerKeySignAborts: every failure, on the device or of the invocation, writes no signature, appends
// nothing, and exits as documented: a refusal on the device 1; a wrong signer, wrong algorithm or bad option 2; a
// locked device, closed or other app, message too long, disconnect, a returned signature that does not verify, or
// a build without the connector 3.
func TestLedgerKeySignAborts(t *testing.T) {
	conformance.Partial(t, "C-id-40", "every Ledger connector failure (refusal on the device, locked, closed or other app, too long, disconnect, a signature over other bytes, wrong path or seed, an ed25519 package, no connector) writes no signature and appends nothing; against an in-process fake only")
	dev := ledgertest.New("abort")
	root := newLedgerHome(t, dev)
	machine := newSigningMachine(t)
	pp, pkg := root.prepare("new.pkg", "identity", "new", "--ts", "2026-11-16T00:00:00Z")
	h := sha256.Sum256(paeOf(t, pkg))
	edHome := newExtHome(t, wire.AlgEd25519)
	edPkg, _ := edHome.prepare("ed.pkg", "identity", "new", "--ts", "2026-11-16T00:00:00Z")
	base := []string{"key", "sign", "--package", pp, "--ledger", "--ledger-path", ledgerTestPath}
	n := 0
	cases := []struct {
		name  string
		set   func(f *ledgertest.App)
		open  bool // false: Env.Ledger nil
		args  []string
		exit  int
		slug  string
		asked bool // the device was asked to sign
	}{
		{"rejected", func(f *ledgertest.App) { f.Reject = true }, true, base, ExitWrong, ledger.Rejected, true},
		{"locked", func(f *ledgertest.App) { f.Locked = true }, true, base, ExitCouldNot, ledger.Locked, false},
		{"dashboard", func(f *ledgertest.App) { f.Name = "BOLOS" }, true, base, ExitCouldNot, ledger.AppClosed, false},
		{"other app", func(f *ledgertest.App) { f.Name = "Bitcoin" }, true, base, ExitCouldNot, ledger.WrongApp, false},
		{"too long for the device", func(f *ledgertest.App) { f.MaxMessage = 100 }, true, base, ExitCouldNot, ledger.TooLong, false},
		{"review pending", func(f *ledgertest.App) { f.Pending = true }, true, base, ExitCouldNot, ledger.Busy, false},
		{"bad timeout", nil, true, append(cloneArgs(base), "--ledger-timeout", "0s"), ExitDidNotStart, "", false},
		{"timeout without --ledger", nil, true, []string{"key", "sign", "--package", pp, "--key", root.keyF, "--ledger-timeout", "1m"}, ExitDidNotStart, "", false},
		{"disconnect mid-stream", func(f *ledgertest.App) { f.DisconnectAt = 4 }, true, base, ExitCouldNot, ledger.Disconnected, false},
		{"signs other bytes", func(f *ledgertest.App) { f.Form = ledgertest.Corrupt }, true, base, ExitCouldNot, "operation-failed", true},
		{"garbage signature", func(f *ledgertest.App) { f.Form = ledgertest.Garbage }, true, base, ExitCouldNot, ledger.BadResponse, true},
		{"another seed", func(f *ledgertest.App) { f.Seed = "other"; f.AddressSeed = "other" }, true, base, ExitDidNotStart, "key-not-signer", false},
		{"wrong path", nil, true, []string{"key", "sign", "--package", pp, "--ledger", "--ledger-path", "m/44'/60'/8'/0/0"}, ExitDidNotStart, "key-not-signer", false},
		{"ed25519 package", nil, true, []string{"key", "sign", "--package", edPkg, "--ledger", "--ledger-path", ledgerTestPath}, ExitDidNotStart, "key-not-signer", false},
		{"no connector", nil, false, base, ExitCouldNot, "not-available", false},
		{"wrong expected hash", nil, true, append(cloneArgs(base), "--expect-pae-sha256", strings.Repeat("0", 64)), ExitWrong, "", false},
		{"no path", nil, true, []string{"key", "sign", "--package", pp, "--ledger"}, ExitDidNotStart, "missing-argument", false},
		{"not an ethereum path", nil, true, []string{"key", "sign", "--package", pp, "--ledger", "--ledger-path", "m/44'/0'/0'/0/0"}, ExitDidNotStart, "", false},
		{"path without --ledger", nil, true, []string{"key", "sign", "--package", pp, "--key", root.keyF, "--ledger-path", ledgerTestPath}, ExitDidNotStart, "", false},
		{"--key and --ledger", nil, true, append(cloneArgs(base), "--key", root.keyF), ExitDidNotStart, "", false},
		{"bad device", nil, true, append(cloneArgs(base), "--ledger-device", "/dev/sda"), ExitDidNotStart, "", false},
		// a review left open by a command that went away, decided since: its answer reaches the next request
		{"stray refusal", func(f *ledgertest.App) { f.Stray = []byte{0x69, 0x85} }, true, base, ExitCouldNot, ledger.DeviceError, false},
		{"stray signature", func(f *ledgertest.App) { f.Stray = append(append([]byte{28}, make([]byte, 64)...), 0x90, 0x00) }, true, base, ExitCouldNot, ledger.BadResponse, false},
	}
	for _, c := range cases {
		n++
		f := ledgertest.New("abort")
		if c.set != nil {
			c.set(f)
		}
		var open LedgerOpener
		if c.open {
			open = f.Opener(nil)
		}
		out := filepath.Join(machine.dir, "s"+itoa(n)+".sig")
		r := runLedger(machine.dir, open, machine.env, append(cloneArgs(c.args), "--out", out, "--json")...)
		if r.code != c.exit || (c.slug != "" && !strings.Contains(r.stdout, ProblemTypeBase+c.slug)) {
			t.Fatalf("%s: %d (want %d, %s)\n%s%s", c.name, r.code, c.exit, c.slug, r.stdout, r.stderr)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%s: a signature was written", c.name)
		}
		if strings.Contains(r.stdout, `"signature"`) {
			t.Fatalf("%s: a signature was printed", c.name)
		}
		asked := false
		for _, a := range f.Received {
			if a[0] == 0xe0 && a[1] == 0x08 {
				asked = true
			}
		}
		if c.asked && !asked {
			t.Fatalf("%s: the device was not asked", c.name)
		}
		if !c.asked && c.exit == ExitDidNotStart && asked {
			t.Fatalf("%s: the device was asked to sign before the invocation was checked", c.name)
		}
	}
	// nothing was appended: the inception still completes from a direct signature
	if r := root.complete([]string{"identity", "new"}, pp, root.sign("ok.sig", pkg)); r.code != ExitOK {
		t.Fatalf("complete after the aborts: %d %s", r.code, r.stdout)
	}
	// a matching expected hash signs
	f := ledgertest.New("abort")
	if r := runLedger(machine.dir, f.Opener(nil), machine.env, append(cloneArgs(base), "--expect-pae-sha256", hex.EncodeToString(h[:]), "--out", "-")...); r.code != ExitOK || f.Signed != 1 {
		t.Fatalf("expected hash: %d %s", r.code, r.stderr)
	}
	// key show: a file and --ledger are two signers; neither is a missing argument
	if r := runLedger(machine.dir, f.Opener(nil), nil, "key", "show", root.keyF, "--ledger", "--ledger-path", ledgerTestPath, "--json"); r.code != ExitDidNotStart {
		t.Fatalf("show file and ledger: %d %s", r.code, r.stdout)
	}
	if r := runLedger(machine.dir, f.Opener(nil), nil, "key", "show", "--json"); r.code != ExitDidNotStart || !strings.Contains(r.stdout, "missing-argument") {
		t.Fatalf("show nothing: %d %s", r.code, r.stdout)
	}
	if r := runLedger(machine.dir, f.Opener(nil), map[string]string{LedgerDeviceEnv: "usb"}, "key", "show", "--ledger", "--ledger-path", ledgerTestPath, "--json"); r.code != ExitDidNotStart {
		t.Fatalf("bad env device: %d %s", r.code, r.stdout)
	}
}

func cloneArgs(s []string) []string { return append([]string{}, s...) }

// interruptOn is an Env.Interrupt that delivers one interrupt once fire is closed, recording that it was started and
// stopped.
type interruptOn struct {
	fire             chan struct{}
	started, stopped int
}

func (w *interruptOn) watch() (<-chan string, func()) {
	w.started++
	out := make(chan string, 1)
	quit := make(chan struct{})
	go func() {
		select {
		case <-w.fire:
			out <- "SIGINT"
		case <-quit:
		}
	}()
	once := false
	return out, func() {
		if !once {
			once = true
			w.stopped++
			close(quit)
		}
	}
}

func runLedgerInterrupt(wd string, open LedgerOpener, intr InterruptWatcher, env map[string]string, args ...string) result {
	var o, e bytes.Buffer
	code := Main(args, &Env{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return env[k] },
		Getwd: func() (string, error) { return wd, nil }, Build: Build{Version: "test", Commit: "0000000"}, Ledger: open, Interrupt: intr})
	return result{code, o.String(), e.String()}
}

// TestLedgerInterruptedReview: an interrupt while the device waits for the holder's review (key sign --ledger, and
// key show --ledger --ledger-confirm) prints that a review may still be open on the device, closes the transport,
// writes no signature and exits 3 (ledger-interrupted). The review stays open on the device: the next request is
// refused busy until the holder decides it there. Without an interrupt the same held review, once approved, signs.
// The line asking for the review is the last thing printed before the device is asked to sign.
func TestLedgerInterruptedReview(t *testing.T) {
	dev := ledgertest.New("intr")
	root := newLedgerHome(t, dev)
	machine := newSigningMachine(t)
	pp, _ := root.prepare("new.pkg", "identity", "new", "--ts", "2026-11-16T00:00:00Z")
	base := []string{"key", "sign", "--package", pp, "--ledger", "--ledger-path", ledgerTestPath}
	for _, human := range []bool{false, true} {
		f := ledgertest.New("intr")
		f.Hold = true
		w := &interruptOn{fire: make(chan struct{})}
		go func() { <-f.Reviewing(); close(w.fire) }()
		out := filepath.Join(machine.dir, "intr.sig")
		args := append(cloneArgs(base), "--out", out)
		if !human {
			args = append(args, "--json")
		}
		r := runLedgerInterrupt(machine.dir, f.Opener(nil), w.watch, machine.env, args...)
		if r.code != ExitCouldNot || !strings.Contains(r.stderr, ReviewMayBeOpen) {
			t.Fatalf("interrupted (human %v): %d\n%s%s", human, r.code, r.stdout, r.stderr)
		}
		if human && !strings.Contains(r.stderr, "interrupted while the device waited for you") {
			t.Fatalf("human problem: %s", r.stderr)
		}
		if !human && !strings.Contains(r.stdout, ProblemTypeBase+ledger.Interrupted) {
			t.Fatalf("json problem: %s", r.stdout)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatal("a signature was written")
		}
		if f.Closed != 1 || w.started != 1 || w.stopped != 1 {
			t.Fatalf("transport closed %d, watch started %d stopped %d", f.Closed, w.started, w.stopped)
		}
		// the review is still open on the device: another request is busy until the holder decides
		if r := runLedger(machine.dir, f.Opener(nil), machine.env, append(cloneArgs(base), "--out", out, "--json")...); r.code != ExitCouldNot || !strings.Contains(r.stdout, ledger.Busy) {
			t.Fatalf("after the interrupt: %d %s", r.code, r.stdout)
		}
		f.Decide()
	}
	// the watch is started only around the review: a refusal before the device is asked starts none
	w := &interruptOn{fire: make(chan struct{})}
	locked := ledgertest.New("intr")
	locked.Locked = true
	if r := runLedgerInterrupt(machine.dir, locked.Opener(nil), w.watch, machine.env, append(cloneArgs(base), "--out", filepath.Join(machine.dir, "locked.sig"), "--json")...); r.code != ExitCouldNot || w.started != 0 {
		t.Fatalf("locked: %d started %d", r.code, w.started)
	}
	// a held review approved by the holder signs, and the watch is stopped
	f := ledgertest.New("intr")
	f.Hold = true
	var atSign string
	var errBuf *bytes.Buffer
	go func() { <-f.Reviewing(); f.Decide() }()
	var o, e bytes.Buffer
	errBuf = &e
	f.BeforeSign = func() { atSign = errBuf.String() }
	w = &interruptOn{fire: make(chan struct{})}
	code := Main(append(cloneArgs(base), "--out", "-"), &Env{Stdout: &o, Stderr: &e, Getenv: func(k string) string { return machine.env[k] },
		Getwd: func() (string, error) { return machine.dir, nil }, Build: Build{Version: "test", Commit: "0000000"}, Ledger: f.Opener(nil), Interrupt: w.watch})
	if code != ExitOK || f.Signed != 1 || !strings.HasPrefix(o.String(), "0x") || w.started != 1 || w.stopped != 1 || f.Closed != 0 {
		t.Fatalf("approved: %d signed %d started %d stopped %d closed %d\n%s%s", code, f.Signed, w.started, w.stopped, f.Closed, o.String(), e.String())
	}
	// the review line is the last thing standard error said before the device was asked to sign
	lines := strings.Split(strings.TrimSuffix(atSign, "\n"), "\n")
	if last := lines[len(lines)-1]; !strings.HasPrefix(last, "commons: review the message on the device now") {
		t.Fatalf("last line before the sign request: %q", last)
	}
	// key show --ledger-confirm: an interrupt while the address is on the device's screen
	f = ledgertest.New("intr")
	f.Hold = true
	w = &interruptOn{fire: make(chan struct{})}
	go func() { <-f.Reviewing(); close(w.fire) }()
	r := runLedgerInterrupt(machine.dir, f.Opener(nil), w.watch, nil, "key", "show", "--ledger", "--ledger-path", ledgerTestPath, "--ledger-confirm", "--json")
	if r.code != ExitCouldNot || !strings.Contains(r.stderr, ReviewMayBeOpen) || !strings.Contains(r.stdout, ledger.Interrupted) || f.Closed != 1 {
		t.Fatalf("key show interrupted: %d closed %d\n%s%s", r.code, f.Closed, r.stdout, r.stderr)
	}
	f.Decide()
}

// TestLedgerCompromisedStoreHost: the connector's half of a compromised operational host (the store's machine). A
// host that alters the package it hands to the signing machine (the PAE, the signer, the summary the holder reads,
// or the envelope under them) gets nothing from the device: key sign --ledger refuses before the device is asked to
// sign (exit 1, naming the member), writes nothing, and the device saw no sign request. A host that prepares a
// different statement honestly (a valid package for other bytes) is caught by the separate-channel digest
// (--expect-pae-sha256) before the device is asked.
func TestLedgerCompromisedStoreHost(t *testing.T) {
	conformance.Partial(t, "C-id-40", "the connector's half of a compromised store host: a package altered after --prepare (PAE, signer, summary, envelope) or a valid package for other bytes caught by --expect-pae-sha256 is refused by key sign --ledger before the device is asked to sign, nothing written; the custody drill of the compromised host is TestIdentityCompromisedHostDrill")
	dev := ledgertest.New("host")
	root := newLedgerHome(t, dev)
	machine := newSigningMachine(t)
	pp, pkg := root.prepare("new.pkg", "identity", "new", "--ts", "2026-11-16T00:00:00Z")
	good := sha256.Sum256(paeOf(t, pkg))
	other := newExtHome(t, wire.AlgEIP191)
	mutated := func(name string, f func(p *canon.Object)) string {
		p := clonePkg(pkg)
		f(p)
		path := filepath.Join(machine.dir, name)
		writePkg(t, path, p)
		return path
	}
	// an honest-looking package for other bytes: the host prepared a different inception (another ts)
	otherPP, _ := root.prepare("other.pkg", "identity", "new", "--ts", "2026-11-16T00:00:01Z")
	cases := []struct {
		name, pkg string
		extra     []string
		member    string
	}{
		{"pae", mutated("h-pae.pkg", func(p *canon.Object) {
			p.Members["pae"] = canon.String(base64.StdEncoding.EncodeToString(append(paeOf(t, pkg), ' ')))
		}), nil, "pae"},
		{"signer", mutated("h-signer.pkg", func(p *canon.Object) { p.Members["signer"] = canon.String(other.signer) }), nil, "signer"},
		{"summary", mutated("h-sum.pkg", func(p *canon.Object) {
			p.Members["summary"].(*canon.Object).Members["root"] = canon.String(other.signer)
		}), nil, "summary"},
		{"envelope", mutated("h-env.pkg", func(p *canon.Object) {
			p.Members["envelope"].(*canon.Object).Members["ts"] = canon.String("2026-11-16T00:00:02Z")
		}), nil, "pae"},
		{"other bytes", otherPP, []string{"--expect-pae-sha256", hex.EncodeToString(good[:])}, ""},
	}
	for _, c := range cases {
		f := ledgertest.New("host")
		out := filepath.Join(machine.dir, "h-"+strings.ReplaceAll(c.name, " ", "-")+".sig")
		args := append([]string{"key", "sign", "--package", c.pkg, "--ledger", "--ledger-path", ledgerTestPath, "--out", out, "--json"}, c.extra...)
		r := runLedger(machine.dir, f.Opener(nil), machine.env, args...)
		if r.code != ExitWrong || (c.member != "" && !strings.Contains(r.stdout, `"scope":"package member `+c.member+`"`)) {
			t.Fatalf("%s: %d %s", c.name, r.code, r.stdout)
		}
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("%s: a signature was written", c.name)
		}
		for _, a := range f.Received {
			if a[0] == 0xe0 && a[1] == 0x08 {
				t.Fatalf("%s: the device was asked to sign", c.name)
			}
		}
	}
	// control: the untampered package with the matching digest signs
	f := ledgertest.New("host")
	if r := runLedger(machine.dir, f.Opener(nil), machine.env, "key", "sign", "--package", pp, "--ledger", "--ledger-path", ledgerTestPath,
		"--expect-pae-sha256", hex.EncodeToString(good[:]), "--out", "-"); r.code != ExitOK || f.Signed != 1 {
		t.Fatalf("control: %d %s", r.code, r.stderr)
	}
}
