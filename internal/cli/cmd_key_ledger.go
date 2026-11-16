package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/wire"
)

// key show --ledger, key sign --ledger: a Ledger device running the Ethereum app as the signer of an
// external-signing package (identity profile §8), for the eip191-secp256k1 algorithm. The device signs the package's
// recomputed PAE bytes with EIP-191 personal_sign after the user reviews them on its screen; the signature is then
// verified as every reader verifies the signed line and written exactly as a key-file signature is. The package flow
// stays the boundary: --complete, identity and publish never open a device, so the device never needs to sit on the
// store's machine.
//
// This package opens no device itself: Env.Ledger (wired by cmd/commons) does, so a build or a test decides what a
// device is.

// LedgerOpener opens the device a spec names ("" for the one attached by USB).
type LedgerOpener func(spec string) (*ledger.Device, error)

// LedgerDeviceEnv names the device when --ledger-device is not given.
const LedgerDeviceEnv = "COMMONS_LEDGER_DEVICE"

func checkLedgerPath(v string) error {
	p, err := ledger.ParsePath(v)
	if err != nil {
		return err
	}
	if !p.IsEthereumAccount() {
		return errors.New("the Ethereum app derives keys under m/44'/60'/ only, for example m/44'/60'/7'/0/0")
	}
	return nil
}

var (
	ledgerFlag     = Flag{Name: "ledger", Help: "sign with a Ledger device running the Ethereum app (eip191-secp256k1 only) instead of a key file; needs --ledger-path"}
	ledgerPathFlag = Flag{Name: "ledger-path", Value: "path", Check: checkLedgerPath,
		Help: "the BIP-32 path of the device's key, m/44'/60'/<account>'/0/<index> (' or h marks hardened); required with --ledger, no default. Use an account that never holds funds: never reuse a payment key as a Commons key"}
	ledgerDeviceFlag = Flag{Name: "ledger-device", Value: "device", Check: ledger.CheckSpec,
		Help: "which device: a hidraw node (/dev/hidrawN, Linux) or an emulator's APDU port (tcp:<host>:<port>, no hardware); else $" + LedgerDeviceEnv + ", else the one Ledger attached by USB"}
	ledgerConfirmFlag = Flag{Name: "ledger-confirm", Help: "show the address on the device and wait for you to confirm it there (recommended once, before an identity's inception)"}
	ledgerTimeoutFlag = Flag{Name: "ledger-timeout", Value: "duration", Check: checkLedgerTimeout,
		Help: "how long to wait for you to approve or reject on the device (a Go duration such as 90s or 10m; 1s to 1h); default 10m. Every other exchange with the device waits 10s"}
)

func checkLedgerTimeout(v string) error {
	d, err := time.ParseDuration(v)
	if err != nil || d < time.Second || d > time.Hour {
		return errors.New("a duration from 1s to 1h, such as 90s or 10m")
	}
	return nil
}

const ledgerHelp = " With --ledger the key is a Ledger device running the Ethereum app (tested on the Speculos emulator for Nano S Plus and Nano X; " +
	"no physical device is tested yet), opened over USB on Linux (hidraw) or as an emulator (tcp:<host>:<port>); " +
	"on other systems the USB connector is not built. --ledger-path names the key (m/44'/60'/<account>'/0/<index>, no default): " +
	"use an account that never holds funds. Identity PAEs are typically 300 to 800 bytes; the Ethereum app 1.23 accepts about 7.6 KB (less when a byte is not printable). " +
	"While a review is pending on the device every other request is refused (ledger-busy): finish or reject it first. --ledger and --key are exclusive."

// ledgerOpts is what an invocation says about the device; nil when --ledger is not given.
type ledgerOpts struct {
	path    ledger.Path
	device  string // "" for the one attached
	confirm bool
	wait    time.Duration // how long the device may wait for the user
}

// ledgerOptions reads --ledger and its options. A device option without --ledger, --ledger without a path, or
// --ledger with --key is exit 2.
func ledgerOptions(c *Ctx) (*ledgerOpts, *Problem) {
	_, on := c.Flag("ledger")
	pathS, hasPath := c.Flag("ledger-path")
	dev, hasDev := c.Flag("ledger-device")
	_, confirm := c.Flag("ledger-confirm")
	waitS, hasWait := c.Flag("ledger-timeout")
	if !on {
		for _, f := range []struct {
			name string
			has  bool
		}{{"ledger-path", hasPath}, {"ledger-device", hasDev}, {"ledger-confirm", confirm}, {"ledger-timeout", hasWait}} {
			if f.has {
				return nil, conflicting(f.name, "--"+f.name+" goes with --ledger", "it names the device's key or the device", "add --ledger, or drop --"+f.name)
			}
		}
		return nil, nil
	}
	if _, ok := c.Flag("key"); ok {
		return nil, conflicting("key", "--ledger and --key are two signers", "give one of them", "drop --key to sign on the device, or drop --ledger")
	}
	if !hasPath {
		return nil, usage("missing-argument", "--ledger-path is missing", "a device holds many keys and there is no default path; nothing was done",
			"option --ledger-path", "give --ledger-path m/44'/60'/<account>'/0/<index>, the path of the key the package names", "")
	}
	p, _ := ledger.ParsePath(pathS) // checked by the flag
	if !hasDev {
		dev = c.Env.Getenv(LedgerDeviceEnv)
		if dev != "" {
			if err := ledger.CheckSpec(dev); err != nil {
				return nil, usage("malformed-argument", "$"+LedgerDeviceEnv+" is not a device", err.Error()+"; nothing was done",
					"environment "+LedgerDeviceEnv, "fix or unset it, or give --ledger-device", dev)
			}
		}
	}
	wait := ledger.UserTimeout
	if hasWait {
		wait, _ = time.ParseDuration(waitS) // checked by the flag
	}
	return &ledgerOpts{path: p, device: dev, confirm: confirm, wait: wait}, nil
}

// ledgerProblem is a device failure as a problem: a refusal on the device is exit 1 (the user checked and said no),
// anything else exit 3 (the signature could not be made). Nothing was signed or written in either case.
func ledgerProblem(err error, what string) *Problem {
	var e *ledger.Error
	if !errors.As(err, &e) {
		return failed(err, "ledger device", false, "run the command again")
	}
	p := &Problem{Slug: e.Slug, Class: refusal.Operational, Scope: "ledger device", Exit: ExitCouldNot,
		Detail: e.Detail + "; " + what}
	if e.SW != 0 {
		p.Detail += " (status word " + ledger.SWText(e.SW) + ")"
	}
	switch e.Slug {
	case ledger.Rejected:
		p.Title, p.Next, p.Exit, p.Class = "refused on the device", "nothing to do; to sign after all, run the command again and approve on the device", ExitWrong, refusal.Policy
	case ledger.Locked:
		p.Title, p.Next = "the device is locked", "unlock the device with its PIN, open the Ethereum app, then run the command again"
	case ledger.AppClosed:
		p.Title, p.Next = "the Ethereum app is not open", "open the Ethereum app on the device, then run the command again"
	case ledger.TooLong:
		p.Title, p.Next = "the device cannot show this message", "this statement is too long to review on the device; sign it with a key file, or write its PAE with package show --pae-out for another signer"
	case ledger.NoDevice, ledger.MultipleDevice:
		p.Title, p.Next = "no usable Ledger device", "connect and unlock the device and open the Ethereum app; name it with --ledger-device when several are attached"
	case ledger.Unusable:
		p.Title, p.Next = "the device cannot be opened", "give your user access to the device (Ledger's udev rules on Linux), reconnect it, then run the command again"
	case ledger.Disconnected:
		p.Title, p.Next = "the device went away", "reconnect and unlock the device, open the Ethereum app, then run the command again"
	case ledger.Timeout:
		p.Title, p.Next = "the device did not answer in time", "run the command again and approve or reject on the device within the time allowed"
	case ledger.NotBuilt:
		p.Title, p.Next = "the USB connector is not built for this system", "sign the PAE bytes with package show --pae-out and your own signer, or use an emulator (tcp:<host>:<port>)"
	case ledger.BadDeviceSpec:
		p.Title, p.Next, p.Exit, p.Class = "not a device", "give --ledger-device /dev/hidrawN or tcp:<host>:<port>", ExitDidNotStart, refusal.Intrinsic
	case ledger.Busy:
		p.Title, p.Next = "the device is busy", "finish or reject the pending review on the device, then run the command again"
	case ledger.BadRequest:
		p.Title, p.Next = "the Ethereum app refused the request", "this is a fault in the connector or an app it does not know: report it with the app version, then sign with a key file or with package show --pae-out"
	default:
		p.Title, p.Next = "the device refused the request", "check the device's screen, update the Ethereum app, then run the command again"
	}
	return p
}

// ledgerSession is an open device with the Ethereum app checked and the address at the path read.
type ledgerSession struct {
	dev     *ledger.Device
	app     ledger.App
	address string
}

func (s *ledgerSession) close() { s.dev.Close() }

// openLedger opens the device, checks that the Ethereum app is open, and reads the address at the path (on the
// device's screen too when confirm). what is the clause appended to failures ("nothing was signed or written").
func openLedger(c *Ctx, o *ledgerOpts, confirm bool, what string) (*ledgerSession, *Problem) {
	if c.Env.Ledger == nil {
		return nil, &Problem{Slug: "not-available", Title: "the Ledger connector is not available in this build", Class: refusal.Operational, Scope: "invocation",
			Detail: "this build has no device connector; " + what, Next: "use a build with the connector, or sign the package with a key file or by hand", Exit: ExitCouldNot}
	}
	d, err := c.Env.Ledger(o.device)
	if err != nil {
		return nil, ledgerProblem(err, what)
	}
	s := &ledgerSession{dev: d}
	if s.app, err = ledger.AppAndVersion(d); err != nil {
		d.Close()
		return nil, ledgerProblem(err, what)
	}
	switch {
	case s.app.Name == "BOLOS":
		d.Close()
		return nil, ledgerProblem(&ledger.Error{Slug: ledger.AppClosed, Detail: "the device shows its dashboard: no app is open"}, what)
	case s.app.Name != ledger.EthereumApp:
		d.Close()
		return nil, &Problem{Slug: ledger.WrongApp, Title: "another app is open on the device", Class: refusal.Operational, Scope: "ledger device",
			Detail: "the open app is not the Ethereum app (its name is in peer_text); " + what, Next: "close it and open the Ethereum app, then run the command again",
			Peer: s.app.Name + " " + s.app.Version, Exit: ExitCouldNot}
	}
	if s.address, err = ledger.AddressWait(d, o.path, confirm, o.wait); err != nil {
		d.Close()
		return nil, ledgerProblem(err, what)
	}
	return s, nil
}

// deviceObj is what the tool says about the device it used.
func deviceObj(o *ledgerOpts, s *ledgerSession) *Obj {
	d := newObj().set("app", peerV(s.app.Name)).set("app_version", peerV(s.app.Version)).set("path", textV(o.path.String())).
		set("where", peerV(s.dev.Where))
	if s.dev.Model != "" {
		d.set("model", peerV(s.dev.Model))
	}
	if s.dev.Emulator {
		d.set("emulator", textV("an emulator, not a hardware device: its key is not protected by hardware"))
	}
	return d
}

// keyShowLedger is key show --ledger: the signer at the path, read from the device.
func keyShowLedger(c *Ctx, o *ledgerOpts) (*Obj, int, error) {
	if c.Args["file"] != "" {
		return nil, 0, conflicting("ledger", "--ledger and a key file are two signers", "give one of them", "drop the file argument to read the device, or drop --ledger")
	}
	if o.confirm && c.Env.Stderr != nil {
		io.WriteString(c.Env.Stderr, "commons: check the address on the device against the one below, then confirm it there\n")
	}
	s, prob := openLedger(c, o, o.confirm, "nothing is shown as the signer")
	if prob != nil {
		return nil, 0, prob
	}
	defer s.close()
	out := newObj().set("signer", refV(s.address)).set("alg", textV(wire.AlgEIP191)).set("device", deviceObj(o, s))
	if o.confirm {
		out.set("confirmed", textV("the address was shown on the device and confirmed there"))
	} else {
		out.set("confirmed", textV("not shown on the device; add --ledger-confirm to check it on the device's screen"))
	}
	return out, ExitOK, nil
}

// eip191Display is what the device shows for the PAE and what to compare it with.
func eip191Display(st *wire.Statement) *Obj {
	pae := st.SignedString
	h := sha256.Sum256(pae)
	o := newObj().set("pae_bytes", intV(int64(len(pae)))).set("pae_sha256", refV(hex.EncodeToString(h[:])))
	if ledger.MessageDisplay(pae) == "text" {
		head := string(pae)
		if len(head) > 40 {
			head = head[:40]
		}
		o.set("message", textV("shown as text, starting "+quoteGraphic(head)+" … (scroll to the end to see it all; line breaks shown as spaces)"))
	} else {
		o.set("message", textV("shown as hex (0x…): the bytes are not all printable"))
	}
	o.set("message_hash", refV("0x"+hex.EncodeToString(sig.EIP191Hash(pae)))).
		set("message_hash_note", textV("the device shows this hash only when the Ethereum app's \"Transaction hash\" setting is enabled (it is off by default): enable it and compare before approving"))
	return o
}

// keySignLedger is key sign --ledger, after the package and the options were checked: st is the recomputed
// statement, path the package file, out the signature's destination.
func keySignLedger(c *Ctx, o *ledgerOpts, st *wire.Statement, path, out string, dry bool) (*Obj, int, error) {
	const none = "nothing was signed or written"
	if st.Alg != wire.AlgEIP191 {
		return nil, 0, &Problem{Slug: "key-not-signer", Title: "a Ledger device is not the package's signer", Class: refusal.Intrinsic, Scope: "option --ledger",
			Detail: "the package is prepared for " + st.Signer + " (" + st.Alg + "); the Ethereum app signs " + wire.AlgEIP191 + " only; " + none,
			Next:   "sign with the key file of " + st.Signer, Exit: ExitDidNotStart}
	}
	if len(st.SignedString) > ledger.MaxMessage {
		return nil, 0, ledgerProblem(&ledger.Error{Slug: ledger.TooLong,
			Detail: "the PAE is " + itoa(len(st.SignedString)) + " bytes; the Ethereum app's protocol carries at most " + itoa(ledger.MaxMessage)}, none)
	}
	s, prob := openLedger(c, o, false, none)
	if prob != nil {
		return nil, 0, prob
	}
	defer s.close()
	if s.address != st.Signer {
		return nil, 0, &Problem{Slug: "key-not-signer", Title: "the device's key at that path is not the package's signer", Class: refusal.Intrinsic, Scope: "option --ledger-path",
			Detail: "the package is prepared for " + st.Signer + "; the device's key at " + o.path.String() + " is " + s.address + "; " + none,
			Next:   "give the path of " + st.Signer + " (commons key show --ledger --ledger-path <path> prints a path's signer), or prepare again with --signer " + s.address,
			Exit:   ExitDidNotStart}
	}
	show := eip191Display(st)
	if dry {
		return packageObj(newObj(), path, st).set("device", deviceObj(o, s)).set("device_shows", show).
			set("dry_run", boolV(true)).set("signed", boolV(false)).set("written", boolV(false)).
			set("would", textV("ask the device to sign the "+itoa(len(st.SignedString))+" PAE bytes above as "+st.Signer+" and write the signature")), ExitOK, nil
	}
	// what the device will show, before it is asked: on standard error (standard output may be the signature, and
	// the device waits for the user while this is read)
	res := newObj()
	if c.JSON {
		res = packageObj(res, path, st).set("device", deviceObj(o, s)).set("device_shows", show)
	}
	if c.Env.Stderr != nil {
		pre := newObj()
		if !c.JSON {
			pre = packageObj(pre, path, st).set("device", deviceObj(o, s))
		}
		io.WriteString(c.Env.Stderr, human(pre.set("device_shows", show).
			set("signing", textV("review the message on the device and approve it there; reject it if anything differs"))))
	}
	rsv, err := ledger.PersonalSignWait(s.dev, o.path, st.SignedString, o.wait)
	if err != nil {
		return nil, 0, ledgerProblem(err, none)
	}
	signature := "0x" + hex.EncodeToString(rsv)
	// the reader's own check of the signed line, as for a key file
	env := envelopeOf(st).(*canon.Object)
	if why := verifyOver(env, st, signature); why != "" {
		return nil, 0, failed(errors.New("the signature the device returned does not verify: "+why), "ledger device", false,
			"nothing was written; check that the device is the one holding "+st.Signer+", then run the command again")
	}
	res.set("statement", refV(st.ID)).set("signature", refV(signature)).set("signed", boolV(true)).set("dry_run", boolV(false))
	return writeSignature(c, res, st, out, signature)
}

// writeSignature writes the signature line to out ("-" for standard output) exactly as key sign does for a key file.
func writeSignature(c *Ctx, res *Obj, st *wire.Statement, out, signature string) (*Obj, int, error) {
	line := []byte(signature + "\n")
	if out == "-" {
		if _, err := c.Env.Stdout.Write(line); err != nil {
			return nil, 0, failed(err, "standard output", false, "run the command again")
		}
		if c.Env.Stderr != nil {
			io.WriteString(c.Env.Stderr, human(newObj().set("written", textV("standard output")).set("next", textV("carry the signature back and run "+completeCommand(st)))))
		}
		return nil, ExitOK, nil
	}
	if p := writeNewFile(out, line, "option --out", "signature-file-exists", "a signature file is never overwritten"); p != nil {
		return nil, 0, p
	}
	return res.set("written", peerV(out)).
		set("next", textV("carry the signature file back and run "+completeCommand(st))), ExitOK, nil
}
