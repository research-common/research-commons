// Package ledgertest is an in-process fake of a Ledger device running the Ethereum app, for tests: it answers the
// app's APDUs (app and version, get address, personal sign in chunks) the way app-ethereum does, signs with
// throwaway secp256k1 keys derived from the path, and can be told to refuse, lock, disconnect, run another app,
// or return the signature in each encoding the device may use.
package ledgertest

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/sig"
)

// SigForm is how the fake encodes an approved signature (the device's v ‖ r ‖ s).
type SigForm int

const (
	Canonical SigForm = iota // low s, v 27/28 (what the app returns)
	V01                      // v 0/1
	HighS                    // high s, v flipped
	HighSV01                 // both
	Corrupt                  // a valid encoding that signs other bytes
	Garbage                  // not a signature encoding (r = 0)
	Short                    // 64 bytes
)

// App is the fake device. The zero value is not usable: use New.
type App struct {
	mu sync.Mutex
	// Seed derives every key: the scalar at a path is sha256(seed ‖ path text), reduced.
	Seed string
	// Name and Version are what the app-and-version command answers ("BOLOS" is the dashboard).
	Name, Version string
	// Locked: every APDU answers 0x5515.
	Locked bool
	// Pending: a review is on the device's screen; every APDU answers 0x6901 until the user decides.
	Pending bool
	// Reject: the user refuses the review (0x6985).
	Reject bool
	// Form is the encoding of an approved signature.
	Form SigForm
	// MaxMessage: a message longer than this is refused with 0x6a84 after its last chunk (the app's heap); 0 is no limit.
	MaxMessage int
	// DisconnectAt: the exchange with this 1-based index fails as a disconnect, and every one after it; 0 is never.
	DisconnectAt int
	// AddressSeed, when set, is the seed the get-address command derives from (the device holds another seed than
	// the one it signs with: a fault no real device has, to reach the connector's address check).
	AddressSeed string

	// Hold: a review (a signing request's last chunk, or an address to confirm) stays on the screen until Decide is
	// called (Reject says how the holder decides) or the transport carrying it is closed. While it is on the screen
	// every other APDU answers 0x6901, as the Ethereum app built with a current SDK does; after the transport is
	// closed the review stays open (Pending) until Decide.
	Hold bool
	// Stray, when set, is the answer the next exchange receives instead of its own (then cleared): a review left
	// open by a process that went away and decided later delivers its answer (a signature, or 0x6985) to whatever
	// request is waiting then, as the emulated app does.
	Stray []byte
	// BeforeSign, when set, is called as the first chunk of a signing request arrives (before it is answered).
	BeforeSign func()

	// Received is every APDU the fake was sent, in order.
	Received [][]byte
	// Signed counts the approved signatures; Shown counts the address confirmations shown.
	Signed, Shown int

	// Closed counts the transports closed while a held review waited for their answer.
	Closed int

	// a held review: reviewing is closed when one is on the screen, decided when the holder decides it
	reviewing, decided chan struct{}

	// signing state, as the app keeps it
	signing bool
	path    ledger.Path
	want    int
	msg     []byte
}

// New is a fake device with the Ethereum app open.
func New(seed string) *App { return &App{Seed: seed, Name: ledger.EthereumApp, Version: "1.23.0"} }

// Key is the scalar the fake signs with at path.
func (a *App) Key(path ledger.Path) []byte { return keyAt(a.Seed, path) }

// AddressAt is the address the fake signs as at path.
func (a *App) AddressAt(path ledger.Path) string {
	return "0x" + hex.EncodeToString(sig.AddressOf(a.Key(path)))
}

func keyAt(seed string, path ledger.Path) []byte {
	h := sha256.Sum256([]byte(seed + "\x00" + path.String()))
	var s secp256k1.ModNScalar
	s.SetByteSlice(h[:])
	if s.IsZero() {
		s.SetInt(1)
	}
	b := s.Bytes()
	return b[:]
}

func sw(code uint16, data ...byte) []byte { return append(data, byte(code>>8), byte(code)) }

// ClosedCount is Closed, read under the fake's lock.
func (a *App) ClosedCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Closed
}

// IsPending is Pending, read under the fake's lock.
func (a *App) IsPending() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.Pending
}

// Reviewing returns a channel closed once a held review is on the screen.
func (a *App) Reviewing() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.reviewing == nil {
		a.reviewing = make(chan struct{})
	}
	return a.reviewing
}

// Decide is the holder deciding the review on the screen (approve, or reject when Reject is set). A held exchange
// still waiting answers; a review left open by a closed transport is dismissed.
func (a *App) Decide() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Pending = false
	if a.decided != nil {
		close(a.decided)
		a.decided = nil
	}
}

// Exchange answers one APDU (a transport that is never closed).
func (a *App) Exchange(apdu []byte) ([]byte, error) { return a.exchange(apdu, nil) }

// Transport is this fake as a transport whose closing (closed) ends a held review's wait.
func (a *App) Transport(closed <-chan struct{}) ledger.Transport {
	return transportFunc(func(apdu []byte) ([]byte, error) { return a.exchange(apdu, closed) })
}

type transportFunc func([]byte) ([]byte, error)

func (f transportFunc) Exchange(apdu []byte) ([]byte, error) { return f(apdu) }

// hold puts a review on the screen and waits, unlocked, until the holder decides or the transport is closed. It
// reports whether the holder decided (false: closed, the review stays open).
func (a *App) hold(closed <-chan struct{}) bool {
	a.Pending = true
	dec := make(chan struct{})
	a.decided = dec
	if a.reviewing == nil {
		a.reviewing = make(chan struct{})
	}
	close(a.reviewing)
	a.mu.Unlock()
	ok := true
	select {
	case <-dec:
	case <-closed:
		ok = false
	}
	a.mu.Lock()
	a.reviewing = nil
	if !ok {
		a.Closed++
	}
	return ok
}

func (a *App) exchange(apdu []byte, closed <-chan struct{}) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Received = append(a.Received, append([]byte{}, apdu...))
	if a.DisconnectAt > 0 && len(a.Received) >= a.DisconnectAt {
		a.signing = false
		return nil, &ledger.Error{Slug: ledger.Disconnected, Detail: "the fake device was unplugged"}
	}
	if a.Stray != nil {
		r := a.Stray
		a.Stray = nil
		return r, nil
	}
	if a.Locked {
		return sw(ledger.SWLocked), nil
	}
	if a.Pending {
		return sw(ledger.SWReviewPending), nil
	}
	if len(apdu) < 5 || int(apdu[4]) != len(apdu)-5 {
		return sw(ledger.SWWrongDataLength), nil
	}
	cla, ins, p1, data := apdu[0], apdu[1], apdu[2], apdu[5:]
	if cla == 0xb0 && ins == 0x01 {
		out := []byte{1, byte(len(a.Name))}
		out = append(out, a.Name...)
		out = append(out, byte(len(a.Version)))
		out = append(out, a.Version...)
		out = append(out, 1, 0)
		return sw(ledger.SWOK, out...), nil
	}
	if a.Name != ledger.EthereumApp {
		if a.Name == "BOLOS" {
			return sw(ledger.SWInvalidCLA01), nil
		}
		return sw(ledger.SWInvalidCLA), nil
	}
	if cla != 0xe0 {
		return sw(ledger.SWInvalidCLA), nil
	}
	switch ins {
	case 0x02:
		if r := a.address(p1, data, closed); r != nil {
			return r, nil
		}
		return nil, &ledger.Error{Slug: ledger.Disconnected, Detail: "the transport was closed during the review"}
	case 0x08:
		if p1 == 0 && a.BeforeSign != nil {
			a.BeforeSign()
		}
		if r := a.sign(p1, data, closed); r != nil {
			return r, nil
		}
		return nil, &ledger.Error{Slug: ledger.Disconnected, Detail: "the transport was closed during the review"}
	}
	return sw(ledger.SWInvalidINS), nil
}

func parsePath(data []byte) (ledger.Path, []byte, bool) {
	if len(data) < 1 || data[0] == 0 || data[0] > 10 || len(data) < 1+4*int(data[0]) {
		return nil, nil, false
	}
	n := int(data[0])
	p := make(ledger.Path, n)
	for i := range n {
		o := 1 + 4*i
		p[i] = uint32(data[o])<<24 | uint32(data[o+1])<<16 | uint32(data[o+2])<<8 | uint32(data[o+3])
	}
	return p, data[1+4*n:], true
}

func (a *App) address(p1 byte, data []byte, closed <-chan struct{}) []byte {
	if a.signing {
		return sw(ledger.SWCommandNotAllowed)
	}
	if p1 > 1 {
		return sw(ledger.SWWrongP1P2)
	}
	p, rest, ok := parsePath(data)
	if !ok || len(rest) != 0 {
		return sw(ledger.SWIncorrectData)
	}
	seed := a.Seed
	if a.AddressSeed != "" {
		seed = a.AddressSeed
	}
	priv := secp256k1.PrivKeyFromBytes(keyAt(seed, p))
	if p1 == 1 {
		a.Shown++
		if a.Hold && !a.hold(closed) {
			return nil
		}
		if a.Reject {
			return sw(ledger.SWRejected)
		}
	}
	out := []byte{65}
	out = append(out, priv.PubKey().SerializeUncompressed()...)
	out = append(out, 40)
	out = append(out, hex.EncodeToString(sig.Address(priv.PubKey()))...)
	return sw(ledger.SWOK, out...)
}

func (a *App) sign(p1 byte, data []byte, closed <-chan struct{}) []byte {
	switch p1 {
	case 0x00:
		if a.signing {
			return sw(ledger.SWCommandNotAllowed)
		}
		p, rest, ok := parsePath(data)
		if !ok || len(rest) < 4 {
			return sw(ledger.SWIncorrectData)
		}
		n := int(rest[0])<<24 | int(rest[1])<<16 | int(rest[2])<<8 | int(rest[3])
		a.signing, a.path, a.want, a.msg = true, p, n, nil
		data = rest[4:]
	case 0x80:
		if !a.signing {
			return sw(ledger.SWIncorrectData)
		}
	default:
		a.signing = false
		return sw(ledger.SWWrongP1P2)
	}
	if len(a.msg)+len(data) > a.want {
		a.signing = false
		return sw(ledger.SWIncorrectData)
	}
	a.msg = append(a.msg, data...)
	if len(a.msg) < a.want {
		return sw(ledger.SWOK)
	}
	a.signing = false
	if a.MaxMessage > 0 && a.want > a.MaxMessage {
		return sw(ledger.SWInsufficientMemory) // as the app: after the last chunk, before any review
	}
	if a.Hold && !a.hold(closed) {
		return nil
	}
	if a.Reject {
		return sw(ledger.SWRejected)
	}
	a.Signed++
	msg := a.msg
	if a.Form == Corrupt {
		msg = append(append([]byte{}, msg...), '!')
	}
	c := sig.SignEIP191(a.Key(a.path), msg) // r ‖ s ‖ v, canonical
	eq := sig.Equivalents(c)                // v01, high, highV01
	var rsv []byte
	switch a.Form {
	case V01:
		rsv = eq[0]
	case HighS:
		rsv = eq[1]
	case HighSV01:
		rsv = eq[2]
	case Garbage:
		rsv = append(make([]byte, 32), c[32:]...)
	default:
		rsv = c
	}
	out := append([]byte{rsv[64]}, rsv[:64]...)
	if a.Form == Short {
		out = out[:64]
	}
	return sw(ledger.SWOK, out...)
}

// Opener returns a device opener over this fake (as the binary's opener over a real device), recording the spec.
func (a *App) Opener(specs *[]string) func(string) (*ledger.Device, error) {
	return func(spec string) (*ledger.Device, error) {
		if specs != nil {
			*specs = append(*specs, spec)
		}
		closed := make(chan struct{})
		var once sync.Once
		return ledger.NewDevice(a.Transport(closed), "Nano S Plus", "fake device", false, func() error {
			once.Do(func() { close(closed) })
			return nil
		}), nil
	}
}

// ServeTCP answers the Speculos APDU protocol on l with this fake until l is closed: a request is a 4-byte
// big-endian length and the APDU; an answer is the 4-byte big-endian length of the data, the data and the status
// word. A client closing its connection while a held review waits ends that wait (the review stays open).
func (a *App) ServeTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go a.serve(c)
	}
}

func (a *App) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		var h [4]byte
		if _, err := io.ReadFull(br, h[:]); err != nil {
			return
		}
		n := int(h[0])<<24 | int(h[1])<<16 | int(h[2])<<8 | int(h[3])
		req := make([]byte, n)
		if _, err := io.ReadFull(br, req); err != nil {
			return
		}
		// while the request is answered, watch for the client going away (a client sends nothing while it waits)
		closed, watched := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(watched)
			if _, err := br.Peek(1); err != nil && !errors.Is(err, os.ErrDeadlineExceeded) {
				close(closed)
			}
		}()
		resp, err := a.exchange(req, closed)
		c.SetReadDeadline(time.Now())
		<-watched
		c.SetReadDeadline(time.Time{})
		var le *ledger.Error
		if errors.As(err, &le) {
			return // a disconnect: close the connection
		}
		d := len(resp) - 2
		if _, err := c.Write(append([]byte{byte(d >> 24), byte(d >> 16), byte(d >> 8), byte(d)}, resp...)); err != nil {
			return
		}
	}
}
