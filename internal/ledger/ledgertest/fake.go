// Package ledgertest is an in-process fake of a Ledger device running the Ethereum app, for tests: it answers the
// app's APDUs (app and version, get address, personal sign in chunks) the way app-ethereum does, signs with
// throwaway secp256k1 keys derived from the path, and can be told to refuse, lock, disconnect, run another app,
// or return the signature in each encoding the device may use.
package ledgertest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"sync"

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

	// Received is every APDU the fake was sent, in order.
	Received [][]byte
	// Signed counts the approved signatures; Shown counts the address confirmations shown.
	Signed, Shown int

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

// Exchange answers one APDU.
func (a *App) Exchange(apdu []byte) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Received = append(a.Received, append([]byte{}, apdu...))
	if a.DisconnectAt > 0 && len(a.Received) >= a.DisconnectAt {
		a.signing = false
		return nil, &ledger.Error{Slug: ledger.Disconnected, Detail: "the fake device was unplugged"}
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
		return a.address(p1, data), nil
	case 0x08:
		return a.sign(p1, data), nil
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

func (a *App) address(p1 byte, data []byte) []byte {
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

func (a *App) sign(p1 byte, data []byte) []byte {
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
		return ledger.NewDevice(a, "Nano S Plus", "fake device", false, nil), nil
	}
}

// ServeTCP answers the Speculos APDU protocol on l with this fake until l is closed: a request is a 4-byte
// big-endian length and the APDU; an answer is the 4-byte big-endian length of the data, the data and the status
// word.
func (a *App) ServeTCP(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			for {
				var h [4]byte
				if _, err := io.ReadFull(c, h[:]); err != nil {
					return
				}
				n := int(h[0])<<24 | int(h[1])<<16 | int(h[2])<<8 | int(h[3])
				req := make([]byte, n)
				if _, err := io.ReadFull(c, req); err != nil {
					return
				}
				resp, err := a.Exchange(req)
				var le *ledger.Error
				if errors.As(err, &le) {
					return // a disconnect: close the connection
				}
				d := len(resp) - 2
				if _, err := c.Write(append([]byte{byte(d >> 24), byte(d >> 16), byte(d >> 8), byte(d)}, resp...)); err != nil {
					return
				}
			}
		}(c)
	}
}
