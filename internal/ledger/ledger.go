// Package ledger is a connector to the Ledger Ethereum app: it reads the app's name and version, the address at
// a BIP-32 path, and asks the device for an EIP-191 personal_sign signature over a message the user reviews on the
// device. It speaks the app's own APDUs (CLA 0xE0: 0x02 get address, 0x08 sign personal message; CLA 0xB0 0x01
// app and version), which are the same on Nano S, Nano S Plus, Nano X, Flex and Stax.
//
// The package signs nothing itself and trusts nothing the device returns: the caller verifies every signature
// with the reader's own check before using it. A Transport carries one APDU and its response; this package
// provides three, USB HID on Linux (hidraw) and on macOS (IOKit), both with Ledger HID framing and no cgo, and the
// Speculos emulator's TCP APDU port, and Open picks one from a device spec. On other operating systems the USB
// transport is not built and Open says so.
package ledger

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// Transport carries one APDU to the device and returns the device's whole response: data followed by the two
// status-word bytes.
type Transport interface {
	Exchange(apdu []byte) ([]byte, error)
}

// Timeouter is implemented by a transport whose exchanges can time out. The app's commands set a short timeout for
// an exchange the device answers at once and a long one for an exchange that waits for the user.
type Timeouter interface {
	SetTimeout(d time.Duration)
}

// Exchange timeouts: an answer the device computes, and one that waits for the user to review and approve.
var (
	ShortTimeout = 10 * time.Second
	UserTimeout  = 10 * time.Minute
)

// Device is an open device: its transport, what is known of it, and how to release it.
type Device struct {
	Transport
	// Model is the device model as the transport learned it ("Nano X", from the USB product), "" when unknown.
	Model string
	// Where names the device for a person: the hidraw node, the IOKit registry entry, or "emulator at <host:port>".
	Where string
	// Emulator is true for the Speculos TCP transport: no hardware is involved.
	Emulator bool
	close    func() error
}

// SetTimeout passes the timeout of the next exchange to the transport when it can time out. Without it a Device would
// hide its transport's Timeouter, and every exchange, the one waiting for the user included, would keep the short one.
func (d *Device) SetTimeout(t time.Duration) {
	if to, ok := d.Transport.(Timeouter); ok {
		to.SetTimeout(t)
	}
}

// Close releases the device.
func (d *Device) Close() error {
	if d == nil || d.close == nil {
		return nil
	}
	return d.close()
}

// NewDevice wraps a transport (an emulator, a test fake) as a Device.
func NewDevice(t Transport, model, where string, emulator bool, close func() error) *Device {
	return &Device{Transport: t, Model: model, Where: where, Emulator: emulator, close: close}
}

// Error is a typed connector failure. Slug is a stable token; SW is the status word when the device sent one
// (0 when the failure is the transport's).
type Error struct {
	Slug   string
	SW     uint16
	Detail string
}

func (e *Error) Error() string {
	s := e.Slug + ": " + e.Detail
	if e.SW != 0 {
		s += " (status word " + SWText(e.SW) + ")"
	}
	return s
}

// Failure slugs.
const (
	Rejected       = "ledger-rejected"         // the user refused on the device
	Locked         = "ledger-locked"           // the device is locked: unlock it with its PIN
	AppClosed      = "ledger-app-closed"       // no app is open (the dashboard answered)
	WrongApp       = "ledger-wrong-app"        // another app is open (the caller decides, from the app name)
	TooLong        = "ledger-message-too-long" // the app cannot hold or show a message this long
	Busy           = "ledger-busy"             // a review is already pending on the device, or the app is mid-request
	BadRequest     = "ledger-bad-request"      // the app refused the request's data (a connector bug)
	BadResponse    = "ledger-bad-response"     // the device's answer is malformed
	DeviceError    = "ledger-device-error"     // any other status word
	NoDevice       = "ledger-no-device"        // no device was found, or the one named cannot be opened
	Disconnected   = "ledger-disconnected"     // the device went away mid-exchange
	Timeout        = "ledger-timeout"          // the device did not answer in time
	NotBuilt       = "ledger-not-built"        // this transport is not built for this operating system
	BadDeviceSpec  = "ledger-bad-device"       // the device spec is not one this package understands
	Unusable       = "ledger-device-unusable"  // the device node exists but cannot be opened (permissions)
	MultipleDevice = "ledger-several-devices"  // more than one device and none named
	Interrupted    = "ledger-interrupted"      // the user interrupted the command while a review waited on the device
)

// Status words the Ethereum app and the device's dashboard send.
const (
	SWOK                 = 0x9000
	SWRejected           = 0x6985 // conditions not satisfied: the user refused
	SWLocked             = 0x5515
	SWCommandNotAllowed  = 0x6980
	SWReviewPending      = 0x6901 // a review is on the device's screen: every APDU gets this until the user decides
	SWIncorrectData      = 0x6a80
	SWInsufficientMemory = 0x6a84
	SWWrongDataLength    = 0x6a87
	SWWrongP1P2          = 0x6b00
	SWInvalidINS         = 0x6d00
	SWInvalidCLA         = 0x6e00
	SWInvalidCLA01       = 0x6e01
	SWNoApp              = 0x6511
)

// SWText is a status word as four hex digits with 0x.
func SWText(sw uint16) string {
	s := strconv.FormatUint(uint64(sw), 16)
	return "0x" + strings.Repeat("0", 4-len(s)) + s
}

// swError maps a status word that is not 0x9000 to a typed failure. what names the request ("sign the message").
func swError(sw uint16, what string) *Error {
	e := &Error{SW: sw}
	switch sw {
	case SWRejected:
		e.Slug, e.Detail = Rejected, "the request to "+what+" was refused on the device"
	case SWLocked:
		e.Slug, e.Detail = Locked, "the device is locked"
	case SWInvalidCLA, SWInvalidCLA01, SWInvalidINS, SWNoApp:
		e.Slug, e.Detail = AppClosed, "the Ethereum app is not open on the device"
	case SWInsufficientMemory:
		e.Slug, e.Detail = TooLong, "the app has not enough memory to "+what+" (the message is too long for it)"
	case SWReviewPending:
		e.Slug, e.Detail = Busy, "a review is already pending on the device"
	case SWCommandNotAllowed:
		e.Slug, e.Detail = Busy, "the app is busy with another request"
	case SWIncorrectData:
		e.Slug, e.Detail = BadRequest, "the app refused the data of the request to "+what+" (a fault in this connector: please report it)"
	default:
		e.Slug, e.Detail = DeviceError, "the device refused the request to "+what
	}
	return e
}

// split separates a response into data and status word.
func split(resp []byte) ([]byte, uint16, error) {
	if len(resp) < 2 {
		return nil, 0, &Error{Slug: BadResponse, Detail: "the response is shorter than a status word"}
	}
	n := len(resp) - 2
	return resp[:n], uint16(resp[n])<<8 | uint16(resp[n+1]), nil
}

// IsSlug reports whether err is a connector failure with the given slug.
func IsSlug(err error, slug string) bool {
	var e *Error
	return errors.As(err, &e) && e.Slug == slug
}

// --- derivation paths ---------------------------------------------------------------------------------

// MaxPathDepth is the deepest BIP-32 path accepted (the app accepts at most 10 components).
const MaxPathDepth = 10

const hardened = 0x80000000

// Path is a BIP-32 derivation path.
type Path []uint32

// ParsePath reads m/44'/60'/0'/0/0: "m" then 1 to MaxPathDepth components, each a decimal below 2^31 with no
// leading zero, hardened when followed by ' or h. There is no default path.
func ParsePath(s string) (Path, error) {
	parts := strings.Split(s, "/")
	if len(parts) < 2 || parts[0] != "m" {
		return nil, errors.New("a derivation path starts with m/ and names at least one component, for example m/44'/60'/7'/0/0")
	}
	if len(parts)-1 > MaxPathDepth {
		return nil, errors.New("a derivation path has at most " + strconv.Itoa(MaxPathDepth) + " components")
	}
	var p Path
	for _, c := range parts[1:] {
		h := uint32(0)
		if strings.HasSuffix(c, "'") || strings.HasSuffix(c, "h") {
			h, c = hardened, c[:len(c)-1]
		}
		if c == "" || strings.Trim(c, "0123456789") != "" || (len(c) > 1 && c[0] == '0') {
			return nil, errors.New("each path component is a decimal number, optionally followed by ' or h (hardened)")
		}
		n, err := strconv.ParseUint(c, 10, 32)
		if err != nil || n >= hardened {
			return nil, errors.New("a path component is below 2147483648")
		}
		p = append(p, uint32(n)|h)
	}
	return p, nil
}

// String is the canonical spelling: m/ then components, hardened ones with '.
func (p Path) String() string {
	var b strings.Builder
	b.WriteString("m")
	for _, c := range p {
		b.WriteString("/" + strconv.FormatUint(uint64(c&^hardened), 10))
		if c&hardened != 0 {
			b.WriteString("'")
		}
	}
	return b.String()
}

// IsEthereumAccount reports whether p is under m/44'/60', the Ethereum coin type the app derives for.
func (p Path) IsEthereumAccount() bool {
	return len(p) >= 2 && p[0] == 44|hardened && p[1] == 60|hardened
}

// encode is the path as the app reads it: the component count, then each component as 4 bytes big-endian.
func (p Path) encode() []byte {
	b := []byte{byte(len(p))}
	for _, c := range p {
		b = append(b, byte(c>>24), byte(c>>16), byte(c>>8), byte(c))
	}
	return b
}
