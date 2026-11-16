package ledger

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// TCPTransport speaks the Speculos emulator's APDU port: a request is the APDU's length as 4 bytes big-endian then
// the APDU; the answer is the length of its data (without the status word) as 4 bytes big-endian, the data, then the
// 2-byte status word. No hardware is involved: it is labelled an emulator everywhere it is shown.
type TCPTransport struct {
	conn    net.Conn
	timeout time.Duration
}

// maxTCPResponse bounds an emulator answer (the app never sends more than a few hundred bytes).
const maxTCPResponse = 1 << 16

// DialTCP connects to an emulator's APDU port at host:port.
func DialTCP(addr string) (*TCPTransport, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return nil, &Error{Slug: BadDeviceSpec, Detail: "an emulator is named tcp:<host>:<port>"}
	}
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, &Error{Slug: NoDevice, Detail: "no emulator answers at " + addr}
	}
	return &TCPTransport{conn: c, timeout: ShortTimeout}, nil
}

// NewTCPTransport wraps an open connection (a test pipe).
func NewTCPTransport(c net.Conn) *TCPTransport { return &TCPTransport{conn: c, timeout: ShortTimeout} }

// SetTimeout sets the deadline of the next exchange.
func (t *TCPTransport) SetTimeout(d time.Duration) { t.timeout = d }

// Close closes the connection.
func (t *TCPTransport) Close() error { return t.conn.Close() }

// Exchange sends one APDU and reads its answer.
func (t *TCPTransport) Exchange(apdu []byte) ([]byte, error) {
	t.conn.SetDeadline(time.Now().Add(t.timeout))
	n := len(apdu)
	req := append([]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}, apdu...)
	if _, err := t.conn.Write(req); err != nil {
		return nil, ioError(err)
	}
	var h [4]byte
	if _, err := io.ReadFull(t.conn, h[:]); err != nil {
		return nil, ioError(err)
	}
	size := int(h[0])<<24 | int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	if size < 0 || size > maxTCPResponse {
		return nil, &Error{Slug: BadResponse, Detail: "the emulator announced an answer of " + itoa(size) + " bytes"}
	}
	resp := make([]byte, size+2)
	if _, err := io.ReadFull(t.conn, resp); err != nil {
		return nil, ioError(err)
	}
	return resp, nil
}

// ioError maps a transport read or write failure: a deadline is a Timeout, anything else a Disconnected.
func ioError(err error) error {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return &Error{Slug: Timeout, Detail: "the device did not answer in time"}
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return &Error{Slug: Timeout, Detail: "the device did not answer in time"}
	}
	return &Error{Slug: Disconnected, Detail: "the device went away: " + err.Error()}
}

// Open opens the device a spec names:
//   - "" : the one Ledger device attached by USB (Linux hidraw); none or several is a failure;
//   - "/dev/hidrawN" : that hidraw node (Linux);
//   - "tcp:<host>:<port>" : a Speculos emulator's APDU port (no hardware; labelled an emulator).
func Open(spec string) (*Device, error) {
	if rest, ok := strings.CutPrefix(spec, "tcp:"); ok {
		t, err := DialTCP(rest)
		if err != nil {
			return nil, err
		}
		return &Device{Transport: t, Where: "emulator at " + rest, Emulator: true, close: t.Close}, nil
	}
	if spec != "" {
		if err := CheckSpec(spec); err != nil {
			return nil, &Error{Slug: BadDeviceSpec, Detail: err.Error()}
		}
	}
	return openHID(spec)
}

// CheckSpec checks the shape of a device spec without opening anything: a hidraw node (/dev/hidrawN) or an emulator
// (tcp:<host>:<port>).
func CheckSpec(spec string) error {
	if rest, ok := strings.CutPrefix(spec, "tcp:"); ok {
		host, port, err := net.SplitHostPort(rest)
		if err != nil || host == "" || port == "" {
			return errors.New("an emulator is named tcp:<host>:<port>")
		}
		return nil
	}
	if n, ok := strings.CutPrefix(spec, "/dev/hidraw"); ok && n != "" && strings.Trim(n, "0123456789") == "" {
		return nil
	}
	return errors.New("a device is a hidraw node (/dev/hidrawN) or an emulator (tcp:<host>:<port>)")
}
