package ledger

import "time"

// Ledger HID framing (the same on every model): an APDU travels in 64-byte reports, each starting with the channel
// 0x0101, the tag 0x05 and a 2-byte big-endian sequence index from 0; the first report then carries the APDU's
// 2-byte big-endian length. The response comes back framed the same way. On the wire to the device each report is
// prefixed with the HID report id 0 (65 bytes written); the reports read back have no prefix.

const (
	packetSize = 64
	channel    = 0x0101
	tagAPDU    = 0x05
)

// Frame splits an APDU into the 64-byte reports that carry it (zero-padded), without the report-id prefix.
func Frame(apdu []byte) [][]byte {
	var out [][]byte
	data := append([]byte{byte(len(apdu) >> 8), byte(len(apdu))}, apdu...)
	for seq := 0; len(data) > 0 || seq == 0; seq++ {
		p := make([]byte, packetSize)
		p[0], p[1], p[2], p[3], p[4] = channel>>8, channel&0xff, tagAPDU, byte(seq>>8), byte(seq)
		n := copy(p[5:], data)
		data = data[n:]
		out = append(out, p)
	}
	return out
}

// Unframer reassembles a framed response from reports read one at a time.
type Unframer struct {
	seq  int
	want int
	buf  []byte
}

// Add takes the next report. It returns the whole response once every byte has arrived (done true), and an error
// for a report on another channel, with another tag, out of sequence, or too short to be a report.
func (u *Unframer) Add(p []byte) (resp []byte, done bool, err error) {
	if len(p) < 5 {
		return nil, false, &Error{Slug: BadResponse, Detail: "a HID report is shorter than its header"}
	}
	if int(p[0])<<8|int(p[1]) != channel {
		return nil, false, &Error{Slug: BadResponse, Detail: "a HID report arrived on another channel"}
	}
	if p[2] != tagAPDU {
		return nil, false, &Error{Slug: BadResponse, Detail: "a HID report carries an unknown tag"}
	}
	if seq := int(p[3])<<8 | int(p[4]); seq != u.seq {
		return nil, false, &Error{Slug: BadResponse, Detail: "a HID report arrived out of sequence (got " + itoa(seq) + ", want " + itoa(u.seq) + ")"}
	}
	body := p[5:]
	if u.seq == 0 {
		if len(body) < 2 {
			return nil, false, &Error{Slug: BadResponse, Detail: "the first HID report has no response length"}
		}
		u.want = int(body[0])<<8 | int(body[1])
		body = body[2:]
		if u.want < 2 {
			return nil, false, &Error{Slug: BadResponse, Detail: "the response is shorter than a status word"}
		}
	}
	u.seq++
	need := u.want - len(u.buf)
	u.buf = append(u.buf, body[:min(need, len(body))]...)
	if len(u.buf) == u.want {
		return u.buf, true, nil
	}
	return nil, false, nil
}

// HIDPort is an open HID device node: Write sends one output report (with its report-id prefix), Read returns one
// input report. SetReadDeadline bounds the next reads (a node that cannot time out returns an error, and reads
// then wait).
type HIDPort interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	SetReadDeadline(t time.Time) error
}

// HIDTransport carries APDUs over a HID port with Ledger framing.
type HIDTransport struct {
	port    HIDPort
	timeout time.Duration
}

// NewHIDTransport wraps a HID port.
func NewHIDTransport(p HIDPort) *HIDTransport { return &HIDTransport{port: p, timeout: ShortTimeout} }

// SetTimeout sets how long the next exchange waits for the device.
func (h *HIDTransport) SetTimeout(d time.Duration) { h.timeout = d }

// Exchange frames the APDU, writes every report (report id 0 first), and reads reports until the response is whole.
func (h *HIDTransport) Exchange(apdu []byte) ([]byte, error) {
	for _, p := range Frame(apdu) {
		if _, err := h.port.Write(append([]byte{0}, p...)); err != nil {
			return nil, ioError(err)
		}
	}
	h.port.SetReadDeadline(time.Now().Add(h.timeout))
	var u Unframer
	buf := make([]byte, packetSize+1)
	for {
		n, err := h.port.Read(buf)
		if err != nil {
			return nil, ioError(err)
		}
		if n == 0 {
			return nil, &Error{Slug: Disconnected, Detail: "the device closed the connection"}
		}
		resp, done, err := u.Add(buf[:n])
		if err != nil {
			return nil, err
		}
		if done {
			return resp, nil
		}
	}
}
