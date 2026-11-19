package ledger_test

import (
	"bytes"
	"os"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/ledger/ledgertest"
)

// TestFrameOnChannel: a response framed on a channel is reassembled by an unframer expecting it, and refused by one
// expecting another (0x0101 when none is set).
func TestFrameOnChannel(t *testing.T) {
	resp := append(bytes.Repeat([]byte{7}, 130), 0x90, 0)
	fs := ledger.FrameOn(0x2a5c, resp)
	for i, f := range fs {
		if f[0] != 0x2a || f[1] != 0x5c || int(f[3])<<8|int(f[4]) != i {
			t.Fatalf("report %d header % x", i, f[:5])
		}
	}
	u := ledger.Unframer{Channel: 0x2a5c}
	var got []byte
	for _, f := range fs {
		r, done, err := u.Add(f)
		if err != nil {
			t.Fatal(err)
		}
		if done {
			got = r
		}
	}
	if !bytes.Equal(got, resp) {
		t.Fatal("round trip on channel 0x2a5c")
	}
	for name, u := range map[string]*ledger.Unframer{"default": {}, "other": {Channel: 0x2a5d}} {
		if _, _, err := u.Add(fs[0]); !ledger.IsSlug(err, ledger.BadResponse) {
			t.Fatalf("%s: a report on another channel: %v", name, err)
		}
	}
	if !bytes.Equal(ledger.Frame(resp)[0], ledger.FrameOn(0x0101, resp)[0]) {
		t.Fatal("Frame is not FrameOn(0x0101)")
	}
}

// echoPort is a HID port over the fake app that answers on the channel each request came on, as a device does, and,
// like an IOKit queue, drops a report byte-equal to the one delivered before it. Without ChannelPort it is the port
// macOS would be with channel 0x0101 throughout.
type echoPort struct {
	app       *ledgertest.App
	fresh     bool // implement NextChannel through the wrapper below
	next      uint16
	sent      []uint16
	in        []byte
	want      int
	ch        uint16
	out       [][]byte
	last      []byte
	deadlined bool
}

func (e *echoPort) SetReadDeadline(time.Time) error { return nil }

func (e *echoPort) Write(p []byte) (int, error) {
	r := p[1:]
	ch := uint16(r[0])<<8 | uint16(r[1])
	body := r[5:]
	if r[3] == 0 && r[4] == 0 {
		e.ch, e.want, e.in = ch, int(body[0])<<8|int(body[1]), nil
		body = body[2:]
	}
	e.in = append(e.in, body[:min(len(body), e.want-len(e.in))]...)
	if len(e.in) == e.want {
		resp, err := e.app.Exchange(e.in)
		if err != nil {
			return 0, err
		}
		for _, f := range ledger.FrameOn(e.ch, resp) {
			if bytes.Equal(f, e.last) {
				continue // the queue never delivers it
			}
			e.out = append(e.out, f)
			e.last = f
		}
	}
	return len(p), nil
}

func (e *echoPort) Read(p []byte) (int, error) {
	if len(e.out) == 0 {
		e.deadlined = true
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, e.out[0])
	e.out = e.out[1:]
	return n, nil
}

type freshPort struct{ *echoPort }

func (f freshPort) NextChannel() uint16 {
	f.next++
	f.sent = append(f.sent, f.next)
	return f.next
}

// TestHIDTransportFreshChannel: the same request twice over a port that drops a repeated report. On a fixed channel
// the second answer never arrives (a timeout); with ChannelPort every exchange goes on the channel the port names
// and both answers arrive.
func TestHIDTransportFreshChannel(t *testing.T) {
	fixed := &echoPort{app: ledgertest.New("fixed")}
	tr := ledger.NewHIDTransport(fixed)
	if _, err := ledger.AppAndVersion(tr); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AppAndVersion(tr); !ledger.IsSlug(err, ledger.Timeout) {
		t.Fatalf("a repeated answer on one channel was delivered: %v", err)
	}
	e := &echoPort{app: ledgertest.New("fresh"), next: 0x0100}
	tr = ledger.NewHIDTransport(freshPort{e})
	for i := 0; i < 3; i++ {
		if a, err := ledger.AppAndVersion(tr); err != nil || a.Name != "Ethereum" {
			t.Fatalf("exchange %d: %v %v", i, a, err)
		}
	}
	if len(e.sent) != 3 || e.sent[0] != 0x0101 || e.sent[2] != 0x0103 || e.deadlined {
		t.Fatalf("channels %04x, timed out %v", e.sent, e.deadlined)
	}
}
