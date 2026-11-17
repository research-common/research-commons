package ledger_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/ledger"
	"github.com/research-common/research-commons/internal/ledger/ledgertest"
	"github.com/research-common/research-commons/internal/sig"
)

func mustPath(t *testing.T, s string) ledger.Path {
	t.Helper()
	p, err := ledger.ParsePath(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return p
}

func TestParsePath(t *testing.T) {
	for in, want := range map[string]string{
		"m/44'/60'/7'/0/0":           "m/44'/60'/7'/0/0",
		"m/44h/60h/7h/0/0":           "m/44'/60'/7'/0/0",
		"m/0":                        "m/0",
		"m/2147483647'":              "m/2147483647'",
		"m/1/2/3/4/5/6/7/8/9/10":     "m/1/2/3/4/5/6/7/8/9/10",
		"m/44'/60'/0'/0/1234567890'": "m/44'/60'/0'/0/1234567890'",
	} {
		p, err := ledger.ParsePath(in)
		if err != nil || p.String() != want {
			t.Fatalf("%s: %v %v", in, p, err)
		}
	}
	for _, in := range []string{"", "m", "m/", "44'/60'", "M/44'", "m/44''", "m/-1", "m/01", "m/2147483648", "m/1/2/3/4/5/6/7/8/9/10/11",
		"m/44'/", "m//1", "m/0x10", "m/ 1", "m/1'h", "m/4294967295"} {
		if _, err := ledger.ParsePath(in); err == nil {
			t.Fatalf("%q accepted", in)
		}
	}
	if !mustPath(t, "m/44'/60'/7'/0/0").IsEthereumAccount() || mustPath(t, "m/44'/0'/0'").IsEthereumAccount() || mustPath(t, "m/44/60").IsEthereumAccount() {
		t.Fatal("IsEthereumAccount")
	}
}

// TestGoldenAPDUs: the exact bytes of each command, against the app's documented encoding.
func TestGoldenAPDUs(t *testing.T) {
	p := mustPath(t, "m/44'/60'/7'/0/0")
	pathHex := "05" + "8000002c" + "8000003c" + "80000007" + "00000000" + "00000000"
	f := ledgertest.New("golden")
	if _, err := ledger.AppAndVersion(f); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Address(f, p, false); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Address(f, p, true); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.PersonalSign(f, p, []byte("DSSEv1 hello")); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"b001000000",
		"e002000015" + pathHex,
		"e002010015" + pathHex,
		"e008000025" + pathHex + "0000000c" + hex.EncodeToString([]byte("DSSEv1 hello")),
	}
	for i, w := range want {
		if got := hex.EncodeToString(f.Received[i]); got != w {
			t.Fatalf("APDU %d:\n got %s\nwant %s", i, got, w)
		}
	}
	if f.Shown != 1 || f.Signed != 1 {
		t.Fatalf("shown %d signed %d", f.Shown, f.Signed)
	}
}

// TestChunkBoundaries: the first chunk holds the path, the length and 255-21-4 = 230 bytes for a 5-component path;
// each next one up to 255; the reassembled message is the message, for sizes around every boundary.
func TestChunkBoundaries(t *testing.T) {
	p := mustPath(t, "m/44'/60'/7'/0/0") // 21 bytes encoded
	first := 255 - 21 - 4
	for _, n := range []int{0, 1, 150, 151, first - 1, first, first + 1, 255, 256, first + 255, first + 256, 1000, 4096, 7652, 7653} {
		msg := make([]byte, n)
		for i := range msg {
			msg[i] = byte('a' + i%26)
		}
		cs := ledger.Chunks(p, msg)
		wantN := 1
		if n > first {
			wantN += (n - first + 254) / 255
		}
		if len(cs) != wantN {
			t.Fatalf("n=%d: %d chunks, want %d", n, len(cs), wantN)
		}
		var got []byte
		for i, c := range cs {
			if len(c) > ledger.MaxChunk || len(c) == 0 && i > 0 {
				t.Fatalf("n=%d chunk %d is %d bytes", n, i, len(c))
			}
			if i == 0 {
				if !bytes.Equal(c[:21], ledger.SignAPDUs(p, nil)[0][5:26]) {
					t.Fatalf("n=%d: the first chunk does not start with the path", n)
				}
				if l := int(c[21])<<24 | int(c[22])<<16 | int(c[23])<<8 | int(c[24]); l != n {
					t.Fatalf("n=%d: declared length %d", n, l)
				}
				c = c[25:]
			} else if i < len(cs)-1 && len(c) != 255 {
				t.Fatalf("n=%d: middle chunk %d is %d bytes", n, i, len(c))
			}
			got = append(got, c...)
		}
		if !bytes.Equal(got, msg) {
			t.Fatalf("n=%d: chunks do not reassemble", n)
		}
		as := ledger.SignAPDUs(p, msg)
		for i, a := range as {
			if a[0] != 0xe0 || a[1] != 0x08 || (i == 0) != (a[2] == 0x00) || (i > 0) != (a[2] == 0x80) || a[3] != 0 || int(a[4]) != len(a)-5 {
				t.Fatalf("n=%d: APDU %d header % x", n, i, a[:5])
			}
		}
		// the fake app reassembles and signs exactly these bytes
		f := ledgertest.New("chunks")
		s, err := ledger.PersonalSign(f, p, msg)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if _, ok := sig.VerifyEIP191(msg, s, sig.AddressOf(f.Key(p))); !ok {
			t.Fatalf("n=%d: the signature does not verify", n)
		}
	}
}

// TestSignatureForms: whatever valid encoding the device answers, PersonalSign returns the canonical r ‖ s ‖ v that
// verifies; a corrupted, garbage or short answer is either refused or does not verify.
func TestSignatureForms(t *testing.T) {
	p := mustPath(t, "m/44'/60'/7'/0/0")
	msg := []byte("DSSEv1 forms")
	for _, form := range []ledgertest.SigForm{ledgertest.Canonical, ledgertest.V01, ledgertest.HighS, ledgertest.HighSV01} {
		f := ledgertest.New("forms")
		f.Form = form
		s, err := ledger.PersonalSign(f, p, msg)
		if err != nil {
			t.Fatalf("form %d: %v", form, err)
		}
		if !bytes.Equal(s, sig.SignEIP191(f.Key(p), msg)) {
			t.Fatalf("form %d: not the canonical encoding", form)
		}
	}
	f := ledgertest.New("forms")
	f.Form = ledgertest.Corrupt
	s, err := ledger.PersonalSign(f, p, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sig.VerifyEIP191(msg, s, sig.AddressOf(f.Key(p))); ok {
		t.Fatal("a corrupted signature verifies")
	}
	for _, form := range []ledgertest.SigForm{ledgertest.Garbage, ledgertest.Short} {
		f := ledgertest.New("forms")
		f.Form = form
		if _, err := ledger.PersonalSign(f, p, msg); !ledger.IsSlug(err, ledger.BadResponse) {
			t.Fatalf("form %d: %v", form, err)
		}
	}
}

// TestStatusWords: each refusal the device sends maps to its slug, at the step it happens.
func TestStatusWords(t *testing.T) {
	p := mustPath(t, "m/44'/60'/7'/0/0")
	long := bytes.Repeat([]byte("x"), 2000)
	cases := []struct {
		name string
		set  func(f *ledgertest.App)
		slug string
		sw   uint16
	}{
		{"rejected", func(f *ledgertest.App) { f.Reject = true }, ledger.Rejected, 0x6985},
		{"locked", func(f *ledgertest.App) { f.Locked = true }, ledger.Locked, 0x5515},
		{"dashboard", func(f *ledgertest.App) { f.Name = "BOLOS" }, ledger.AppClosed, 0x6e01},
		{"other app", func(f *ledgertest.App) { f.Name = "Bitcoin" }, ledger.AppClosed, 0x6e00},
		{"heap", func(f *ledgertest.App) { f.MaxMessage = 1000 }, ledger.TooLong, 0x6a84},
		{"review pending", func(f *ledgertest.App) { f.Pending = true }, ledger.Busy, 0x6901},
		{"disconnect mid-stream", func(f *ledgertest.App) { f.DisconnectAt = 3 }, ledger.Disconnected, 0},
	}
	for _, c := range cases {
		f := ledgertest.New("sw")
		c.set(f)
		_, err := ledger.PersonalSign(f, p, long)
		var e *ledger.Error
		if !errors.As(err, &e) || e.Slug != c.slug || e.SW != c.sw {
			t.Fatalf("%s: %v", c.name, err)
		}
		if f.Signed != 0 {
			t.Fatalf("%s: signed", c.name)
		}
	}
	// 0x6a84 on the last chunk is the app's heap: too long; 0x6a80 anywhere is a bad request
	if _, err := ledger.PersonalSign(lastChunk{sw: 0x6a84}, p, long); !ledger.IsSlug(err, ledger.TooLong) {
		t.Fatalf("heap on the last chunk: %v", err)
	}
	if _, err := ledger.PersonalSign(lastChunk{sw: 0x6a80}, p, long); !ledger.IsSlug(err, ledger.BadRequest) {
		t.Fatalf("bad data on the last chunk: %v", err)
	}
	// a message over the connector's bound is refused before anything is sent
	f := ledgertest.New("sw")
	if _, err := ledger.PersonalSign(f, p, make([]byte, ledger.MaxMessage+1)); !ledger.IsSlug(err, ledger.TooLong) || len(f.Received) != 0 {
		t.Fatalf("over the protocol bound: %v, %d sent", err, len(f.Received))
	}
	// no pre-send cap at the emulator's measured heap limit: the app decides (the fake has no heap limit here)
	if _, err := ledger.PersonalSign(f, p, bytes.Repeat([]byte("a"), 7653)); err != nil || f.Signed != 1 {
		t.Fatalf("7653 bytes: %v", err)
	}
	// other words
	for sw, slug := range map[uint16]string{0x6980: ledger.Busy, 0x6901: ledger.Busy, 0x6a80: ledger.BadRequest, 0x6a84: ledger.TooLong, 0x6d00: ledger.AppClosed, 0x6511: ledger.AppClosed, 0x6f00: ledger.DeviceError} {
		_, err := ledger.AppAndVersion(fixed{resp: []byte{byte(sw >> 8), byte(sw)}})
		if !ledger.IsSlug(err, slug) {
			t.Fatalf("sw %04x: %v", sw, err)
		}
	}
	// the address confirmation refused
	f = ledgertest.New("sw")
	f.Reject = true
	if _, err := ledger.Address(f, p, true); !ledger.IsSlug(err, ledger.Rejected) || f.Shown != 1 {
		t.Fatalf("address refused: %v", err)
	}
	if !strings.Contains(ledger.SWText(0x6985), "0x6985") || ledger.SWText(0x15) != "0x0015" {
		t.Fatal("SWText")
	}
}

// lastChunk accepts every chunk and answers the last one (P1 0x80 with fewer than 255 bytes) with sw.
type lastChunk struct{ sw uint16 }

func (l lastChunk) Exchange(a []byte) ([]byte, error) {
	if a[2] == 0x80 && len(a)-5 < 255 {
		return []byte{byte(l.sw >> 8), byte(l.sw)}, nil
	}
	return []byte{0x90, 0}, nil
}

// fixed answers every APDU with one response.
type fixed struct{ resp []byte }

func (f fixed) Exchange([]byte) ([]byte, error) { return f.resp, nil }

// TestMalformedResponses: answers that are not what the app sends are refused, never read past their end.
func TestMalformedResponses(t *testing.T) {
	p := mustPath(t, "m/44'/60'/7'/0/0")
	ok := func(b ...byte) []byte { return append(b, 0x90, 0x00) }
	addrResp, _ := ledgertest.New("m").Exchange(append([]byte{0xe0, 0x02, 0, 0, 21}, ledger.SignAPDUs(p, nil)[0][5:26]...))
	for name, resp := range map[string][]byte{
		"empty":           {},
		"one byte":        {0x90},
		"no format":       ok(),
		"format 2":        ok(2, 1, 'a', 1, '1'),
		"name overrun":    ok(1, 9, 'a'),
		"version overrun": ok(1, 1, 'a', 5, '1'),
		"flags overrun":   ok(1, 1, 'a', 1, '1', 3, 0),
		"control in name": ok(1, 2, 'a', 0x07, 1, '1'),
	} {
		if _, err := ledger.AppAndVersion(fixed{resp}); !ledger.IsSlug(err, ledger.BadResponse) {
			t.Fatalf("app %s: %v", name, err)
		}
	}
	mut := func(f func(b []byte) []byte) []byte { return f(append([]byte{}, addrResp...)) }
	for name, resp := range map[string][]byte{
		"empty data":     ok(),
		"key length":     mut(func(b []byte) []byte { b[0] = 33; return b }),
		"not a point":    mut(func(b []byte) []byte { b[10] ^= 1; return b }),
		"addr length":    mut(func(b []byte) []byte { b[66] = 42; return b }),
		"wrong address":  mut(func(b []byte) []byte { b[70] ^= 1; return b }),
		"trailing bytes": mut(func(b []byte) []byte { return append(b[:len(b)-2], 0, 0x90, 0) }),
		"truncated":      mut(func(b []byte) []byte { return append(b[:80], 0x90, 0) }),
	} {
		if _, err := ledger.Address(fixed{resp}, p, false); !ledger.IsSlug(err, ledger.BadResponse) {
			t.Fatalf("address %s: %v", name, err)
		}
	}
	// a chunk answered with data
	if _, err := ledger.PersonalSign(fixed{ok(1)}, p, make([]byte, 600)); !ledger.IsSlug(err, ledger.BadResponse) {
		t.Fatalf("chunk with data: %v", err)
	}
	// the address check accepts the checksummed text the app sends
	a, err := ledger.Address(ledgertest.New("m"), p, false)
	if err != nil || a != ledgertest.New("m").AddressAt(p) {
		t.Fatalf("address: %s %v", a, err)
	}
}

// TestFraming: frames round-trip through the unframer at sizes around the report boundaries; wrong channel, tag,
// sequence and short reports are refused.
func TestFraming(t *testing.T) {
	for _, n := range []int{0, 1, 2, 57, 58, 59, 60, 121, 122, 123, 255 + 5, 1000} {
		a := make([]byte, n)
		for i := range a {
			a[i] = byte(i)
		}
		fs := ledger.Frame(a)
		if want := 1 + max(0, (n+2-59+58)/59); n+2 > 59 && len(fs) != want || n+2 <= 59 && len(fs) != 1 {
			t.Fatalf("n=%d: %d reports", n, len(fs))
		}
		var u ledger.Unframer
		var got []byte
		for i, f := range fs {
			if len(f) != 64 || f[0] != 1 || f[1] != 1 || f[2] != 5 || int(f[3])<<8|int(f[4]) != i {
				t.Fatalf("n=%d report %d header % x", n, i, f[:5])
			}
			r, done, err := u.Add(f)
			if n < 2 {
				if err == nil {
					t.Fatalf("n=%d: a response shorter than a status word was accepted", n)
				}
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if done != (i == len(fs)-1) {
				t.Fatalf("n=%d: done at %d of %d", n, i, len(fs))
			}
			got = r
		}
		if n >= 2 && !bytes.Equal(got, a) {
			t.Fatalf("n=%d: round trip", n)
		}
	}
	one := ledger.Frame([]byte{1, 2, 3, 0x90, 0})
	two := ledger.Frame(make([]byte, 100))
	for name, c := range map[string][][]byte{
		"short":    {one[0][:4]},
		"channel":  {append([]byte{1, 2}, one[0][2:]...)},
		"tag":      {append([]byte{1, 1, 6}, one[0][3:]...)},
		"sequence": {two[1]},
		"gap":      {two[0], append([]byte{1, 1, 5, 0, 2}, two[1][5:]...)},
		"no len":   {one[0][:6]},
	} {
		var u ledger.Unframer
		var err error
		for _, r := range c {
			if _, _, err = u.Add(r); err != nil {
				break
			}
		}
		if !ledger.IsSlug(err, ledger.BadResponse) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// hidPipe is a HID port over the fake app: written reports are unframed into APDUs, answers framed into reads.
type hidPipe struct {
	app      *ledgertest.App
	in       ledger.Unframer
	out      [][]byte
	inBuf    []byte
	want     int
	readErr  error
	deadline time.Time
	extra    [][]byte // reports injected before the answer
}

func (h *hidPipe) SetReadDeadline(t time.Time) error { h.deadline = t; return nil }

func (h *hidPipe) Write(p []byte) (int, error) {
	if len(p) != 65 || p[0] != 0 {
		return 0, errors.New("a report is 65 bytes starting with report id 0")
	}
	r := p[1:]
	seq := int(r[3])<<8 | int(r[4])
	body := r[5:]
	if seq == 0 {
		h.want = int(body[0])<<8 | int(body[1])
		h.inBuf = nil
		body = body[2:]
	}
	h.inBuf = append(h.inBuf, body[:min(len(body), h.want-len(h.inBuf))]...)
	if len(h.inBuf) == h.want {
		resp, err := h.app.Exchange(h.inBuf)
		if err != nil {
			h.readErr = errors.New("read: no such device")
			return len(p), nil
		}
		h.out = append(h.out, h.extra...)
		h.out = append(h.out, ledger.Frame(resp)...)
	}
	return len(p), nil
}

func (h *hidPipe) Read(p []byte) (int, error) {
	if h.readErr != nil {
		return 0, h.readErr
	}
	if len(h.out) == 0 {
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(p, h.out[0])
	h.out = h.out[1:]
	return n, nil
}

// TestHIDTransport: the whole flow over the HID framing, a disconnect and a timeout mapped, a report on another
// channel refused.
func TestHIDTransport(t *testing.T) {
	p := mustPath(t, "m/44'/60'/7'/0/0")
	app := ledgertest.New("hid")
	tr := ledger.NewHIDTransport(&hidPipe{app: app})
	if a, err := ledger.AppAndVersion(tr); err != nil || a.Name != "Ethereum" || a.Version != "1.23.0" {
		t.Fatalf("%v %v", a, err)
	}
	if a, err := ledger.Address(tr, p, false); err != nil || a != app.AddressAt(p) {
		t.Fatalf("%v %v", a, err)
	}
	msg := bytes.Repeat([]byte("DSSEv1 "), 200)
	s, err := ledger.PersonalSign(tr, p, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sig.VerifyEIP191(msg, s, sig.AddressOf(app.Key(p))); !ok {
		t.Fatal("does not verify")
	}
	app.DisconnectAt = len(app.Received) + 2
	if _, err := ledger.PersonalSign(tr, p, msg); !ledger.IsSlug(err, ledger.Disconnected) {
		t.Fatalf("disconnect: %v", err)
	}
	// nothing answers: a timeout
	silent := ledger.NewHIDTransport(&hidPipe{app: ledgertest.New("x"), readErr: os.ErrDeadlineExceeded})
	if _, err := ledger.AppAndVersion(silent); !ledger.IsSlug(err, ledger.Timeout) {
		t.Fatalf("timeout: %v", err)
	}
	// a report on another channel before the answer
	other := ledger.Frame([]byte{0x90, 0})[0]
	other[1] = 2
	if _, err := ledger.AppAndVersion(ledger.NewHIDTransport(&hidPipe{app: ledgertest.New("x"), extra: [][]byte{other}})); !ledger.IsSlug(err, ledger.BadResponse) {
		t.Fatalf("other channel: %v", err)
	}
}

// TestTCPTransport: the Speculos APDU protocol against the fake served on loopback, and Open's spec forms.
func TestTCPTransport(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback:", err)
	}
	defer l.Close()
	app := ledgertest.New("tcp")
	go app.ServeTCP(l)
	d, err := ledger.Open("tcp:" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if !d.Emulator || !strings.Contains(d.Where, "emulator") {
		t.Fatalf("not labelled an emulator: %+v", d)
	}
	p := mustPath(t, "m/44'/60'/7'/0/0")
	msg := bytes.Repeat([]byte("z"), 900)
	s, err := ledger.PersonalSign(d, p, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sig.VerifyEIP191(msg, s, sig.AddressOf(app.Key(p))); !ok {
		t.Fatal("does not verify")
	}
	app.DisconnectAt = len(app.Received) + 1
	if _, err := ledger.AppAndVersion(d); !ledger.IsSlug(err, ledger.Disconnected) {
		t.Fatalf("disconnect: %v", err)
	}
	for _, spec := range []string{"hidraw0", "tcp:", "tcp:nohost", "usb:1", "/dev/hidraw", "/dev/hidrawx", "/dev/sda", "tcp::99"} {
		if _, err := ledger.Open(spec); !ledger.IsSlug(err, ledger.BadDeviceSpec) {
			t.Fatalf("%q: %v", spec, err)
		}
	}
	for _, spec := range []string{"/dev/hidraw0", "/dev/hidraw12", "tcp:127.0.0.1:9999", "tcp:[::1]:9999", "tcp:speculos:9999"} {
		if err := ledger.CheckSpec(spec); err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
	}
	// nothing listening
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l2.Addr().String()
	l2.Close()
	if _, err := ledger.Open("tcp:" + addr); !ledger.IsSlug(err, ledger.NoDevice) {
		t.Fatalf("closed port: %v", err)
	}
	// a server that never answers: a timeout
	l3, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l3.Close()
	go func() {
		c, err := l3.Accept()
		if err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	tr, err := ledger.DialTCP(l3.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tr.SetTimeout(100 * time.Millisecond)
	if _, err := tr.Exchange([]byte{0xb0, 1, 0, 0, 0}); !ledger.IsSlug(err, ledger.Timeout) {
		t.Fatalf("silent server: %v", err)
	}
}

// TestFindHID: Ledger nodes are found in a fake sysfs tree by vendor id, the APDU interface by usage page 0xFFA0
// (else interface 0), and picked: one found, none, several, a named node, a named node that is not a Ledger.
func TestFindHID(t *testing.T) {
	sys, dev := t.TempDir(), "/dev"
	add := func(n, hidID string, desc []byte, ifn string) {
		d := filepath.Join(sys, n, "device")
		os.MkdirAll(d, 0o755)
		os.WriteFile(filepath.Join(d, "uevent"), []byte("DRIVER=hid-generic\nHID_ID="+hidID+"\nHID_NAME=x\n"), 0o644)
		if desc != nil {
			os.WriteFile(filepath.Join(d, "report_descriptor"), desc, 0o644)
		}
		if ifn != "" {
			os.WriteFile(filepath.Join(sys, n, "bInterfaceNumber"), []byte(ifn+"\n"), 0o644)
		}
	}
	appDesc := []byte{0x06, 0xa0, 0xff, 0x09, 0x01, 0xa1, 0x01}  // usage page 0xFFA0
	fidoDesc := []byte{0x06, 0xd0, 0xf1, 0x09, 0x01, 0xa1, 0x01} // FIDO 0xF1D0
	add("hidraw3", "0003:00002C97:00004011", appDesc, "")
	add("hidraw4", "0003:00002C97:00004011", fidoDesc, "")
	add("hidraw1", "0003:0000046D:0000C52B", appDesc, "") // another vendor
	add("hidraw10", "0003:00002C97:00005011", nil, "00")  // no descriptor: interface 0 is the APDU interface
	nodes := ledger.FindHID(sys, dev)
	if len(nodes) != 3 || nodes[0].Node != "/dev/hidraw3" || !nodes[0].App || nodes[1].App || !nodes[2].App || nodes[0].Model != "Nano X" || nodes[2].Model != "Nano S Plus" {
		t.Fatalf("%+v", nodes)
	}
	if n, err := ledger.PickHID(nodes[:2], ""); err != nil || n.Node != "/dev/hidraw3" {
		t.Fatalf("one: %v %v", n, err)
	}
	if _, err := ledger.PickHID(nil, ""); !ledger.IsSlug(err, ledger.NoDevice) {
		t.Fatalf("none: %v", err)
	}
	two := append(nodes[:2:2], ledger.HIDNode{Node: "/dev/hidraw7", App: true})
	if _, err := ledger.PickHID(two, ""); !ledger.IsSlug(err, ledger.MultipleDevice) {
		t.Fatalf("several: %v", err)
	}
	if n, err := ledger.PickHID(two, "/dev/hidraw7"); err != nil || n.Node != "/dev/hidraw7" {
		t.Fatalf("named: %v", err)
	}
	if _, err := ledger.PickHID(two, "/dev/hidraw4"); !ledger.IsSlug(err, ledger.NoDevice) {
		t.Fatalf("named FIDO: %v", err)
	}
	if _, err := ledger.PickHID(two, "/dev/hidraw1"); !ledger.IsSlug(err, ledger.NoDevice) {
		t.Fatalf("named other vendor: %v", err)
	}
	for pid, m := range map[uint16]string{0x0001: "Nano S", 0x1011: "Nano S", 0x4015: "Nano X", 0x5011: "Nano S Plus", 0x6011: "Stax", 0x7011: "Flex", 0x9999: ""} {
		if ledger.ModelOf(pid) != m {
			t.Fatalf("%04x: %q", pid, ledger.ModelOf(pid))
		}
	}
	if (ledger.MessageDisplay([]byte("DSSEv1 12 a/b {\"x\":1}\n")) != "text") || ledger.MessageDisplay([]byte{'a', 0}) != "hex" || ledger.MessageDisplay([]byte("é")) != "hex" {
		t.Fatal("MessageDisplay")
	}
}

// recordingTransport records the timeout set before each exchange.
type recordingTransport struct {
	app  *ledgertest.App
	next time.Duration
	seen []time.Duration
}

func (r *recordingTransport) SetTimeout(d time.Duration) { r.next = d }
func (r *recordingTransport) Exchange(a []byte) ([]byte, error) {
	r.seen = append(r.seen, r.next)
	return r.app.Exchange(a)
}

// TestDeviceTimeouts: through a Device, every exchange is short except the last sign chunk and a confirmed address,
// which wait for the user as long as asked.
func TestDeviceTimeouts(t *testing.T) {
	rt := &recordingTransport{app: ledgertest.New("to")}
	d := ledger.NewDevice(rt, "", "test", false, nil)
	p := mustPath(t, "m/44'/60'/7'/0/0")
	if _, err := ledger.AppAndVersion(d); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.AddressWait(d, p, true, 3*time.Minute); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.PersonalSignWait(d, p, make([]byte, 600), 7*time.Minute); err != nil {
		t.Fatal(err)
	}
	s, u := ledger.ShortTimeout, 7*time.Minute
	want := []time.Duration{s, 3 * time.Minute, s, s, u}
	if len(rt.seen) != len(want) {
		t.Fatalf("%d exchanges: %v", len(rt.seen), rt.seen)
	}
	for i := range want {
		if rt.seen[i] != want[i] {
			t.Fatalf("exchange %d waited %v, want %v (all: %v)", i, rt.seen[i], want[i], rt.seen)
		}
	}
}

// TestStrayReviewAnswer: a review left open by a command that went away and decided later delivers its answer to the
// next request (the emulated Ethereum app 1.23.0 does). AppAndVersion, the first request of every command, names
// either answer as an earlier review's, never as this device's app or as a refusal of this request; the request after
// it is answered normally.
func TestStrayReviewAnswer(t *testing.T) {
	for name, stray := range map[string][]byte{
		"refusal":   {0x69, 0x85},
		"signature": append(append([]byte{27}, bytes.Repeat([]byte{1}, 64)...), 0x90, 0x00),
	} {
		f := ledgertest.New("stray")
		f.Stray = stray
		_, err := ledger.AppAndVersion(f)
		var e *ledger.Error
		if !errors.As(err, &e) || e.Slug == ledger.Rejected || !strings.Contains(e.Detail, "an earlier review") {
			t.Fatalf("%s: %v", name, err)
		}
		if app, err := ledger.AppAndVersion(f); err != nil || app.Name != ledger.EthereumApp {
			t.Fatalf("%s: the next request: %v %v", name, app, err)
		}
	}
}
