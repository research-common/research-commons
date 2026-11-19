//go:build darwin

package ledger

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// HIDBuilt reports whether this build can open a USB device (IOKit HID on macOS).
const HIDBuilt = true

// The macOS USB transport talks to IOKit's HID manager without cgo (iokit_imports_darwin.go). It writes each report
// with IOHIDDeviceSetReport and reads by polling an IOHIDQueue holding the device's 64-byte input element: IOKit
// delivers input reports to C callbacks on a run loop, which a CGO_ENABLED=0 build cannot receive, and
// IOHIDDeviceGetReport is refused by the device (kIOReturnUnsupported). A queue delivers an element's value only
// when it changes, so the port asks the transport for a fresh channel each exchange (ChannelPort): the device echoes
// the channel, and no answer equals the report before it.

// syscall.syscall9 is the runtime's call into a C function with up to nine integer arguments, the one x/sys/unix
// uses on darwin. Checked against go1.27.2; see iokit_darwin_arm64.s.
//
//go:linkname syscall_syscall9 syscall.syscall9
func syscall_syscall9(fn, a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (r1, r2 uintptr, err syscall.Errno)

// call runs the C function at fn with up to nine integer or pointer arguments and returns its integer or pointer
// result. Every function bound here takes and returns only such values.
func call(fn uintptr, args ...uintptr) uintptr {
	var a [9]uintptr
	copy(a[:], args)
	r, _, _ := syscall_syscall9(fn, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
	return r
}

const (
	kCFStringEncodingUTF8  = 0x08000100
	kCFNumberSInt64Type    = 4
	kIOHIDReportTypeOutput = 1
	// element types: input misc, button, axis (kIOHIDElementTypeInput_*)
	kIOHIDElementTypeInputMisc = 1
	kIOHIDElementTypeInputAxis = 3
	kIOReturnSuccess           = 0
	queueDepth                 = 128
	pollFast                   = time.Millisecond
	pollSlow                   = 20 * time.Millisecond
	pollFastFor                = 200 * time.Millisecond
	presenceEvery              = 250 * time.Millisecond
)

// cfString makes a CFString the caller releases.
func cfString(s string) uintptr {
	b := append([]byte(s), 0)
	r := call(fnCFStringCreateWithCString, 0, uintptr(unsafe.Pointer(&b[0])), kCFStringEncodingUTF8)
	runtime.KeepAlive(b)
	return r
}

// intProperty reads a numeric property of a HID device; ok false when it is absent.
func intProperty(dev uintptr, key string) (int64, bool) {
	k := cfString(key)
	defer call(fnCFRelease, k)
	n := call(fnIOHIDDeviceGetProperty, dev, k) // not owned: no release
	if n == 0 {
		return 0, false
	}
	var v int64
	if call(fnCFNumberGetValue, n, kCFNumberSInt64Type, uintptr(unsafe.Pointer(&v)))&0xff == 0 {
		return 0, false
	}
	return v, true
}

// macDevice is one Ledger HID interface IOKit lists.
type macDevice struct {
	ref uintptr // IOHIDDeviceRef, owned by the manager's device set
	HIDNode
}

// listLedgers lists the Ledger HID interfaces attached. The returned release frees the manager and the device set;
// the refs are valid until then.
func listLedgers() ([]macDevice, func()) {
	m := call(fnIOHIDManagerCreate, 0, 0)
	if m == 0 {
		return nil, func() {}
	}
	call(fnIOHIDManagerSetDeviceMatching, m, 0) // every HID device; filtered by property below
	set := call(fnIOHIDManagerCopyDevices, m)
	release := func() {
		if set != 0 {
			call(fnCFRelease, set)
		}
		call(fnCFRelease, m)
	}
	if set == 0 {
		return nil, release
	}
	n := int(call(fnCFSetGetCount, set))
	if n == 0 {
		return nil, release
	}
	refs := make([]uintptr, n)
	call(fnCFSetGetValues, set, uintptr(unsafe.Pointer(&refs[0])))
	var out []macDevice
	for _, d := range refs {
		if v, ok := intProperty(d, "VendorID"); !ok || v != VendorID {
			continue
		}
		pro, _ := intProperty(d, "ProductID")
		page, _ := intProperty(d, "PrimaryUsagePage")
		var id uint64
		if svc := call(fnIOHIDDeviceGetService, d); svc != 0 {
			call(fnIORegistryEntryGetRegistryEntryID, svc, uintptr(unsafe.Pointer(&id)))
		}
		out = append(out, macDevice{ref: d, HIDNode: HIDNode{
			Node:    "USB (IOKit registry entry 0x" + strconv.FormatUint(id, 16) + ")",
			Product: uint16(pro),
			Model:   ModelOf(uint16(pro)),
			App:     page == usagePageApp,
		}})
	}
	return out, release
}

// openHID opens the one Ledger APDU interface attached. macOS has no device node to name, so a named spec is refused
// by CheckSpec before this is reached; several devices attached is a failure asking for one to be disconnected.
func openHID(named string) (*Device, error) {
	if named != "" {
		return nil, &Error{Slug: BadDeviceSpec, Detail: "on macOS a USB device is not named: attach one Ledger and give no device"}
	}
	devs, release := listLedgers()
	nodes := make([]HIDNode, len(devs))
	for i, d := range devs {
		nodes[i] = d.HIDNode
	}
	n, err := PickHID(nodes, "")
	if err != nil {
		release()
		if IsSlug(err, MultipleDevice) {
			return nil, &Error{Slug: MultipleDevice, Detail: "several Ledger devices are attached by USB; on macOS a device is not named, so disconnect all but one"}
		}
		return nil, err
	}
	var dev uintptr
	for _, d := range devs {
		if d.HIDNode == n {
			dev = d.ref
		}
	}
	p, err := openPort(dev)
	release() // the port holds its own references
	if err != nil {
		return nil, err
	}
	return &Device{Transport: NewHIDTransport(p), Model: n.Model, Where: n.Node, close: p.Close}, nil
}

// iokitPort is an open Ledger APDU interface. Its methods are safe to call from several goroutines: Close may run
// while a Read waits (an interrupted review), and a Read then returns at once.
type iokitPort struct {
	mu       sync.Mutex
	dev      uintptr // IOHIDDeviceRef, retained by openPort and released by Close
	svc      uintptr // io_service_t of the device, to notice an unplug
	queue    uintptr // IOHIDQueueRef
	closed   bool
	deadline time.Time
	lastSeen uint16 // the channel of the last input report (the element's cached value at open)
	lastSent uint16 // the channel of the last request
}

// errClosed is what a Read returns once Close has run.
var errClosed = errors.New("the device was closed")

// openPort opens dev, retaining it: the caller may then release the device set it came from.
func openPort(dev uintptr) (*iokitPort, error) {
	if r := call(fnIOHIDDeviceOpen, dev, 0); r != kIOReturnSuccess {
		return nil, &Error{Slug: NoDevice, Detail: "the Ledger's USB interface cannot be opened (IOReturn 0x" + strconv.FormatUint(uint64(uint32(r)), 16) + "); close any other app using it (Ledger Live), then try again"}
	}
	call(fnCFRetain, dev)
	fail := func(e *Error) (*iokitPort, error) {
		call(fnIOHIDDeviceClose, dev, 0)
		call(fnCFRelease, dev)
		return nil, e
	}
	p := &iokitPort{dev: dev, svc: call(fnIOHIDDeviceGetService, dev)}
	elems := call(fnIOHIDDeviceCopyMatchingElements, dev, 0, 0)
	if elems == 0 {
		return fail(&Error{Slug: NoDevice, Detail: "the Ledger's USB interface lists no HID elements"})
	}
	defer call(fnCFRelease, elems)
	var elem uintptr
	for i := 0; i < int(call(fnCFArrayGetCount, elems)); i++ {
		e := call(fnCFArrayGetValueAtIndex, elems, uintptr(i))
		t := call(fnIOHIDElementGetType, e)
		if t >= kIOHIDElementTypeInputMisc && t <= kIOHIDElementTypeInputAxis &&
			call(fnIOHIDElementGetReportSize, e) == 8 && call(fnIOHIDElementGetReportCount, e) == packetSize {
			elem = e
			break
		}
	}
	if elem == 0 {
		return fail(&Error{Slug: NoDevice, Detail: "the Ledger's USB interface has no 64-byte input report"})
	}
	// the channel of the report IOKit last cached: an answer on it would not be delivered
	var v uintptr
	if call(fnIOHIDDeviceGetValue, dev, elem, uintptr(unsafe.Pointer(&v))) == kIOReturnSuccess && v != 0 {
		if b := valueBytes(v); len(b) >= 2 {
			p.lastSeen = uint16(b[0])<<8 | uint16(b[1])
		}
	}
	p.lastSent = p.lastSeen
	p.queue = call(fnIOHIDQueueCreate, 0, dev, queueDepth, 0)
	if p.queue == 0 {
		return fail(&Error{Slug: NoDevice, Detail: "IOKit cannot create a queue for the Ledger's input reports"})
	}
	call(fnIOHIDQueueAddElement, p.queue, elem)
	call(fnIOHIDQueueStart, p.queue)
	return p, nil
}

// valueBytes is the byte content of an IOHIDValueRef (valid while the value is).
func valueBytes(v uintptr) []byte {
	n := int(call(fnIOHIDValueGetLength, v))
	ptr := call(fnIOHIDValueGetBytePtr, v)
	if n <= 0 || ptr == 0 {
		return nil
	}
	// ptr is memory IOKit owns, not Go's: read it through a pointer-typed copy, as vet asks for a uintptr from C
	return unsafe.Slice(*(**byte)(unsafe.Pointer(&ptr)), n)
}

// NextChannel picks the channel of the next exchange: one past the last sent, never 0x0000, never the channel of the
// last report the queue holds (ChannelPort).
func (p *iokitPort) NextChannel() uint16 {
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.lastSent + 1
	for c == 0 || c == p.lastSeen {
		c++
	}
	p.lastSent = c
	return c
}

// Write sends one report: p is the report id followed by the 64-byte report.
func (p *iokitPort) Write(b []byte) (int, error) {
	if len(b) < 1 {
		return 0, errors.New("an empty report")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, errClosed
	}
	r := call(fnIOHIDDeviceSetReport, p.dev, kIOHIDReportTypeOutput, uintptr(b[0]), uintptr(unsafe.Pointer(&b[1])), uintptr(len(b)-1))
	runtime.KeepAlive(b)
	if r != kIOReturnSuccess {
		return 0, errors.New("IOHIDDeviceSetReport returned 0x" + strconv.FormatUint(uint64(uint32(r)), 16))
	}
	return len(b), nil
}

// SetReadDeadline bounds the next reads; the zero time waits without end.
func (p *iokitPort) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.deadline = t
	p.mu.Unlock()
	return nil
}

// Read returns the next 64-byte input report. It polls the queue, every millisecond at first and every 20 ms after
// 200 ms (an exchange that waits for the holder can last minutes), and checks every 250 ms that the device is still
// attached.
func (p *iokitPort) Read(b []byte) (int, error) {
	start := time.Now()
	lastCheck := start
	for {
		n, ok, err := p.poll(b)
		if err != nil || ok {
			return n, err
		}
		now := time.Now()
		p.mu.Lock()
		dl := p.deadline
		p.mu.Unlock()
		if !dl.IsZero() && now.After(dl) {
			return 0, os.ErrDeadlineExceeded
		}
		if now.Sub(lastCheck) >= presenceEvery {
			lastCheck = now
			if !p.attached() {
				return 0, errors.New("the device was disconnected")
			}
		}
		if now.Sub(start) < pollFastFor {
			time.Sleep(pollFast)
		} else {
			time.Sleep(pollSlow)
		}
	}
}

// poll takes one value from the queue, if there is one.
func (p *iokitPort) poll(b []byte) (int, bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, false, errClosed
	}
	v := call(fnIOHIDQueueCopyNextValue, p.queue)
	if v == 0 {
		return 0, false, nil
	}
	defer call(fnCFRelease, v)
	r := valueBytes(v)
	if len(r) >= 2 {
		p.lastSeen = uint16(r[0])<<8 | uint16(r[1])
	}
	return copy(b, r), true, nil
}

// attached reports whether the device is still in the IO registry (an unplugged device leaves the service plane).
func (p *iokitPort) attached() bool {
	if p.svc == 0 {
		return true
	}
	plane := append([]byte("IOService"), 0)
	ok := call(fnIORegistryEntryInPlane, p.svc, uintptr(unsafe.Pointer(&plane[0])))&0xff != 0
	runtime.KeepAlive(plane)
	return ok
}

// Close stops the queue and closes the device; a Read waiting returns at once. It is idempotent.
func (p *iokitPort) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	call(fnIOHIDQueueStop, p.queue)
	call(fnCFRelease, p.queue)
	call(fnIOHIDDeviceClose, p.dev, 0)
	call(fnCFRelease, p.dev)
	return nil
}
