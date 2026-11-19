//go:build !linux && !darwin

package ledger

import "runtime"

// HIDBuilt reports whether this build can open a USB device (Linux and macOS only).
const HIDBuilt = false

// openHID: USB HID on this operating system needs its own system interface (the Windows HID API), which this build
// does not use. An emulator (tcp:<host>:<port>) still works.
func openHID(string) (*Device, error) {
	return nil, &Error{Slug: NotBuilt, Detail: "the USB connector is built for Linux and macOS only; on " + runtime.GOOS +
		" sign with the external-signing package by hand, or use an emulator (tcp:<host>:<port>)"}
}
