//go:build linux

package ledger

import (
	"errors"
	"io/fs"
	"os"
	"syscall"
)

// HIDBuilt reports whether this build can open a USB device (hidraw, Linux only).
const HIDBuilt = true

// sysHidraw and devDir are where the hidraw nodes are listed and opened.
var (
	sysHidraw = "/sys/class/hidraw"
	devDir    = "/dev"
)

// openHID opens the named hidraw node, or the one Ledger APDU interface attached. It uses the plain file API: a
// hidraw node reads and writes whole reports, and the runtime poller gives reads a deadline.
func openHID(named string) (*Device, error) {
	n, err := PickHID(FindHID(sysHidraw, devDir), named)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(n.Node, os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return nil, &Error{Slug: Unusable, Detail: "no permission to open " + n.Node + "; install Ledger's udev rules (or give your user access to the node), then reconnect the device"}
		}
		return nil, &Error{Slug: NoDevice, Detail: n.Node + " cannot be opened: " + err.Error()}
	}
	return &Device{Transport: NewHIDTransport(f), Model: n.Model, Where: n.Node, close: f.Close}, nil
}
