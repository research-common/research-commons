package ledger

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// Finding a Ledger among the hidraw nodes (Linux sysfs). Every function here reads sysfs under a root the caller
// names, so tests run on a fake tree; nothing here opens a device node.

// VendorID is Ledger's USB vendor id.
const VendorID = 0x2c97

// usagePageApp is the HID usage page of the interface the apps speak APDUs on (the others are FIDO and the like).
const usagePageApp = 0xffa0

// HIDNode is one hidraw node that belongs to a Ledger device.
type HIDNode struct {
	Node    string // /dev/hidrawN
	Product uint16
	Model   string
	// App is true when the node is the APDU interface (usage page 0xFFA0, or interface 0 when the report descriptor
	// cannot be read).
	App bool
}

// ModelOf names a Ledger model from its USB product id ("" when unknown). Current firmware reports the model in
// the high byte; old firmware used small ids.
func ModelOf(product uint16) string {
	switch product {
	case 0x0001:
		return "Nano S"
	case 0x0004:
		return "Nano X"
	case 0x0005:
		return "Nano S Plus"
	case 0x0006:
		return "Stax"
	case 0x0007:
		return "Flex"
	}
	switch product >> 8 {
	case 0x10:
		return "Nano S"
	case 0x40:
		return "Nano X"
	case 0x50:
		return "Nano S Plus"
	case 0x60:
		return "Stax"
	case 0x70:
		return "Flex"
	}
	return ""
}

// parseHIDID reads "HID_ID=0003:00002C97:00004011" from a uevent file: bus, vendor, product.
func parseHIDID(uevent string) (vendor, product uint16, ok bool) {
	for _, l := range strings.Split(uevent, "\n") {
		v, found := strings.CutPrefix(l, "HID_ID=")
		if !found {
			continue
		}
		f := strings.Split(v, ":")
		if len(f) != 3 {
			return 0, 0, false
		}
		ven, err1 := strconv.ParseUint(f[1], 16, 32)
		pro, err2 := strconv.ParseUint(f[2], 16, 32)
		if err1 != nil || err2 != nil || ven > 0xffff || pro > 0xffff {
			return 0, 0, false
		}
		return uint16(ven), uint16(pro), true
	}
	return 0, 0, false
}

// usagePages lists the usage pages a HID report descriptor declares (short items, global tag Usage Page).
func usagePages(desc []byte) []uint32 {
	var out []uint32
	for i := 0; i < len(desc); {
		b := desc[i]
		if b == 0xfe { // long item: size in the next byte
			if i+1 >= len(desc) {
				break
			}
			i += 3 + int(desc[i+1])
			continue
		}
		size := int(b & 3)
		if size == 3 {
			size = 4
		}
		if i+1+size > len(desc) {
			break
		}
		if b&0xfc == 0x04 { // Usage Page
			var v uint32
			for k := size - 1; k >= 0; k-- {
				v = v<<8 | uint32(desc[i+1+k])
			}
			out = append(out, v)
		}
		i += 1 + size
	}
	return out
}

// FindHID lists the Ledger hidraw nodes under sysRoot (normally /sys/class/hidraw), in node order. devRoot is the
// directory of the device nodes (normally /dev).
func FindHID(sysRoot, devRoot string) []HIDNode {
	ents, err := os.ReadDir(sysRoot)
	if err != nil {
		return nil
	}
	var out []HIDNode
	for _, e := range ents {
		name := e.Name()
		if !strings.HasPrefix(name, "hidraw") {
			continue
		}
		dev := filepath.Join(sysRoot, name, "device")
		ue, err := os.ReadFile(filepath.Join(dev, "uevent"))
		if err != nil {
			continue
		}
		ven, pro, ok := parseHIDID(string(ue))
		if !ok || ven != VendorID {
			continue
		}
		n := HIDNode{Node: filepath.Join(devRoot, name), Product: pro, Model: ModelOf(pro)}
		if desc, err := os.ReadFile(filepath.Join(dev, "report_descriptor")); err == nil && len(desc) > 0 {
			n.App = slices.Contains(usagePages(desc), usagePageApp)
		} else if real, err := filepath.EvalSymlinks(dev); err == nil {
			// device links to the HID device, whose parent is the USB interface
			if ifn, err := os.ReadFile(filepath.Join(filepath.Dir(real), "bInterfaceNumber")); err == nil {
				n.App = strings.TrimSpace(string(ifn)) == "00"
			}
		}
		out = append(out, n)
	}
	slices.SortFunc(out, func(a, b HIDNode) int { return nodeNumber(a.Node) - nodeNumber(b.Node) })
	return out
}

func nodeNumber(p string) int {
	n, _ := strconv.Atoi(strings.TrimPrefix(filepath.Base(p), "hidraw"))
	return n
}

// PickHID chooses the node to open: the named one (which must be a Ledger node when sysfs knows it), else the one
// APDU interface found. None, or several with none named, is a failure naming what was found.
func PickHID(nodes []HIDNode, named string) (HIDNode, error) {
	if named != "" {
		for _, n := range nodes {
			if n.Node == named {
				if !n.App {
					return HIDNode{}, &Error{Slug: NoDevice, Detail: named + " is a Ledger interface the apps do not speak APDUs on; name the device's other hidraw node, or name none"}
				}
				return n, nil
			}
		}
		return HIDNode{}, &Error{Slug: NoDevice, Detail: named + " is not a Ledger device's hidraw node (vendor 2c97)"}
	}
	var apps []HIDNode
	for _, n := range nodes {
		if n.App {
			apps = append(apps, n)
		}
	}
	switch len(apps) {
	case 0:
		return HIDNode{}, &Error{Slug: NoDevice, Detail: "no Ledger device is attached by USB (or it is locked at the PIN screen and not yet enumerated)"}
	case 1:
		return apps[0], nil
	}
	var names []string
	for _, n := range apps {
		names = append(names, n.Node)
	}
	return HIDNode{}, &Error{Slug: MultipleDevice, Detail: "several Ledger devices are attached (" + strings.Join(names, ", ") + "); name one"}
}
