//go:build darwin

package ledger

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// TestIOKitBindingsInStep: every function iokit_imports_darwin.go imports has an address variable and a trampoline
// in each architecture's assembly, in the same order, and nothing else is bound.
func TestIOKitBindingsInStep(t *testing.T) {
	read := func(name string) string {
		b, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	all := func(re, s string) []string {
		var out []string
		for _, m := range regexp.MustCompile(re).FindAllStringSubmatch(s, -1) {
			out = append(out, m[1])
		}
		return out
	}
	imports := read("iokit_imports_darwin.go")
	imported := all(`(?m)^//go:cgo_import_dynamic iokit_(\w+) (\w+) "/System/Library/Frameworks/`, imports)
	if len(imported) < 20 {
		t.Fatalf("only %d imports found", len(imported))
	}
	for _, m := range regexp.MustCompile(`(?m)^//go:cgo_import_dynamic iokit_(\w+) (\w+) `).FindAllStringSubmatch(imports, -1) {
		if m[1] != m[2] {
			t.Errorf("iokit_%s imports %s", m[1], m[2])
		}
	}
	if vars := all(`(?m)^\tfn(\w+) +uintptr$`, imports); !slices.Equal(vars, imported) {
		t.Errorf("address variables %v\nimports %v", vars, imported)
	}
	for _, arch := range []string{"arm64", "amd64"} {
		s := read("iokit_darwin_" + arch + ".s")
		if got := all(`(?m)^TEXT iokit_(\w+)_trampoline<>\(SB\),NOSPLIT,\$0-0$`, s); !slices.Equal(got, imported) {
			t.Errorf("%s trampolines %v", arch, got)
		}
		if got := all(`(?m)^\tJMP\tiokit_(\w+)\(SB\)$`, s); !slices.Equal(got, imported) {
			t.Errorf("%s jumps %v", arch, got)
		}
		if got := all(`(?m)^DATA\t·fn(\w+)\(SB\)/8, \$iokit_\w+_trampoline<>\(SB\)$`, s); !slices.Equal(got, imported) {
			t.Errorf("%s address data %v", arch, got)
		}
	}
}

// TestNextChannel: each exchange gets a channel past the last one sent, never 0 and never the channel of the last
// report seen (whose answer the queue would drop).
func TestNextChannel(t *testing.T) {
	p := &iokitPort{lastSeen: 0x0101, lastSent: 0x0101}
	if c := p.NextChannel(); c != 0x0102 {
		t.Fatalf("first channel %04x", c)
	}
	p.lastSeen = 0x0103 // a late answer arrived on the next channel
	if c := p.NextChannel(); c != 0x0104 {
		t.Fatalf("skipping the last seen: %04x", c)
	}
	p.lastSent, p.lastSeen = 0xfffe, 0xffff
	if c := p.NextChannel(); c != 0x0001 {
		t.Fatalf("wrap: %04x", c)
	}
	seen := map[uint16]bool{}
	p.lastSent, p.lastSeen = 0, 0
	for i := 0; i < 1<<16; i++ {
		c := p.NextChannel()
		if c == 0 || c == p.lastSeen {
			t.Fatalf("channel %04x", c)
		}
		p.lastSeen = c // the device answered on it
		seen[c] = true
	}
	if len(seen) != 1<<16-1 {
		t.Fatalf("%d distinct channels", len(seen))
	}
}

// TestOpenDarwin: on macOS the USB transport is built; a named device is refused (macOS has no node to name), and
// with no device named Open finds the one Ledger or says none is attached, never that USB is not built.
func TestOpenDarwin(t *testing.T) {
	if !HIDBuilt {
		t.Fatal("HIDBuilt is false on darwin")
	}
	if _, err := openHID("/dev/hidraw0"); !IsSlug(err, BadDeviceSpec) {
		t.Fatalf("named device: %v", err)
	}
	d, err := Open("")
	if err == nil {
		defer d.Close()
		if d.Emulator || d.Where == "" {
			t.Fatalf("%+v", d)
		}
		t.Logf("a Ledger is attached: %s %s", d.Model, d.Where)
		return
	}
	if IsSlug(err, NotBuilt) {
		t.Fatalf("Open: %v", err)
	}
	if !IsSlug(err, NoDevice) && !IsSlug(err, MultipleDevice) {
		t.Fatalf("Open with nothing attached: %v", err)
	}
}
