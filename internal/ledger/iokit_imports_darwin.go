// The macOS USB transport's imports. Each function here has a trampoline in iokit_darwin_arm64.s and iokit_darwin_amd64.s
// (TestIOKitBindingsInStep checks the three files agree).

//go:build darwin

package ledger

import _ "unsafe" // for go:cgo_import_dynamic

// The CoreFoundation and IOKit functions the macOS USB transport calls, bound without cgo: each is imported from its
// framework by the linker and reached through a trampoline (iokit_darwin_<arch>.s), the way golang.org/x/sys binds
// libSystem. A release build stays CGO_ENABLED=0 and reproducible.

//go:cgo_import_dynamic iokit_CFStringCreateWithCString CFStringCreateWithCString "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic iokit_CFNumberGetValue CFNumberGetValue "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic iokit_CFSetGetCount CFSetGetCount "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic iokit_CFSetGetValues CFSetGetValues "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic iokit_CFArrayGetCount CFArrayGetCount "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic iokit_CFArrayGetValueAtIndex CFArrayGetValueAtIndex "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic iokit_CFRelease CFRelease "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic iokit_CFRetain CFRetain "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
//go:cgo_import_dynamic iokit_IOHIDManagerCreate IOHIDManagerCreate "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDManagerSetDeviceMatching IOHIDManagerSetDeviceMatching "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDManagerCopyDevices IOHIDManagerCopyDevices "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDDeviceGetProperty IOHIDDeviceGetProperty "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDDeviceOpen IOHIDDeviceOpen "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDDeviceClose IOHIDDeviceClose "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDDeviceSetReport IOHIDDeviceSetReport "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDDeviceCopyMatchingElements IOHIDDeviceCopyMatchingElements "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDDeviceGetValue IOHIDDeviceGetValue "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDDeviceGetService IOHIDDeviceGetService "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDElementGetType IOHIDElementGetType "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDElementGetReportSize IOHIDElementGetReportSize "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDElementGetReportCount IOHIDElementGetReportCount "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDQueueCreate IOHIDQueueCreate "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDQueueAddElement IOHIDQueueAddElement "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDQueueStart IOHIDQueueStart "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDQueueStop IOHIDQueueStop "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDQueueCopyNextValue IOHIDQueueCopyNextValue "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDValueGetBytePtr IOHIDValueGetBytePtr "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IOHIDValueGetLength IOHIDValueGetLength "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IORegistryEntryGetRegistryEntryID IORegistryEntryGetRegistryEntryID "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"
//go:cgo_import_dynamic iokit_IORegistryEntryInPlane IORegistryEntryInPlane "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit"

// The trampoline addresses, filled in by the assembly files.
var (
	fnCFStringCreateWithCString         uintptr
	fnCFNumberGetValue                  uintptr
	fnCFSetGetCount                     uintptr
	fnCFSetGetValues                    uintptr
	fnCFArrayGetCount                   uintptr
	fnCFArrayGetValueAtIndex            uintptr
	fnCFRelease                         uintptr
	fnCFRetain                          uintptr
	fnIOHIDManagerCreate                uintptr
	fnIOHIDManagerSetDeviceMatching     uintptr
	fnIOHIDManagerCopyDevices           uintptr
	fnIOHIDDeviceGetProperty            uintptr
	fnIOHIDDeviceOpen                   uintptr
	fnIOHIDDeviceClose                  uintptr
	fnIOHIDDeviceSetReport              uintptr
	fnIOHIDDeviceCopyMatchingElements   uintptr
	fnIOHIDDeviceGetValue               uintptr
	fnIOHIDDeviceGetService             uintptr
	fnIOHIDElementGetType               uintptr
	fnIOHIDElementGetReportSize         uintptr
	fnIOHIDElementGetReportCount        uintptr
	fnIOHIDQueueCreate                  uintptr
	fnIOHIDQueueAddElement              uintptr
	fnIOHIDQueueStart                   uintptr
	fnIOHIDQueueStop                    uintptr
	fnIOHIDQueueCopyNextValue           uintptr
	fnIOHIDValueGetBytePtr              uintptr
	fnIOHIDValueGetLength               uintptr
	fnIORegistryEntryGetRegistryEntryID uintptr
	fnIORegistryEntryInPlane            uintptr
)
