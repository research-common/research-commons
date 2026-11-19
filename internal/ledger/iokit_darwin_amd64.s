// Trampolines to the functions iokit_imports_darwin.go imports, one per function, in the same order.
//
// This is golang.org/x/sys/unix's pattern for calling libSystem without cgo (zsyscall_darwin_*.s): the linker
// resolves each go:cgo_import_dynamic symbol, a JMP trampoline gives it an address, and hid_darwin.go calls it
// through the runtime's syscall.syscall9. Checked against go1.27.2. The syscall9 route is reachable only while the
// toolchain keeps that linkname open (it does for x/sys); if a Go release closes it, the build fails here, not at run
// time, and CI's darwin cross-build (go.yml, static build) catches it.

//go:build darwin

#include "textflag.h"

TEXT iokit_CFStringCreateWithCString_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_CFStringCreateWithCString(SB)
GLOBL	·fnCFStringCreateWithCString(SB), RODATA, $8
DATA	·fnCFStringCreateWithCString(SB)/8, $iokit_CFStringCreateWithCString_trampoline<>(SB)

TEXT iokit_CFNumberGetValue_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_CFNumberGetValue(SB)
GLOBL	·fnCFNumberGetValue(SB), RODATA, $8
DATA	·fnCFNumberGetValue(SB)/8, $iokit_CFNumberGetValue_trampoline<>(SB)

TEXT iokit_CFSetGetCount_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_CFSetGetCount(SB)
GLOBL	·fnCFSetGetCount(SB), RODATA, $8
DATA	·fnCFSetGetCount(SB)/8, $iokit_CFSetGetCount_trampoline<>(SB)

TEXT iokit_CFSetGetValues_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_CFSetGetValues(SB)
GLOBL	·fnCFSetGetValues(SB), RODATA, $8
DATA	·fnCFSetGetValues(SB)/8, $iokit_CFSetGetValues_trampoline<>(SB)

TEXT iokit_CFArrayGetCount_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_CFArrayGetCount(SB)
GLOBL	·fnCFArrayGetCount(SB), RODATA, $8
DATA	·fnCFArrayGetCount(SB)/8, $iokit_CFArrayGetCount_trampoline<>(SB)

TEXT iokit_CFArrayGetValueAtIndex_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_CFArrayGetValueAtIndex(SB)
GLOBL	·fnCFArrayGetValueAtIndex(SB), RODATA, $8
DATA	·fnCFArrayGetValueAtIndex(SB)/8, $iokit_CFArrayGetValueAtIndex_trampoline<>(SB)

TEXT iokit_CFRelease_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_CFRelease(SB)
GLOBL	·fnCFRelease(SB), RODATA, $8
DATA	·fnCFRelease(SB)/8, $iokit_CFRelease_trampoline<>(SB)

TEXT iokit_CFRetain_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_CFRetain(SB)
GLOBL	·fnCFRetain(SB), RODATA, $8
DATA	·fnCFRetain(SB)/8, $iokit_CFRetain_trampoline<>(SB)

TEXT iokit_IOHIDManagerCreate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDManagerCreate(SB)
GLOBL	·fnIOHIDManagerCreate(SB), RODATA, $8
DATA	·fnIOHIDManagerCreate(SB)/8, $iokit_IOHIDManagerCreate_trampoline<>(SB)

TEXT iokit_IOHIDManagerSetDeviceMatching_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDManagerSetDeviceMatching(SB)
GLOBL	·fnIOHIDManagerSetDeviceMatching(SB), RODATA, $8
DATA	·fnIOHIDManagerSetDeviceMatching(SB)/8, $iokit_IOHIDManagerSetDeviceMatching_trampoline<>(SB)

TEXT iokit_IOHIDManagerCopyDevices_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDManagerCopyDevices(SB)
GLOBL	·fnIOHIDManagerCopyDevices(SB), RODATA, $8
DATA	·fnIOHIDManagerCopyDevices(SB)/8, $iokit_IOHIDManagerCopyDevices_trampoline<>(SB)

TEXT iokit_IOHIDDeviceGetProperty_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDDeviceGetProperty(SB)
GLOBL	·fnIOHIDDeviceGetProperty(SB), RODATA, $8
DATA	·fnIOHIDDeviceGetProperty(SB)/8, $iokit_IOHIDDeviceGetProperty_trampoline<>(SB)

TEXT iokit_IOHIDDeviceOpen_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDDeviceOpen(SB)
GLOBL	·fnIOHIDDeviceOpen(SB), RODATA, $8
DATA	·fnIOHIDDeviceOpen(SB)/8, $iokit_IOHIDDeviceOpen_trampoline<>(SB)

TEXT iokit_IOHIDDeviceClose_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDDeviceClose(SB)
GLOBL	·fnIOHIDDeviceClose(SB), RODATA, $8
DATA	·fnIOHIDDeviceClose(SB)/8, $iokit_IOHIDDeviceClose_trampoline<>(SB)

TEXT iokit_IOHIDDeviceSetReport_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDDeviceSetReport(SB)
GLOBL	·fnIOHIDDeviceSetReport(SB), RODATA, $8
DATA	·fnIOHIDDeviceSetReport(SB)/8, $iokit_IOHIDDeviceSetReport_trampoline<>(SB)

TEXT iokit_IOHIDDeviceCopyMatchingElements_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDDeviceCopyMatchingElements(SB)
GLOBL	·fnIOHIDDeviceCopyMatchingElements(SB), RODATA, $8
DATA	·fnIOHIDDeviceCopyMatchingElements(SB)/8, $iokit_IOHIDDeviceCopyMatchingElements_trampoline<>(SB)

TEXT iokit_IOHIDDeviceGetValue_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDDeviceGetValue(SB)
GLOBL	·fnIOHIDDeviceGetValue(SB), RODATA, $8
DATA	·fnIOHIDDeviceGetValue(SB)/8, $iokit_IOHIDDeviceGetValue_trampoline<>(SB)

TEXT iokit_IOHIDDeviceGetService_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDDeviceGetService(SB)
GLOBL	·fnIOHIDDeviceGetService(SB), RODATA, $8
DATA	·fnIOHIDDeviceGetService(SB)/8, $iokit_IOHIDDeviceGetService_trampoline<>(SB)

TEXT iokit_IOHIDElementGetType_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDElementGetType(SB)
GLOBL	·fnIOHIDElementGetType(SB), RODATA, $8
DATA	·fnIOHIDElementGetType(SB)/8, $iokit_IOHIDElementGetType_trampoline<>(SB)

TEXT iokit_IOHIDElementGetReportSize_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDElementGetReportSize(SB)
GLOBL	·fnIOHIDElementGetReportSize(SB), RODATA, $8
DATA	·fnIOHIDElementGetReportSize(SB)/8, $iokit_IOHIDElementGetReportSize_trampoline<>(SB)

TEXT iokit_IOHIDElementGetReportCount_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDElementGetReportCount(SB)
GLOBL	·fnIOHIDElementGetReportCount(SB), RODATA, $8
DATA	·fnIOHIDElementGetReportCount(SB)/8, $iokit_IOHIDElementGetReportCount_trampoline<>(SB)

TEXT iokit_IOHIDQueueCreate_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDQueueCreate(SB)
GLOBL	·fnIOHIDQueueCreate(SB), RODATA, $8
DATA	·fnIOHIDQueueCreate(SB)/8, $iokit_IOHIDQueueCreate_trampoline<>(SB)

TEXT iokit_IOHIDQueueAddElement_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDQueueAddElement(SB)
GLOBL	·fnIOHIDQueueAddElement(SB), RODATA, $8
DATA	·fnIOHIDQueueAddElement(SB)/8, $iokit_IOHIDQueueAddElement_trampoline<>(SB)

TEXT iokit_IOHIDQueueStart_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDQueueStart(SB)
GLOBL	·fnIOHIDQueueStart(SB), RODATA, $8
DATA	·fnIOHIDQueueStart(SB)/8, $iokit_IOHIDQueueStart_trampoline<>(SB)

TEXT iokit_IOHIDQueueStop_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDQueueStop(SB)
GLOBL	·fnIOHIDQueueStop(SB), RODATA, $8
DATA	·fnIOHIDQueueStop(SB)/8, $iokit_IOHIDQueueStop_trampoline<>(SB)

TEXT iokit_IOHIDQueueCopyNextValue_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDQueueCopyNextValue(SB)
GLOBL	·fnIOHIDQueueCopyNextValue(SB), RODATA, $8
DATA	·fnIOHIDQueueCopyNextValue(SB)/8, $iokit_IOHIDQueueCopyNextValue_trampoline<>(SB)

TEXT iokit_IOHIDValueGetBytePtr_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDValueGetBytePtr(SB)
GLOBL	·fnIOHIDValueGetBytePtr(SB), RODATA, $8
DATA	·fnIOHIDValueGetBytePtr(SB)/8, $iokit_IOHIDValueGetBytePtr_trampoline<>(SB)

TEXT iokit_IOHIDValueGetLength_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IOHIDValueGetLength(SB)
GLOBL	·fnIOHIDValueGetLength(SB), RODATA, $8
DATA	·fnIOHIDValueGetLength(SB)/8, $iokit_IOHIDValueGetLength_trampoline<>(SB)

TEXT iokit_IORegistryEntryGetRegistryEntryID_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IORegistryEntryGetRegistryEntryID(SB)
GLOBL	·fnIORegistryEntryGetRegistryEntryID(SB), RODATA, $8
DATA	·fnIORegistryEntryGetRegistryEntryID(SB)/8, $iokit_IORegistryEntryGetRegistryEntryID_trampoline<>(SB)

TEXT iokit_IORegistryEntryInPlane_trampoline<>(SB),NOSPLIT,$0-0
	JMP	iokit_IORegistryEntryInPlane(SB)
GLOBL	·fnIORegistryEntryInPlane(SB), RODATA, $8
DATA	·fnIORegistryEntryInPlane(SB)/8, $iokit_IORegistryEntryInPlane_trampoline<>(SB)

