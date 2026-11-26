// SPDX-License-Identifier: GPL-3.0-or-later

package webview

import (
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	clipboardUser32      = windows.NewLazySystemDLL("user32.dll")
	clipboardKernel32    = windows.NewLazySystemDLL("kernel32.dll")
	openClipboard        = clipboardUser32.NewProc("OpenClipboard")
	closeClipboard       = clipboardUser32.NewProc("CloseClipboard")
	emptyClipboard       = clipboardUser32.NewProc("EmptyClipboard")
	setClipboardData     = clipboardUser32.NewProc("SetClipboardData")
	registerClipboard    = clipboardUser32.NewProc("RegisterClipboardFormatW")
	createClipboardHWND  = clipboardUser32.NewProc("CreateWindowExW")
	destroyClipboardHWND = clipboardUser32.NewProc("DestroyWindow")
	clipboardAlloc       = clipboardKernel32.NewProc("GlobalAlloc")
	clipboardFree        = clipboardKernel32.NewProc("GlobalFree")
	clipboardLock        = clipboardKernel32.NewProc("GlobalLock")
	clipboardUnlock      = clipboardKernel32.NewProc("GlobalUnlock")
	clipboardMove        = clipboardKernel32.NewProc("RtlMoveMemory")
)

// CopySensitive supplies the platform's clipboard history and cloud sync opt-outs
// before publishing the text.
func CopySensitive(text string) error {
	encoded, err := windows.UTF16FromString(text)
	if err != nil {
		return errors.New("invalid clipboard text")
	}
	defer clear(encoded)
	formats := []string{"ExcludeClipboardContentFromMonitorProcessing", "CanIncludeInClipboardHistory", "CanUploadToCloudClipboard"}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	class, _ := windows.UTF16PtrFromString("STATIC")
	// A message-only window gives EmptyClipboard an owner for the formats.
	hwnd, _, err := createClipboardHWND.Call(0, uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, ^uintptr(2), 0, 0, 0)
	if hwnd == 0 {
		return err
	}
	defer destroyClipboardHWND.Call(hwnd)
	if ok, _, err := openClipboard.Call(hwnd); ok == 0 {
		return err
	}
	defer closeClipboard.Call()
	if ok, _, err := emptyClipboard.Call(); ok == 0 {
		return err
	}
	for _, name := range formats {
		wide, _ := windows.UTF16PtrFromString(name)
		format, _, err := registerClipboard.Call(uintptr(unsafe.Pointer(wide)))
		if format == 0 {
			return err
		}
		if err := putClipboardData(format, []byte{0, 0, 0, 0}); err != nil {
			return err
		}
	}
	const unicodeTextFormat = 13
	data := unsafe.Slice((*byte)(unsafe.Pointer(&encoded[0])), 2*len(encoded))
	return putClipboardData(unicodeTextFormat, data)
}

func putClipboardData(format uintptr, data []byte) error {
	const movable = 2
	handle, _, err := clipboardAlloc.Call(movable, uintptr(len(data)))
	if handle == 0 {
		return err
	}
	address, _, err := clipboardLock.Call(handle)
	if address == 0 {
		clipboardFree.Call(handle)
		return err
	}
	clipboardMove.Call(address, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)))
	runtime.KeepAlive(data)
	clipboardUnlock.Call(handle)
	if written, _, err := setClipboardData.Call(format, handle); written == 0 {
		clipboardFree.Call(handle)
		return err
	}
	return nil
}
