//go:build windows

package clipboard

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	clipboardUnicodeText = 13
	globalMoveable       = 0x0002
)

var (
	user32             = windows.NewLazySystemDLL("user32.dll")
	kernel32           = windows.NewLazySystemDLL("kernel32.dll")
	procOpenClipboard  = user32.NewProc("OpenClipboard")
	procCloseClipboard = user32.NewProc("CloseClipboard")
	procEmptyClipboard = user32.NewProc("EmptyClipboard")
	procSetClipboard   = user32.NewProc("SetClipboardData")
	procGlobalAlloc    = kernel32.NewProc("GlobalAlloc")
	procGlobalLock     = kernel32.NewProc("GlobalLock")
	procGlobalUnlock   = kernel32.NewProc("GlobalUnlock")
	procGlobalFree     = kernel32.NewProc("GlobalFree")
	procCreateWindow   = user32.NewProc("CreateWindowExW")
	procDestroyWindow  = user32.NewProc("DestroyWindow")
)

func writeText(ctx context.Context, text string) (returnErr error) {
	utf16Text, err := windows.UTF16FromString(text)
	if err != nil {
		return fmt.Errorf("encode clipboard text: %w", err)
	}

	// Clipboard ownership and the hidden owner window are thread-affine Win32
	// state. Keep the complete operation on one OS thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	owner, err := createClipboardOwner()
	if err != nil {
		return err
	}
	defer procDestroyWindow.Call(owner)

	if err := openClipboard(ctx, owner); err != nil {
		return err
	}
	defer func() {
		if ok, _, callErr := procCloseClipboard.Call(); ok == 0 && returnErr == nil {
			returnErr = windowsCallError("close clipboard", callErr)
		}
	}()

	if ok, _, callErr := procEmptyClipboard.Call(); ok == 0 {
		return windowsCallError("empty clipboard", callErr)
	}

	byteLen := uintptr(len(utf16Text) * 2)
	handle, _, callErr := procGlobalAlloc.Call(globalMoveable, byteLen)
	if handle == 0 {
		return windowsCallError("allocate clipboard memory", callErr)
	}
	owned := true
	defer func() {
		if owned {
			procGlobalFree.Call(handle)
		}
	}()

	ptr, _, callErr := procGlobalLock.Call(handle)
	if ptr == 0 {
		return windowsCallError("lock clipboard memory", callErr)
	}
	encoded := make([]byte, byteLen)
	for index, codeUnit := range utf16Text {
		binary.LittleEndian.PutUint16(encoded[index*2:], codeUnit)
	}
	var written uintptr
	if err := windows.WriteProcessMemory(windows.CurrentProcess(), ptr, &encoded[0], byteLen, &written); err != nil {
		return fmt.Errorf("copy clipboard text: %w", err)
	}
	if written != byteLen {
		return fmt.Errorf("copy clipboard text: wrote %d of %d bytes", written, byteLen)
	}
	if ok, _, unlockErr := procGlobalUnlock.Call(handle); ok == 0 {
		if errno, isErrno := unlockErr.(windows.Errno); !isErrno || errno != 0 {
			return windowsCallError("unlock clipboard memory", unlockErr)
		}
	}

	if result, _, callErr := procSetClipboard.Call(clipboardUnicodeText, handle); result == 0 {
		return windowsCallError("set clipboard text", callErr)
	}
	owned = false // the clipboard owns the memory after SetClipboardData
	return nil
}

func createClipboardOwner() (uintptr, error) {
	className, err := windows.UTF16PtrFromString("STATIC")
	if err != nil {
		return 0, fmt.Errorf("encode clipboard window class: %w", err)
	}
	const hwndMessage = ^uintptr(2) // HWND_MESSAGE == (HWND)-3
	handle, _, callErr := procCreateWindow.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		0,
		0,
		0, 0, 0, 0,
		hwndMessage,
		0, 0, 0,
	)
	runtime.KeepAlive(className)
	if handle == 0 {
		return 0, windowsCallError("create clipboard owner window", callErr)
	}
	return handle, nil
}

func openClipboard(ctx context.Context, owner uintptr) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for {
		if ok, _, _ := procOpenClipboard.Call(owner); ok != 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout.C:
			return fmt.Errorf("open clipboard: clipboard is busy")
		case <-ticker.C:
		}
	}
}

func windowsCallError(action string, err error) error {
	if errno, ok := err.(windows.Errno); ok && errno == 0 {
		return fmt.Errorf("%s failed", action)
	}
	return fmt.Errorf("%s: %w", action, err)
}
