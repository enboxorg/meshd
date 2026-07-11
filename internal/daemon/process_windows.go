//go:build windows

package daemon

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func processAlivePlatform(pid int) (bool, error) {
	handle, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		switch {
		case errors.Is(err, windows.ERROR_INVALID_PARAMETER), errors.Is(err, windows.ERROR_NOT_FOUND):
			return false, nil
		case errors.Is(err, windows.ERROR_ACCESS_DENIED):
			return true, nil
		default:
			return false, err
		}
	}
	defer windows.CloseHandle(handle)

	result, err := windows.WaitForSingleObject(handle, 0)
	if err != nil {
		return false, err
	}
	switch result {
	case windows.WAIT_OBJECT_0:
		return false, nil
	case uint32(windows.WAIT_TIMEOUT):
		return true, nil
	default:
		return false, fmt.Errorf("unexpected process wait result %#x", result)
	}
}
