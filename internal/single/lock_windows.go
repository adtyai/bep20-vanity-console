//go:build windows

package single

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func holdDirectory(string) (*os.File, error) {
	return nil, nil
}

func releaseHeld(*os.File) {}

func openLockFile(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(
		p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}

func isHeld(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

func lockExclusive(*os.File) error {
	return nil
}

func unlock(*os.File) error {
	return nil
}

func Tighten() {}
