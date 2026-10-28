//go:build linux

package single

import (
	"errors"
	"os"
	"syscall"
)

func lockExclusive(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("lock")
	}
	return nil
}

func unlock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func Tighten() {
	syscall.Umask(0o077)
}
