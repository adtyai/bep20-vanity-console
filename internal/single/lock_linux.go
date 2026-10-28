//go:build unix

package single

import (
	"errors"
	"os"
	"syscall"
)

func holdDirectory(dir string) (*os.File, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = d.Close()
		return nil, errors.New("lock")
	}
	return d, nil
}

func releaseHeld(d *os.File) {
	if d == nil {
		return
	}
	_ = syscall.Flock(int(d.Fd()), syscall.LOCK_UN)
	_ = d.Close()
}

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}

func isHeld(error) bool {
	return false
}

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
