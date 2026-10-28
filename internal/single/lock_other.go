//go:build !unix && !windows

package single

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

func holdDirectory(string) (*os.File, error) {
	return nil, nil
}

func releaseHeld(*os.File) {}

func openLockFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}

func isHeld(error) bool {
	return false
}

func lockExclusive(f *os.File) error {
	held := f.Name() + ".held"
	h, err := os.OpenFile(held, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return errors.New("lock")
		}
		if !staleHeld(held) {
			return errors.New("lock")
		}
		if err := os.Remove(held); err != nil {
			return errors.New("lock")
		}
		h, err = os.OpenFile(held, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return errors.New("lock")
		}
	}
	if _, err := h.WriteString(strconv.Itoa(os.Getpid())); err != nil {
		_ = h.Close()
		_ = os.Remove(held)
		return errors.New("lock")
	}
	if err := h.Close(); err != nil {
		_ = os.Remove(held)
		return errors.New("lock")
	}
	return nil
}

func staleHeld(path string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 || pid == os.Getpid() {
		return false
	}
	return !processAlive(pid)
}

func processAlive(int) bool {
	return true
}

func unlock(f *os.File) error {
	err := os.Remove(f.Name() + ".held")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func Tighten() {}
