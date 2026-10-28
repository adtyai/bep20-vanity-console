//go:build !linux

package single

import (
	"errors"
	"os"
)

func lockExclusive(f *os.File) error {
	h, err := os.OpenFile(f.Name()+".held", os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("lock")
	}
	return h.Close()
}

func unlock(f *os.File) error {
	err := os.Remove(f.Name() + ".held")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func Tighten() {}
