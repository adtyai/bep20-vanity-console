package single

import (
	"errors"
	"os"
	"path/filepath"
)

type Lock struct {
	f   *os.File
	dir *os.File
}

func Acquire(path string) (*Lock, error) {
	dir, err := holdDirectory(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	f, err := openLockFile(path)
	if err != nil {
		releaseHeld(dir)
		if isHeld(err) {
			return nil, errors.New("lock")
		}
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = f.Close()
		releaseHeld(dir)
		return nil, err
	}
	if err := lockExclusive(f); err != nil {
		_ = f.Close()
		releaseHeld(dir)
		return nil, errors.New("lock")
	}
	return &Lock{f: f, dir: dir}, nil
}

func (l *Lock) Release() error {
	if l == nil {
		return nil
	}
	var err error
	if l.f != nil {
		err = unlock(l.f)
		if cerr := l.f.Close(); err == nil {
			err = cerr
		}
		l.f = nil
	}
	if l.dir != nil {
		releaseHeld(l.dir)
		l.dir = nil
	}
	return err
}
