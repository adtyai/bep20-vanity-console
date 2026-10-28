package secret

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
)

func EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	return os.Chmod(path, 0o700)
}

func SaveKey(path string, key []byte) error {
	if len(key) != 32 {
		return errors.New("secret_key")
	}
	release, err := lockKey(path)
	if err != nil {
		return err
	}
	defer release()
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, key) {
		return os.Chmod(path, 0o600)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeAtomic(path, key, 0o600)
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return werr
		}
		if serr != nil {
			return serr
		}
		return cerr
	}
	if err := os.Chmod(tmp, mode); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	_ = dir.Sync()
	return nil
}

func LoadOrCreateKey(path string) ([]byte, error) {
	release, err := lockKey(path)
	if err != nil {
		return nil, err
	}
	defer release()
	return loadOrCreateKey(path)
}

func loadOrCreateKey(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	switch {
	case err == nil && len(b) == 32:
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, err
		}
		return b, nil
	case err == nil:
		if err := os.Remove(path); err != nil {
			return nil, errors.New("secret_key")
		}
	case errors.Is(err, os.ErrNotExist):
	default:
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := writeNewFile(path, key, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(path)
		if werr != nil {
			return werr
		}
		if serr != nil {
			return serr
		}
		return cerr
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	_ = dir.Sync()
	return nil
}
