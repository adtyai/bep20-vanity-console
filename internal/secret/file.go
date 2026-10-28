package secret

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

var chmodPath = os.Chmod

func EnsureDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := chmodPath(path, 0o700); err != nil {
		// 绑定卷有时不允许改权限。目录能写入就继续，写不进去仍失败。
		if dirWritable(path) {
			return nil
		}
		return err
	}
	return nil
}

func dirWritable(path string) bool {
	f, err := os.CreateTemp(path, ".write-check-*")
	if err != nil {
		return false
	}
	name := f.Name()
	_ = f.Close()
	_ = os.Remove(name)
	return true
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
	if err := replaceFile(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func AdoptPendingKey(path string) error {
	release, err := lockKey(path)
	if err != nil {
		return err
	}
	defer release()
	return adoptPendingKey(path)
}

func adoptPendingKey(path string) error {
	current, err := os.ReadFile(path)
	if err == nil && len(current) == 32 {
		_ = wipeAndRemove(path + ".bak")
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, suffix := range []string{".tmp", ".bak"} {
		staged, err := os.ReadFile(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if len(staged) != 32 {
			continue
		}
		if err := installKey(path, staged); err != nil {
			return err
		}
		if err := os.Remove(path + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return nil
}

func installKey(path string, key []byte) error {
	staged := path + ".new"
	f, err := os.OpenFile(staged, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(key)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(staged)
		if werr != nil {
			return werr
		}
		if serr != nil {
			return serr
		}
		return cerr
	}
	if err := os.Chmod(staged, 0o600); err != nil {
		_ = os.Remove(staged)
		return err
	}
	if err := replaceFile(staged, path); err != nil {
		_ = os.Remove(staged)
		return err
	}
	return syncDir(filepath.Dir(path))
}

var renameFile = os.Rename

func ReplaceFile(staged, path string) error {
	return replaceFile(staged, path)
}

func replaceFile(staged, path string) error {
	err := renameFile(staged, path)
	if err == nil {
		return os.Chmod(path, 0o600)
	}
	if !cannotReplace(err) {
		return err
	}
	info, statErr := os.Stat(path)
	if statErr != nil || info.IsDir() {
		return err
	}
	bak := path + ".bak"
	_ = os.Remove(bak)
	if err := renameFile(path, bak); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := renameFile(staged, path); err != nil {
		_ = renameFile(bak, path)
		return err
	}
	_ = wipeAndRemove(bak)
	return os.Chmod(path, 0o600)
}

func cannotReplace(err error) bool {
	if errors.Is(err, os.ErrExist) {
		return true
	}
	var link *os.LinkError
	if errors.As(err, &link) {
		if errno, ok := link.Err.(syscall.Errno); ok && (errno == 80 || errno == 183) {
			return true
		}
	}
	return false
}

func wipeAndRemove(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	var werr error
	if info.Size() > 0 {
		_, werr = f.Write(make([]byte, info.Size()))
	}
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if serr != nil {
		return serr
	}
	if cerr != nil {
		return cerr
	}
	return os.Remove(path)
}

var syncDirFile = func(f *os.File) error { return f.Sync() }

func SyncDir(dir string) error {
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return normalizeDirSyncOS(syncDirFile(d), runtime.GOOS == "windows")
}

func normalizeDirSyncOS(err error, windows bool) error {
	if err == nil {
		return nil
	}
	if windows && windowsDirSyncUnsupported(err) {
		return nil
	}
	return err
}

func windowsDirSyncUnsupported(err error) bool {
	return errors.Is(err, syscall.Errno(5)) ||
		errors.Is(err, syscall.Errno(1)) ||
		errors.Is(err, syscall.Errno(87))
}

func LoadOrCreateKey(path string) ([]byte, error) {
	release, err := lockKey(path)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := adoptPendingKey(path); err != nil {
		return nil, err
	}
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
		return nil, errors.New("secret_key")
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
	return syncDir(filepath.Dir(path))
}
