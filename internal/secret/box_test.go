package secret

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

func TestEncryptRoundTripAndAAD(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	plain := []byte("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	nonce, ct, err := Encrypt(key, plain, []byte("15"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, plain) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := Decrypt(key, nonce, ct, []byte("15"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatal("round trip mismatch")
	}
	if _, err := Decrypt(key, nonce, ct, []byte("16")); err == nil {
		t.Fatal("wrong aad should fail")
	}
}

func TestKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.key")
	key, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("len %d", len(key))
	}
	again, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, again) {
		t.Fatal("key changed")
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", info.Mode().Perm())
	}
	dinfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dinfo.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dinfo.Mode().Perm())
	}
}

func TestShortSecretKeyIsKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("shortkey"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("short key was accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("shortkey")) {
		t.Fatal("short key was replaced")
	}
}

func TestNewlineSecretKeyIsKept(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	key := bytes.Repeat([]byte{7}, 32)
	if err := os.WriteFile(path, append(append([]byte(nil), key...), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("newline key was accepted")
	}
	got, err := os.ReadFile(path)
	if err != nil || len(got) != 33 || !bytes.HasPrefix(got, key) {
		t.Fatalf("file changed len=%d err=%v", len(got), err)
	}
}

func TestExistingSecretKeyModeIsTightened(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	key := bytes.Repeat([]byte{3}, 32)
	if err := os.WriteFile(path, key, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("existing key was replaced")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode stayed %o", info.Mode().Perm())
	}
}

func TestSaveKeyRestoresDamagedFile(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	t.Run("short", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret.key")
		if err := os.WriteFile(path, []byte("shortkey"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := SaveKey(path, key); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, key) {
			t.Fatal("short file was not restored")
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode %o", info.Mode().Perm())
		}
	})
	t.Run("missing", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret.key")
		if err := SaveKey(path, key); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, key) {
			t.Fatal("missing file was not restored")
		}
	})
	t.Run("replaced", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret.key")
		if err := os.WriteFile(path, bytes.Repeat([]byte{1}, 32), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := SaveKey(path, key); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, key) {
			t.Fatal("different key was kept")
		}
	})
}

func TestConcurrentShortKeyRepairDoesNotSplit(t *testing.T) {
	const trials = 40
	const workers = 8
	for trial := 0; trial < trials; trial++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "secret.key")
		if err := os.WriteFile(path, []byte("shortkey"), 0o600); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		keys := make([][]byte, workers)
		errs := make([]error, workers)
		start := make(chan struct{})
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				keys[i], errs[i] = LoadOrCreateKey(path)
			}(i)
		}
		close(start)
		wg.Wait()
		file, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(file, []byte("shortkey")) {
			t.Fatalf("trial %d file changed len=%d err=%v", trial, len(file), err)
		}
		for i := 0; i < workers; i++ {
			if errs[i] == nil || keys[i] != nil {
				t.Fatalf("trial %d caller %d replaced short key", trial, i)
			}
		}
	}
}

func TestNewKeyDirSyncErrorIsReturned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	key := bytes.Repeat([]byte{3}, 32)
	old := syncDirFile
	syncDirFile = func(*os.File) error { return errors.New("dirsync") }
	t.Cleanup(func() { syncDirFile = old })
	err := writeNewFile(path, key, 0o600)
	if err == nil || err.Error() != "dirsync" {
		t.Fatalf("dir sync swallowed: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, key) {
		t.Fatalf("key file lost after dir sync failure: %v", readErr)
	}
	syncDirFile = old
	loaded, err := LoadOrCreateKey(path)
	if err != nil || !bytes.Equal(loaded, key) {
		t.Fatalf("restart did not keep written key: %v", err)
	}
}

func TestAtomicKeyDirSyncErrorIsReturned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	key := bytes.Repeat([]byte{4}, 32)
	old := syncDirFile
	syncDirFile = func(*os.File) error { return errors.New("dirsync") }
	t.Cleanup(func() { syncDirFile = old })
	err := writeAtomic(path, key, 0o600)
	if err == nil || err.Error() != "dirsync" {
		t.Fatalf("dir sync swallowed: %v", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || !bytes.Equal(got, key) {
		t.Fatalf("key file lost after dir sync failure: %v", readErr)
	}
}

func TestReplaceFileWhenRenameCannotOverwrite(t *testing.T) {
	old := renameFile
	renameFile = func(oldpath, newpath string) error {
		if _, err := os.Stat(newpath); err == nil {
			return os.ErrExist
		}
		return os.Rename(oldpath, newpath)
	}
	t.Cleanup(func() { renameFile = old })
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("shortkey"), 0o600); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	if err := SaveKey(path, key); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("not replaced: %v %q", err, got)
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("bak left behind")
	}
}

func TestAdoptBackupWhenKeyMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	key := bytes.Repeat([]byte{8}, 32)
	if err := os.WriteFile(path+".bak", key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AdoptPendingKey(path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("bak not adopted: %v", err)
	}
}

func TestCannotReplaceRecognizesWindowsErrno(t *testing.T) {
	err := &os.LinkError{Op: "rename", Old: "a", New: "b", Err: syscall.Errno(183)}
	if !cannotReplace(err) || !cannotReplace(os.ErrExist) || !cannotReplace(&os.LinkError{Err: syscall.Errno(80)}) {
		t.Fatal("windows replace error not recognized")
	}
	if cannotReplace(errors.New("permission")) {
		t.Fatal("unrelated error")
	}
}

func TestWindowsDirectorySyncUnsupportedIsNotFatal(t *testing.T) {
	denied := &os.PathError{Op: "sync", Path: "data", Err: syscall.Errno(5)}
	if normalizeDirSyncOS(denied, true) != nil {
		t.Fatal("windows directory sync access denied treated as fatal")
	}
	if normalizeDirSyncOS(&os.PathError{Op: "sync", Path: "data", Err: syscall.Errno(1)}, true) != nil {
		t.Fatal("windows directory sync invalid function treated as fatal")
	}
	if normalizeDirSyncOS(&os.PathError{Op: "sync", Path: "data", Err: syscall.Errno(87)}, true) != nil {
		t.Fatal("windows directory sync invalid parameter treated as fatal")
	}
	if normalizeDirSyncOS(denied, false) == nil {
		t.Fatal("non-windows access denied was ignored")
	}
	if normalizeDirSyncOS(&os.PathError{Op: "sync", Path: "data", Err: syscall.Errno(112)}, true) == nil {
		t.Fatal("windows disk full was ignored")
	}
	if normalizeDirSyncOS(nil, true) != nil {
		t.Fatal("nil sync error became an error")
	}
}
