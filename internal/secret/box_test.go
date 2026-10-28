package secret

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sync"
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

func TestShortSecretKeyIsReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("shortkey"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := LoadOrCreateKey(path)
	if err != nil {
		t.Fatalf("short key blocked restart: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("len %d", len(key))
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("file does not match new key")
	}
	again, err := LoadOrCreateKey(path)
	if err != nil || !bytes.Equal(again, key) {
		t.Fatalf("reload err=%v changed=%v", err, !bytes.Equal(again, key))
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
		if err != nil || len(file) != 32 {
			t.Fatalf("trial %d file len=%d err=%v", trial, len(file), err)
		}
		var first []byte
		for i := 0; i < workers; i++ {
			if errs[i] != nil {
				t.Fatalf("trial %d caller %d: %v", trial, i, errs[i])
			}
			if len(keys[i]) != 32 || !bytes.Equal(keys[i], file) {
				t.Fatalf("trial %d caller %d key diverged from file", trial, i)
			}
			if first == nil {
				first = keys[i]
			} else if !bytes.Equal(keys[i], first) {
				t.Fatalf("trial %d callers returned different keys", trial)
			}
		}
	}
}
