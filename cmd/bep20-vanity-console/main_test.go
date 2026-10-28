package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"bep20-vanity-console/internal/secret"
)

func TestStartupKindSeparatesHeldLockFromPath(t *testing.T) {
	if startupKind(errors.New("lock")) != "lock" {
		t.Fatal("held lock")
	}
	if startupKind(errors.New("lock_path")) != "lock_path" {
		t.Fatal("path")
	}
	if startupKind(errors.New("sql")) != "store" {
		t.Fatal("other")
	}
	if startupKind(errors.New("data_dir")) != "data_dir" {
		t.Fatal("data dir")
	}
	if startupKind(errors.New("secret_key")) != "secret_key" {
		t.Fatal("secret key")
	}
}

func TestLockedStartDoesNotReplaceDamagedKey(t *testing.T) {
	dir := t.TempDir()
	st, key, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("shortkey"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRuntime(dir); err == nil || err.Error() != "lock" {
		t.Fatalf("short err=%v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("shortkey")) {
		t.Fatal("short key was replaced while lock held")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRuntime(dir); err == nil || err.Error() != "lock" {
		t.Fatalf("missing err=%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing key was recreated while lock held")
	}
	if err := secret.SaveKey(path, key); err != nil {
		t.Fatal(err)
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("in-memory key was not written back")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st2, key2, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if !bytes.Equal(key2, key) {
		t.Fatal("restart loaded a different key")
	}
}
