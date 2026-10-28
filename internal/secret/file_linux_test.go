//go:build linux

package secret

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestWriteFailureRemovesPartial(t *testing.T) {
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
	}()
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 0, Max: old.Max}); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.key")
	err := writeNewFile(path, bytes.Repeat([]byte{1}, 32), 0o600)
	if err == nil {
		t.Fatal("expected write error")
	}
	if errors.Is(err, os.ErrExist) {
		t.Fatalf("did not reach write: %v", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("partial file kept: %v", statErr)
	}
}
