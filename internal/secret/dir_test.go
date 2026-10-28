package secret

import (
	"os"
	"runtime"
	"testing"
)

func TestEnsureDirKeepsWritableDirWhenChmodDenied(t *testing.T) {
	dir := t.TempDir()
	old := chmodPath
	chmodPath = func(string, os.FileMode) error {
		return os.ErrPermission
	}
	t.Cleanup(func() { chmodPath = old })
	if err := EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureDirStillFailsWhenChmodDeniedAndNotWritable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory mode")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	old := chmodPath
	chmodPath = func(string, os.FileMode) error {
		return os.ErrPermission
	}
	t.Cleanup(func() { chmodPath = old })
	if err := EnsureDir(dir); err == nil {
		t.Fatal("unwritable dir should still fail")
	}
}
