package single

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLockReleasedAfterHolderExits(t *testing.T) {
	if os.Getenv("BEP20_LOCK_CHILD") == "1" {
		lk, err := Acquire(os.Getenv("BEP20_LOCK_PATH"))
		if err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("BEP20_LOCK_READY"), []byte("1"), 0o600); err != nil {
			os.Exit(3)
		}
		time.Sleep(time.Hour)
		_ = lk.Release()
		return
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db.lock")
	ready := path + ".ready"
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockReleasedAfterHolderExits$")
	cmd.Env = append(os.Environ(), "BEP20_LOCK_CHILD=1", "BEP20_LOCK_PATH="+path, "BEP20_LOCK_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(ready); err != nil {
		t.Fatal("child never locked")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = cmd.Process.Wait()
	deadline = time.Now().Add(3 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		lk, err := Acquire(path)
		if err == nil {
			if err := lk.Release(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(path + ".held"); !os.IsNotExist(err) {
				t.Fatal("stale held file left after exit")
			}
			return
		}
		last = err
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(last)
}
