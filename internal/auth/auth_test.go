package auth

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"bep20-vanity-console/internal/store"
)

func testParams() Params {
	return Params{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32}
}

func TestProductionParamsAreStrong(t *testing.T) {
	p := ProductionParams()
	if p.Time < 3 || p.Memory < 64*1024 || p.KeyLen < 32 {
		t.Fatalf("%+v", p)
	}
}

func TestLoginLockAfterFiveFailures(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now()
	m := New(st, testParams(), func() time.Time { return now })
	if err := m.CreateAdmin("owner", "0123456789abcdef", "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		_, err := m.Login("owner", "wrong-password-1")
		if err != ErrBadLogin {
			t.Fatalf("attempt %d: %v", i+1, err)
		}
	}
	if _, err := m.Login("owner", "wrong-password-1"); err != ErrLocked {
		t.Fatalf("fifth error = %v", err)
	}
	if _, err := m.Login("owner", "0123456789abcdef"); err != ErrLocked {
		t.Fatalf("correct password during lock = %v", err)
	}
	_, err = m.Login("nobody", "0123456789abcdef")
	if err != ErrLocked {
		t.Fatal(err)
	}
}

func TestParallelWrongLoginsDoNotOverlapHashes(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := New(st, testParams(), time.Now)
	if err := m.CreateAdmin("owner", "0123456789abcdef", "0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	old := deriveKey
	var calls atomic.Int32
	var inFlight atomic.Int32
	var maxFlight atomic.Int32
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	deriveKey = func(password, salt []byte, timeCost, memory uint32, threads uint8, keyLen uint32) []byte {
		calls.Add(1)
		n := inFlight.Add(1)
		for {
			cur := maxFlight.Load()
			if n <= cur || maxFlight.CompareAndSwap(cur, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		inFlight.Add(-1)
		return old(password, salt, timeCost, memory, threads, keyLen)
	}
	defer func() { deriveKey = old }()
	var wg sync.WaitGroup
	errs := make([]error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = m.Login("owner", "wrong-password-1")
		}(i)
	}
	<-entered
	select {
	case <-entered:
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if maxFlight.Load() != 1 {
		t.Fatalf("overlapping hashes %d", maxFlight.Load())
	}
	if calls.Load() != 5 {
		t.Fatalf("hash calls %d", calls.Load())
	}
	locked := 0
	for _, err := range errs {
		if err == ErrLocked {
			locked++
		} else if err != ErrBadLogin {
			t.Fatalf("unexpected %v", err)
		}
	}
	if locked < 1 {
		t.Fatal("lock was not applied")
	}
}

func TestShortPasswordRejected(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m := New(st, testParams(), time.Now)
	if err := m.CreateAdmin("owner", "short", "short"); err == nil {
		t.Fatal("short password accepted")
	}
}
