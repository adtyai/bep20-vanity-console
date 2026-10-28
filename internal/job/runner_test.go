package job

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"bep20-vanity-console/internal/store"
	"bep20-vanity-console/internal/vanity"
)

func TestMissesAreNotSavedAndMismatchIsNotLoggedWithKey(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	const key = "0000000000000000000000000000000000000000000000000000000000000001"
	sum, lower, err := vanity.AddressFromPrivateKeyHex(key)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var logs []string
	var calls int
	r := New(st, []byte("0123456789abcdef0123456789abcdef"), func() (string, string, string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if calls > 3 {
			return "", "", "", errStop
		}
		if calls == 2 {
			return key, "0x" + strings.Repeat("0", 40), strings.Repeat("0", 40), nil
		}
		return key, sum, lower, nil
	}, 1, func(event, rule string, id int64, count uint64, errorType string) {
		mu.Lock()
		logs = append(logs, event+" "+rule+" "+errorType)
		mu.Unlock()
	})
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if r.Snapshot().Attempts >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	r.Shutdown()
	if r.Snapshot().Attempts < 3 {
		t.Fatalf("attempts %d", r.Snapshot().Attempts)
	}
	for _, rule := range []string{"8A", "9A", "1-8", "1-9"} {
		rows, err := st.List(rule)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("%s saved %d misses", rule, len(rows))
		}
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(logs, "\n")
	if strings.Contains(joined, key) {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "address_mismatch") {
		t.Fatal(joined)
	}
}

var errStop = stopErr{}

type stopErr struct{}

func (stopErr) Error() string { return "stop" }

func TestResumeKeepsAttempts(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetAttempts(42); err != nil {
		t.Fatal(err)
	}
	if err := st.MarkRunning(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	snap := r.Snapshot()
	if !snap.Running || snap.Attempts != 42 {
		t.Fatalf("%+v", snap)
	}
	r.Shutdown()
	settings, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.Running {
		t.Fatal("shutdown cleared running")
	}
	if settings.Attempts != 42 {
		t.Fatalf("attempts %d", settings.Attempts)
	}
}

func bytesKey() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}

func TestWriterStoresCiphertextOnly(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	priv := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	r.events <- event{hit: &hit{
		rule:     "8A",
		length:   8,
		checksum: "0x1111111111111111111111111111111111111111",
		lower:    "1111111111111111111111111111111111111111",
		privHex:  priv,
	}}
	r.syncFlush()
	r.Shutdown()
	rows, err := st.List("8A")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows %d", len(rows))
	}
	raw, err := st.RawCiphertext(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(priv)) || bytes.Contains(raw, []byte("0x"+priv)) {
		t.Fatal("database stored plaintext")
	}
}

func TestDefaultGeneratorDoesNotMismatch(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var mu sync.Mutex
	var logs []string
	r := New(st, bytesKey(), nil, 1, func(event, rule string, id int64, count uint64, errorType string) {
		mu.Lock()
		logs = append(logs, errorType)
		mu.Unlock()
	})
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && r.Snapshot().Attempts < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	r.Shutdown()
	if r.Snapshot().Attempts < 1 {
		t.Fatal("generator produced no attempts")
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(strings.Join(logs, " "), "address_mismatch") {
		t.Fatal(logs)
	}
}

func TestSetCPUDoesNotApplyWhenStoreFails(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.SetCPU(80); err == nil {
		t.Fatal("expected store error")
	}
	if r.Snapshot().CPU != 50 {
		t.Fatalf("cpu changed to %d", r.Snapshot().CPU)
	}
	r.Shutdown()
}

func TestSetRulesDoesNotApplyWhenStoreFails(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	err = r.SetRules(map[string]bool{"8A": false, "9A": true, "1-8": true, "1-9": true})
	if err == nil {
		t.Fatal("expected store error")
	}
	if !r.Snapshot().Rules["8A"] {
		t.Fatal("rule changed after store failure")
	}
	r.Shutdown()
}

func TestStopStaysRunningWhenStoreFails(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	if err := r.Stop(); err == nil {
		t.Fatal("expected store error")
	}
	if !r.Snapshot().Running {
		t.Fatal("memory stopped while database update failed")
	}
	r.Shutdown()
}

func TestShutdownReturnsWhenWorkerStuck(t *testing.T) {
	old := shutdownLimit
	shutdownLimit = 50 * time.Millisecond
	defer func() { shutdownLimit = old }()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	r.busy[0].Store(1)
	done := make(chan struct{})
	go func() {
		r.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		r.busy[0].Store(0)
		t.Fatal("shutdown hung")
	}
	r.busy[0].Store(0)
	time.Sleep(200 * time.Millisecond)
}

func TestFailedSaveIsRetriedAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key := bytesKey()
	priv := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	var calls int
	var logs []string
	var mu sync.Mutex
	r := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, func(event, rule string, id int64, count uint64, errorType string) {
		mu.Lock()
		logs = append(logs, event+" "+rule+" "+errorType)
		mu.Unlock()
	})
	r.HookSave(func(got []byte, in store.NewResult) (int64, error) {
		calls++
		if calls < 3 {
			return 0, errors.New("busy")
		}
		return st.SaveResult(got, in)
	})
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	r.EnqueueHit("8A", 8, "0x1111111111111111111111111111111111111111", "1111111111111111111111111111111111111111", priv)
	if r.Snapshot().Unsaved != 1 {
		t.Fatalf("unsaved %d", r.Snapshot().Unsaved)
	}
	pending, err := os.ReadDir(filepath.Join(dir, "pending"))
	if err != nil || len(pending) == 0 {
		t.Fatalf("pending files %v %v", pending, err)
	}
	for _, ent := range pending {
		b, err := os.ReadFile(filepath.Join(dir, "pending", ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(priv)) {
			t.Fatal("pending file contains plaintext")
		}
	}
	r.syncFlush()
	if r.Snapshot().Unsaved != 0 {
		t.Fatalf("still unsaved %d", r.Snapshot().Unsaved)
	}
	rows, err := st.List("8A")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d err %v", len(rows), err)
	}
	left, _ := os.ReadDir(filepath.Join(dir, "pending"))
	if len(left) != 0 {
		t.Fatalf("pending left %d", len(left))
	}
	r.Shutdown()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	fail := New(st2, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	fail.HookSave(func([]byte, store.NewResult) (int64, error) {
		return 0, errors.New("busy")
	})
	if err := fail.Boot(); err != nil {
		t.Fatal(err)
	}
	fail.EnqueueHit("1-8", 8, "0x2222222222222222222222222222222222222222", "2222222222222222222222222222222222222222", priv)
	if fail.Snapshot().Unsaved != 1 {
		t.Fatalf("restart unsaved %d", fail.Snapshot().Unsaved)
	}
	fail.Shutdown()
	if err := st2.Close(); err != nil {
		t.Fatal(err)
	}

	st3, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st3.Close()
	restored := New(st3, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := restored.Boot(); err != nil {
		t.Fatal(err)
	}
	restored.syncFlush()
	restored.Shutdown()
	rows, err = st3.List("1-8")
	if err != nil || len(rows) != 1 {
		t.Fatalf("restored rows %d err %v", len(rows), err)
	}
	left, _ = os.ReadDir(filepath.Join(dir, "pending"))
	if len(left) != 0 {
		t.Fatalf("pending remained %d", len(left))
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(strings.Join(logs, "\n"), priv) {
		t.Fatal("log contains key")
	}
}

func TestBrokenPendingIsNotCountedAsRetry(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "0123456789abcdef0123456789abcdef"
	path := filepath.Join(pending, name)
	if err := os.WriteFile(path, []byte("not-a-valid-box"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown()
	if r.Snapshot().Unsaved != 0 {
		t.Fatalf("broken counted as retryable unsaved %d", r.Snapshot().Unsaved)
	}
	if r.Snapshot().Broken != 1 {
		t.Fatalf("broken %d", r.Snapshot().Broken)
	}
	r.syncFlush()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("broken file changed: %v", err)
	}
}

func TestZeroSpeedIsStuck(t *testing.T) {
	r := &Runner{}
	now := time.Now()
	r.samples = []sample{{at: now.Add(-16 * time.Second), n: 4}, {at: now, n: 4}}
	per, have, stuck := r.speed(now, true, 16*time.Second)
	if per != 0 || !have || !stuck {
		t.Fatalf("per=%v have=%v stuck=%v", per, have, stuck)
	}
}
