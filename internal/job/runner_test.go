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
	if !r.Snapshot().Rules["8A"] || !r.enabled()["8A"] {
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

func TestShutdownReturnsWhenCheckpointStuck(t *testing.T) {
	oldLimit := shutdownLimit
	shutdownLimit = 40 * time.Millisecond
	defer func() { shutdownLimit = oldLimit }()
	oldSave := saveOpenSegment
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	saveOpenSegment = func(st *store.Store, accumulated time.Duration, segment time.Time) error {
		once.Do(func() { close(started) })
		<-release
		return oldSave(st, accumulated, segment)
	}
	defer func() { saveOpenSegment = oldSave }()
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
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		r.Shutdown()
		close(done)
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("checkpoint did not start")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("shutdown hung on checkpoint")
	}
	close(release)
	time.Sleep(200 * time.Millisecond)
}

func TestStopDuringShutdownPersistsStopped(t *testing.T) {
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
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	r.exited.Store(true)
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	got, err := st.Settings()
	if err != nil || got.Running {
		t.Fatalf("running=%v err=%v", got.Running, err)
	}
	r.Shutdown()
}

func TestShutdownTimeoutSkipsClosedStore(t *testing.T) {
	old := shutdownLimit
	shutdownLimit = 40 * time.Millisecond
	defer func() { shutdownLimit = old }()
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key := bytesKey()
	priv := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	sum, lower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	r := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	r.HookSave(func([]byte, store.NewResult) (int64, error) {
		once.Do(func() { close(started) })
		<-release
		return 0, errors.New("closed")
	})
	go r.EnqueueHit("8A", 8, sum, lower, priv)
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("save did not start")
	}
	done := make(chan struct{})
	go func() {
		r.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("shutdown hung")
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	close(release)
	time.Sleep(200 * time.Millisecond)
	st2, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	restored := New(st2, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := restored.Boot(); err != nil {
		t.Fatal(err)
	}
	restored.syncFlush()
	rows, err := st2.List("8A")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d err %v", len(rows), err)
	}
	restored.Shutdown()
}

func TestAbandonedHitDoesNotTouchStore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key := bytesKey()
	priv := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	sum, lower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	var saves int
	r := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	r.HookSave(func([]byte, store.NewResult) (int64, error) {
		saves++
		return 0, errors.New("should not save")
	})
	r.abandoned.Store(true)
	r.handle(event{hit: &hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}})
	if saves != 0 {
		t.Fatal("saved after abandon")
	}
	pending, err := os.ReadDir(filepath.Join(dir, "pending"))
	if err != nil || len(pending) == 0 {
		t.Fatalf("pending %v %v", pending, err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	r.Shutdown()
}

func TestWipeFileOverwritesBeforeRemove(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.bin")
	payload := []byte("private-key-material")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	var saw []byte
	old := removeFile
	removeFile = func(name string) error {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		saw = append([]byte(nil), b...)
		return os.Remove(name)
	}
	defer func() { removeFile = old }()
	if err := wipeFile(path); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(saw, payload) || bytes.Contains(saw, []byte("private")) {
		t.Fatalf("not overwritten: %q", saw)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file kept: %v", err)
	}
}

func TestRemovePendingWipesBeforeUnlink(t *testing.T) {
	dir := t.TempDir()
	lower := "abcdef"
	base := filepath.Join(dir, "pending")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, pendingName(lower))
	if err := os.WriteFile(path, []byte("ciphertext-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	var saw []byte
	old := removeFile
	removeFile = func(name string) error {
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if !strings.HasSuffix(name, ".tmp") {
			saw = append([]byte(nil), b...)
		}
		return os.Remove(name)
	}
	defer func() { removeFile = old }()
	if err := removePending(dir, lower); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(saw, []byte("ciphertext")) {
		t.Fatalf("pending unlinked with ciphertext: %q", saw)
	}
}

func TestClearBrokenKeepsValidPending(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key := bytesKey()
	r := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	priv := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	sum, lower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := writePending(dir, key, hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(dir, "pending", "0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(broken, []byte("not-a-valid-box"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := r.ClearBroken()
	if err != nil || n != 1 {
		t.Fatalf("cleared %d %v", n, err)
	}
	if _, err := os.Stat(broken); !os.IsNotExist(err) {
		t.Fatalf("broken kept: %v", err)
	}
	hits, brokenN, err := loadPending(dir, key)
	if err != nil || brokenN != 0 || len(hits) != 1 {
		t.Fatalf("hits %d broken %d err %v", len(hits), brokenN, err)
	}
	if r.Snapshot().Broken != 0 {
		t.Fatal(r.Snapshot().Broken)
	}
	r.Shutdown()
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
	sum, lower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
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
	r.EnqueueHit("8A", 8, sum, lower, priv)
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
	priv2 := "0000000000000000000000000000000000000000000000000000000000000002"
	sum2, lower2, err := vanity.AddressFromPrivateKeyHex(priv2)
	if err != nil {
		t.Fatal(err)
	}
	fail.EnqueueHit("1-8", 8, sum2, lower2, priv2)
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

func TestBootDoesNotCountCrashGap(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	past := time.Now().UTC().Add(-2 * time.Hour)
	if err := st.MarkRunning(past); err != nil {
		t.Fatal(err)
	}
	if err := st.SetAttempts(99); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveOpenSegment(1500*time.Millisecond, past); err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown()
	snap := r.Snapshot()
	settings, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Running || snap.Attempts != 99 {
		t.Fatalf("resume %+v", snap)
	}
	if settings.Accumulated > 5*time.Second || snap.Runtime > 5*time.Second {
		t.Fatalf("downtime counted snap=%s acc=%s", snap.Runtime, settings.Accumulated)
	}
	if settings.SegmentStarted.IsZero() || time.Since(settings.SegmentStarted) > time.Minute {
		t.Fatalf("segment not restarted: %s", settings.SegmentStarted)
	}
}

func TestShutdownFoldsRuntimeWithoutCountingDowntime(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	st, err := store.Open(path)
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
	time.Sleep(40 * time.Millisecond)
	r.Shutdown()
	settings, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if !settings.Running || settings.Accumulated < 20*time.Millisecond || !settings.SegmentStarted.IsZero() {
		t.Fatalf("running=%v acc=%s segment=%v", settings.Running, settings.Accumulated, settings.SegmentStarted)
	}
	folded := settings.Accumulated
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	again := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := again.Boot(); err != nil {
		t.Fatal(err)
	}
	defer again.Shutdown()
	settings, err = st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.Accumulated+5*time.Millisecond < folded || settings.Accumulated > folded+20*time.Millisecond {
		t.Fatalf("folded=%s now=%s", folded, settings.Accumulated)
	}
}

func TestValidTmpPendingIsImported(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	priv := "0000000000000000000000000000000000000000000000000000000000000001"
	sum, lower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	h := hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}
	if err := writePending(dir, bytesKey(), h); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "pending", pendingName(lower))
	if err := os.Rename(final, final+".tmp"); err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	r.syncFlush()
	r.Shutdown()
	rows, err := st.List("8A")
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows %d err %v", len(rows), err)
	}
	if _, err := os.Stat(final + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp kept: %v", err)
	}
}

func TestPartialTmpIsBrokenNotSilent(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pending, "0123456789abcdef0123456789abcdef.tmp")
	if err := os.WriteFile(path, []byte("partial"), 0o600); err != nil {
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
	if r.Snapshot().Broken != 1 || r.Snapshot().Unsaved != 0 {
		t.Fatalf("broken=%d unsaved=%d", r.Snapshot().Broken, r.Snapshot().Unsaved)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestMismatchedPendingIsNotImported(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	priv := "0000000000000000000000000000000000000000000000000000000000000001"
	sum, lower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	bad := hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: "0000000000000000000000000000000000000000000000000000000000000002"}
	if err := writePending(dir, bytesKey(), bad); err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	r.syncFlush()
	r.Shutdown()
	rows, err := st.List("8A")
	if err != nil || len(rows) != 0 || r.Snapshot().Broken != 1 {
		t.Fatalf("rows %d broken %d err %v", len(rows), r.Snapshot().Broken, err)
	}
}

func TestDeleteRemovesPendingBeforeItCanReturn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key := bytesKey()
	priv := "0000000000000000000000000000000000000000000000000000000000000001"
	sum, lower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	id, err := st.SaveResult(key, store.NewResult{Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: priv})
	if err != nil {
		t.Fatal(err)
	}
	if err := writePending(dir, key, hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}); err != nil {
		t.Fatal(err)
	}
	r := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.DeleteResult(id); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	again := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := again.Boot(); err != nil {
		t.Fatal(err)
	}
	again.syncFlush()
	again.Shutdown()
	rows, err := st.List("8A")
	if err != nil || len(rows) != 0 {
		t.Fatalf("rows %d err %v", len(rows), err)
	}
}

func TestPendingRenameFailureRemovesTmp(t *testing.T) {
	dir := t.TempDir()
	priv := "0000000000000000000000000000000000000000000000000000000000000001"
	sum, lower, err := vanity.AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "pending", pendingName(lower))
	if err := os.MkdirAll(final, 0o700); err != nil {
		t.Fatal(err)
	}
	err = writePending(dir, bytesKey(), hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv})
	if err == nil {
		t.Fatal("expected rename error")
	}
	if _, statErr := os.Stat(final + ".tmp"); !os.IsNotExist(statErr) {
		t.Fatalf("tmp kept: %v", statErr)
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

func TestEnabledDoesNotWaitOnRunnerLock(t *testing.T) {
	r := New(nil, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	r.mu.Lock()
	defer r.mu.Unlock()
	got := enabledWithoutLock(t, r)
	if !got["8A"] || !got["9A"] || !got["1-8"] || !got["1-9"] {
		t.Fatalf("default rules %+v", got)
	}
}

func TestBootPublishesRulesWithoutLockingHotPath(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetRules(map[string]bool{"8A": false, "9A": true, "1-8": false, "1-9": true}); err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown()
	r.mu.Lock()
	defer r.mu.Unlock()
	got := enabledWithoutLock(t, r)
	if got["8A"] || !got["9A"] || got["1-8"] || !got["1-9"] {
		t.Fatalf("published %+v", got)
	}
}

func TestSetRulesPublishesWithoutLockingHotPath(t *testing.T) {
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
	defer r.Shutdown()
	if err := r.SetRules(map[string]bool{"8A": false, "9A": true, "1-8": false, "1-9": true}); err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	got := enabledWithoutLock(t, r)
	if got["8A"] || !got["9A"] || got["1-8"] || !got["1-9"] {
		t.Fatalf("published %+v", got)
	}
}

func TestApplyCoreLimitUsesNinetyFivePercentOfTheMachine(t *testing.T) {
	r := New(nil, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 40, nil)
	r.hostCPUs = 40
	r.usableCPUs = 40
	r.cpu.Store(95)
	var got int
	old := setMaxProcs
	setMaxProcs = func(n int) int {
		got = n
		return n
	}
	defer func() { setMaxProcs = old }()
	if n := r.applyCoreLimit(); n != 38 || got != 38 || int(r.coreLimit.Load()) != 38 {
		t.Fatalf("limit = %d procs = %d stored = %d, want 38", n, got, r.coreLimit.Load())
	}
}

func TestBootWritesBackCPUAbove95(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetCPU(500); err != nil {
		t.Fatal(err)
	}
	r := New(st, bytesKey(), func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown()
	if r.Snapshot().CPU != 95 {
		t.Fatalf("cpu = %d, want 95", r.Snapshot().CPU)
	}
	settings, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.CPU != 95 {
		t.Fatalf("stored cpu = %d, want 95", settings.CPU)
	}
}

func enabledWithoutLock(t *testing.T, r *Runner) map[string]bool {
	t.Helper()
	done := make(chan map[string]bool, 1)
	go func() {
		done <- r.enabled()
	}()
	select {
	case got := <-done:
		return got
	case <-time.After(200 * time.Millisecond):
		t.Fatal("enabled waited on r.mu")
	}
	return nil
}
