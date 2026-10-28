package job

import (
	"path/filepath"
	"testing"

	"bep20-vanity-console/internal/store"
	"bep20-vanity-console/internal/vanity"
)

func TestDeleteDropsHitAlreadyQueued(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
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
	r := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown()
	early := hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}
	r.stamp(&early)
	if err := r.DeleteResult(id); err != nil {
		t.Fatal(err)
	}
	r.events <- event{hit: &early}
	r.syncFlush()
	rows, err := st.List("8A")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("stamped hit restored deleted row: %d", len(rows))
	}
	h := hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}
	r.events <- event{hit: &h}
	r.syncFlush()
	rows, err = st.List("8A")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("queued hit restored deleted row: %d", len(rows))
	}
	fresh := hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}
	r.stamp(&fresh)
	r.events <- event{hit: &fresh}
	r.syncFlush()
	rows, err = st.List("8A")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("new hit after delete was dropped: %d", len(rows))
	}
}

func TestAbandonedKeepPendingDoesNotRestoreDeleted(t *testing.T) {
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
	r := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	early := hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}
	r.stamp(&early)
	r.remember(early)
	r.pendingMu.Lock()
	snapshot := append([]hit(nil), r.pending...)
	r.pendingMu.Unlock()
	if err := r.DeleteResult(id); err != nil {
		t.Fatal(err)
	}
	for _, item := range snapshot {
		r.keepPending(item)
	}
	r.abandoned.Store(true)
	r.handle(event{hit: &early})
	r.abandonStore()
	r.Shutdown()
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("deleted row came back: %d", len(rows))
	}
	restored.Shutdown()
}

func TestKeepPendingAfterDeleteKeepsNewerStamp(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
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
	r := New(st, key, func() (string, string, string, error) {
		return "", "", "", errStop
	}, 1, nil)
	if err := r.Boot(); err != nil {
		t.Fatal(err)
	}
	defer r.Shutdown()
	old := hit{rule: "8A", length: 8, checksum: sum, lower: lower, privHex: priv}
	r.stamp(&old)
	if err := r.DeleteResult(id); err != nil {
		t.Fatal(err)
	}
	fresh := old
	r.stamp(&fresh)
	r.keepPending(fresh)
	hits, _, err := loadPending(dir, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 1 {
		t.Fatalf("newer hit was dropped: %d", len(hits))
	}
}

func TestShutdownStillOffersStop(t *testing.T) {
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
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	r.Shutdown()
	snap := r.Snapshot()
	if snap.Running || !snap.Exiting || !snap.Stoppable {
		t.Fatalf("exit snapshot %+v", snap)
	}
	settings, err := st.Settings()
	if err != nil || !settings.Running {
		t.Fatal(err, settings.Running)
	}
	if err := r.Stop(); err != nil {
		t.Fatal(err)
	}
	snap = r.Snapshot()
	if snap.Stoppable || snap.Running || !snap.Exiting {
		t.Fatalf("after stop %+v", snap)
	}
	settings, err = st.Settings()
	if err != nil || settings.Running {
		t.Fatal(err, settings.Running)
	}
}
