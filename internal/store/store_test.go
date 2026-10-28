package store

import (
	"bytes"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"bep20-vanity-console/internal/secret"
)

func TestCiphertextIsNotPlaintext(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key := bytes.Repeat([]byte{9}, 32)
	priv := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	id, err := st.SaveResult(key, NewResult{
		Rule:     "8A",
		Length:   8,
		Checksum: "0x1111111111111111111111111111111111111111",
		Lower:    "1111111111111111111111111111111111111111",
		PrivHex:  priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := st.RawCiphertext(id)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(priv)) || bytes.Contains(raw, []byte("0x"+priv)) {
		t.Fatal("database stored plaintext")
	}
	got, err := st.Get(id)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := secret.Decrypt(key, got.Nonce, got.Ciphertext, []byte(strconv.FormatInt(id, 10)))
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != priv {
		t.Fatal("decrypt mismatch")
	}
	if err := st.SetCPU(95); err != nil {
		t.Fatal(err)
	}
	settings, err := st.Settings()
	if err != nil {
		t.Fatal(err)
	}
	if settings.CPU != 95 || settings.Running {
		t.Fatalf("%+v", settings)
	}
}

func TestLockPathIsNotReportedAsHeld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	if err := os.Mkdir(path+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path)
	if err == nil {
		t.Fatal("opened with a directory lock path")
	}
	if err.Error() == "lock" {
		t.Fatal("path error reported as another instance")
	}
	if err.Error() != "lock_path" {
		t.Fatalf("err=%v", err)
	}
}

func TestSecondOpenFailsWhileHeld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if _, err := Open(path); err == nil || err.Error() != "lock" {
		t.Fatalf("second open err=%v", err)
	}
}

func TestUnlinkLockFileDoesNotAllowSecondOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := os.Remove(path + ".lock"); err != nil && !os.IsNotExist(err) {
		if _, err2 := Open(path); err2 == nil || err2.Error() != "lock" {
			t.Fatalf("remove=%v second=%v", err, err2)
		}
		return
	}
	if _, err := Open(path); err == nil || err.Error() != "lock" {
		t.Fatalf("second open after unlink err=%v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	again.Close()
}

func TestDeleteOverwritesCiphertext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 32)
	priv := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	id, err := st.SaveResult(key, NewResult{
		Rule:     "8A",
		Length:   8,
		Checksum: "0x1111111111111111111111111111111111111111",
		Lower:    "1111111111111111111111111111111111111111",
		PrivHex:  priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	ct, err := st.RawCiphertext(id)
	if err != nil || len(ct) == 0 {
		t.Fatal(err)
	}
	if err := st.Delete(id); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(dir, func(name string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		if bytes.Contains(b, ct) || bytes.Contains(b, []byte(priv)) || bytes.Contains(b, []byte("0x"+priv)) {
			return errors.New(name)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDeleteScrubFailureStillRemovesRow(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	key := bytes.Repeat([]byte{9}, 32)
	priv := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	id, err := st.SaveResult(key, NewResult{
		Rule: "8A", Length: 8,
		Checksum: "0x1111111111111111111111111111111111111111",
		Lower:    "1111111111111111111111111111111111111111",
		PrivHex:  priv,
	})
	if err != nil {
		t.Fatal(err)
	}
	restore := SetScrubHook(func(*sql.DB, string) error { return errors.New("vacuum") })
	defer restore()
	err = st.Delete(id)
	if !errors.Is(err, ErrScrub) {
		t.Fatalf("err %v", err)
	}
	_, err = st.Get(id)
	if err == nil || err.Error() != "not_found" {
		t.Fatalf("row still present: %v", err)
	}
}

func TestDBFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("windows mode bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "vanity.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	for _, name := range []string{path, path + "-wal", path + "-shm", path + ".lock"} {
		fi, err := os.Stat(name)
		if err != nil {
			t.Fatal(name, err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", name, fi.Mode().Perm())
		}
	}
}
