package main

import (
	"bytes"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bep20-vanity-console/internal/secret"
	"bep20-vanity-console/internal/store"
	"bep20-vanity-console/internal/vanity"
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

func TestRequireSetupTokenAfterAdmin(t *testing.T) {
	if err := requireSetupToken(false, ""); err == nil || err.Error() != "setup_token" {
		t.Fatal(err)
	}
	if err := requireSetupToken(false, "short"); err == nil {
		t.Fatal("short token")
	}
	if err := requireSetupToken(true, ""); err != nil {
		t.Fatal(err)
	}
	if err := requireSetupToken(true, "short"); err != nil {
		t.Fatal(err)
	}
	if startupMessage(errors.New("setup_token")) != "缺少 SETUP_TOKEN" {
		t.Fatal(startupMessage(errors.New("setup_token")))
	}
	if startupMessage(errors.New("listen")) != "监听地址必须是本机回环" {
		t.Fatal(startupMessage(errors.New("listen")))
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

func TestMissingKeyDoesNotMintOverCiphertext(t *testing.T) {
	dir := t.TempDir()
	st, key, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum, lower, err := vanity.AddressFromPrivateKeyHex("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveResult(key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: "0000000000000000000000000000000000000000000000000000000000000001",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRuntime(dir); err == nil || err.Error() != "secret_key" {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing key was recreated over ciphertext")
	}
}

func TestMissingKeyDoesNotMintOverPending(t *testing.T) {
	dir := t.TempDir()
	st, _, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	pending := filepath.Join(dir, "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pending, "0123456789abcdef0123456789abcdef"), []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRuntime(dir); err == nil || err.Error() != "secret_key" {
		t.Fatalf("err=%v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("missing key was recreated over pending")
	}
}

func TestShortKeyDoesNotReplaceCiphertext(t *testing.T) {
	dir := t.TempDir()
	st, key, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum, lower, err := vanity.AddressFromPrivateKeyHex("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveResult(key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: "0000000000000000000000000000000000000000000000000000000000000001",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("shortkey"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := openRuntime(dir); err == nil || err.Error() != "secret_key" {
		t.Fatalf("err=%v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, []byte("shortkey")) {
		t.Fatal("short key was replaced")
	}
}

func TestMissingKeyAdoptsCompleteTmp(t *testing.T) {
	dir := t.TempDir()
	st, key, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum, lower, err := vanity.AddressFromPrivateKeyHex("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveResult(key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: "0000000000000000000000000000000000000000000000000000000000000001",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", key, 0o600); err != nil {
		t.Fatal(err)
	}
	st2, key2, err := openRuntime(dir)
	if err != nil {
		t.Fatalf("tmp key not adopted: %v", err)
	}
	defer st2.Close()
	if !bytes.Equal(key2, key) {
		t.Fatal("adopted a different key")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("key file was not restored from tmp")
	}
}

func TestShortKeyAdoptsCompleteTmp(t *testing.T) {
	dir := t.TempDir()
	st, key, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	sum, lower, err := vanity.AddressFromPrivateKeyHex("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SaveResult(key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: "0000000000000000000000000000000000000000000000000000000000000001",
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path, []byte("shortkey"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".tmp", key, 0o600); err != nil {
		t.Fatal(err)
	}
	st2, key2, err := openRuntime(dir)
	if err != nil {
		t.Fatalf("short key with tmp not adopted: %v", err)
	}
	defer st2.Close()
	if !bytes.Equal(key2, key) {
		t.Fatal("short key was not replaced by tmp")
	}
}

func TestValidKeyIgnoresDifferentTmp(t *testing.T) {
	dir := t.TempDir()
	st, key, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	other := bytes.Repeat([]byte{9}, 32)
	path := filepath.Join(dir, "secret.key")
	if err := os.WriteFile(path+".tmp", other, 0o600); err != nil {
		t.Fatal(err)
	}
	st2, key2, err := openRuntime(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	if !bytes.Equal(key2, key) {
		t.Fatal("valid key was replaced by tmp")
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatal("key file changed")
	}
}

func TestStartedLineIncludesBoundPort(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	line := startedLine(ln.Addr())
	if !strings.HasPrefix(line, "已启动 ") || !strings.Contains(line, ln.Addr().String()) {
		t.Fatalf("%q", line)
	}
}
