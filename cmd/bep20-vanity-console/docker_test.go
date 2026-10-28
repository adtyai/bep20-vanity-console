package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImageFixesDataDirOwnership(t *testing.T) {
	root := moduleRoot(t)
	docker, err := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	script, err := os.ReadFile(filepath.Join(root, "docker-entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(docker)
	if strings.Contains(text, "\nUSER vanity\n") || strings.HasSuffix(text, "\nUSER vanity\n") || strings.Contains(text, "\nUSER vanity\r\n") {
		t.Fatal("image still starts as vanity, so a root-owned bind mount cannot be repaired")
	}
	if !strings.Contains(text, "docker-entrypoint.sh") {
		t.Fatal("image does not use the entrypoint")
	}
	entry := string(script)
	for _, needle := range []string{"chown -R vanity:vanity", "exec setpriv --reuid=vanity --regid=vanity --init-groups --inh-caps=-all", "DATA_DIR", "realpath -m", "/data|/data/*"} {
		if !strings.Contains(entry, needle) {
			t.Fatalf("entrypoint missing %s", needle)
		}
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "docker stop -t 30") {
		t.Fatal("stop docs still use the 10s default")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
