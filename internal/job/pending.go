package job

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"bep20-vanity-console/internal/secret"
)

type pendingPayload struct {
	Rule     string `json:"rule"`
	Length   int    `json:"length"`
	Checksum string `json:"checksum"`
	Lower    string `json:"lower"`
	Priv     string `json:"priv"`
}

func pendingDir(dir string) string {
	return filepath.Join(dir, "pending")
}

func pendingName(lower string) string {
	sum := sha256.Sum256([]byte(lower))
	return hex.EncodeToString(sum[:16])
}

func writePending(dir string, key []byte, h hit) error {
	base := pendingDir(dir)
	if err := secret.EnsureDir(base); err != nil {
		return err
	}
	payload, err := json.Marshal(pendingPayload{
		Rule: h.rule, Length: h.length, Checksum: h.checksum, Lower: h.lower, Priv: h.privHex,
	})
	if err != nil {
		return err
	}
	nonce, ct, err := secret.Encrypt(key, payload, []byte("pending"))
	if err != nil {
		return err
	}
	name := pendingName(h.lower)
	final := filepath.Join(base, name)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(append(append([]byte{}, nonce...), ct...))
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	if serr != nil {
		return serr
	}
	if cerr != nil {
		return cerr
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

func removePending(dir, lower string) error {
	base := filepath.Join(pendingDir(dir), pendingName(lower))
	err1 := os.Remove(base)
	err2 := os.Remove(base + ".tmp")
	if err1 != nil && !errors.Is(err1, os.ErrNotExist) {
		return err1
	}
	if err2 != nil && !errors.Is(err2, os.ErrNotExist) {
		return err2
	}
	return nil
}

func loadPending(dir string, key []byte) ([]hit, int, error) {
	entries, err := os.ReadDir(pendingDir(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, nil
		}
		return nil, 0, err
	}
	var hits []hit
	broken := 0
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || strings.HasSuffix(name, ".tmp") || len(name) != 32 {
			continue
		}
		b, err := os.ReadFile(filepath.Join(pendingDir(dir), name))
		if err != nil || len(b) < 12 {
			broken++
			continue
		}
		plain, err := secret.Decrypt(key, b[:12], b[12:], []byte("pending"))
		if err != nil {
			broken++
			continue
		}
		var payload pendingPayload
		if err := json.Unmarshal(plain, &payload); err != nil || pendingName(payload.Lower) != name || payload.Priv == "" {
			broken++
			continue
		}
		hits = append(hits, hit{
			rule: payload.Rule, length: payload.Length, checksum: payload.Checksum, lower: payload.Lower, privHex: payload.Priv,
		})
	}
	return hits, broken, nil
}

func alreadyStored(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}
