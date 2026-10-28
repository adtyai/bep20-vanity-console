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
	"bep20-vanity-console/internal/vanity"
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
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		if werr != nil {
			return werr
		}
		if serr != nil {
			return serr
		}
		return cerr
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := secret.ReplaceFile(tmp, final); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return secret.SyncDir(base)
}

var removeFile = os.Remove

func removePending(dir, lower string) error {
	base := filepath.Join(pendingDir(dir), pendingName(lower))
	if err := wipeFile(base); err != nil {
		return err
	}
	return wipeFile(base + ".tmp")
}

func wipeFile(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	var werr error
	if info.Size() > 0 {
		_, werr = f.WriteAt(make([]byte, info.Size()), 0)
	}
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
	return removeFile(path)
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
		if ent.IsDir() {
			continue
		}
		h, ok, bad := pendingState(filepath.Join(pendingDir(dir), name), name, key)
		if bad {
			broken++
			continue
		}
		if ok {
			hits = append(hits, h)
		}
	}
	return hits, broken, nil
}

func pendingState(path, name string, key []byte) (hit, bool, bool) {
	baseName := name
	tmp := strings.HasSuffix(name, ".tmp")
	if tmp {
		baseName = strings.TrimSuffix(name, ".tmp")
	}
	if len(baseName) != 32 {
		return hit{}, false, tmp
	}
	b, err := os.ReadFile(path)
	if err != nil || len(b) < 12 {
		return hit{}, false, true
	}
	plain, err := secret.Decrypt(key, b[:12], b[12:], []byte("pending"))
	if err != nil {
		return hit{}, false, true
	}
	var payload pendingPayload
	if err := json.Unmarshal(plain, &payload); err != nil || pendingName(payload.Lower) != baseName || payload.Priv == "" {
		return hit{}, false, true
	}
	sum, lower, err := vanity.AddressFromPrivateKeyHex(payload.Priv)
	if err != nil || sum != payload.Checksum || lower != payload.Lower {
		return hit{}, false, true
	}
	return hit{
		rule: payload.Rule, length: payload.Length, checksum: payload.Checksum, lower: payload.Lower, privHex: payload.Priv,
	}, true, false
}

func clearBroken(dir string, key []byte) (int, error) {
	entries, err := os.ReadDir(pendingDir(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	n := 0
	var first error
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		path := filepath.Join(pendingDir(dir), name)
		_, _, bad := pendingState(path, name, key)
		if !bad {
			continue
		}
		if err := wipeFile(path); err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		n++
	}
	return n, first
}

func alreadyStored(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}
