package httpapi

import (
	"strconv"

	"bep20-vanity-console/internal/secret"
	"bep20-vanity-console/internal/store"
)

func decrypt(key []byte, rec store.ResultSecret) ([]byte, error) {
	return secret.Decrypt(key, rec.Nonce, rec.Ciphertext, []byte(strconv.FormatInt(rec.ID, 10)))
}
