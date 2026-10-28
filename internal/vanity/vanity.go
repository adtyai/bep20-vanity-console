package vanity

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"math"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
)

type Match struct {
	Rule   string
	Length int
}

func Generate() (privHex, checksum, lower string, err error) {
	key, err := crypto.GenerateKey()
	if err != nil {
		return "", "", "", err
	}
	return formatKey(key)
}

func AddressFromPrivateKeyHex(privHex string) (checksum, lower string, err error) {
	raw := strings.TrimPrefix(strings.TrimSpace(privHex), "0x")
	raw = strings.TrimPrefix(raw, "0X")
	if len(raw) != 64 {
		return "", "", errors.New("private_key")
	}
	if _, err := hex.DecodeString(raw); err != nil {
		return "", "", errors.New("private_key")
	}
	key, err := crypto.HexToECDSA(raw)
	if err != nil {
		return "", "", errors.New("private_key")
	}
	_, checksum, lower, err = formatKey(key)
	return checksum, lower, err
}

func formatKey(key *ecdsa.PrivateKey) (privHex, checksum, lower string, err error) {
	b := crypto.FromECDSA(key)
	if len(b) != 32 {
		return "", "", "", errors.New("private_key")
	}
	privHex = hex.EncodeToString(b)
	addr := crypto.PubkeyToAddress(key.PublicKey)
	checksum = addr.Hex()
	lower = strings.TrimPrefix(strings.ToLower(checksum), "0x")
	if len(lower) != 40 {
		return "", "", "", errors.New("address")
	}
	return privHex, checksum, lower, nil
}

// Classify 只看结尾。优先级是 1-9、1-8、至少 9 位相同数字、恰好 8 位相同数字。
// 字母和倒序都不算。9 位以上仍记为 9A，并保留实际位数。
func Classify(addr string) (Match, bool) {
	addr = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(addr)), "0x")
	if len(addr) != 40 || !isHex(addr) {
		return Match{}, false
	}
	if strings.HasSuffix(addr, "123456789") {
		return Match{Rule: "1-9", Length: 9}, true
	}
	if strings.HasSuffix(addr, "12345678") {
		return Match{Rule: "1-8", Length: 8}, true
	}
	last := addr[39]
	if last < '0' || last > '9' {
		return Match{}, false
	}
	run := 0
	for i := 39; i >= 0; i-- {
		if addr[i] != last {
			break
		}
		run++
	}
	if run >= 9 {
		return Match{Rule: "9A", Length: run}, true
	}
	if run == 8 {
		return Match{Rule: "8A", Length: 8}, true
	}
	return Match{}, false
}

func EnabledMatch(addr string, enabled map[string]bool) (Match, bool) {
	got, ok := Classify(addr)
	if !ok || !enabled[got.Rule] {
		return Match{}, false
	}
	return got, true
}

func ExpectedAttempts(rule string) float64 {
	switch rule {
	case "8A":
		return math.Pow(16, 9) / 150
	case "9A":
		return math.Pow(16, 9) / 10
	case "1-8":
		return math.Pow(16, 8)
	case "1-9":
		return math.Pow(16, 9)
	default:
		return 0
	}
}

func SplitChecksum(checksum string, n int) (head, tail string, err error) {
	body := strings.TrimPrefix(checksum, "0x")
	body = strings.TrimPrefix(body, "0X")
	if len(body) != 40 || !isHex(body) || n < 1 || n > 40 {
		return "", "", errors.New("address")
	}
	return "0x" + body[:40-n], body[40-n:], nil
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}
