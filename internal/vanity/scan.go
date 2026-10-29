package vanity

import (
	"crypto/rand"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/chacha20"
)

// DeriveAddress 用栈上的标量乘和 Keccak 算出地址。无效私钥返回 false。
// 没命中时调用方不能再分配；只有命中后才把十六进制字符串做出来。
func DeriveAddress(priv *[32]byte) (addr [20]byte, ok bool) {
	var scalar secp256k1.ModNScalar
	if scalar.SetByteSlice(priv[:]) || scalar.IsZero() {
		return addr, false
	}
	var point secp256k1.JacobianPoint
	secp256k1.ScalarBaseMultNonConst(&scalar, &point)
	point.ToAffine()
	var x, y [32]byte
	point.X.PutBytes(&x)
	point.Y.PutBytes(&y)
	var pub [64]byte
	copy(pub[:32], x[:])
	copy(pub[32:], y[:])
	var sum [32]byte
	keccak256(pub[:], &sum)
	copy(addr[:], sum[12:])
	return addr, true
}

// ClassifyAddress 和 Classify 同一套优先级，只是不把地址先变成字符串。
func ClassifyAddress(addr [20]byte) (Match, bool) {
	if straight19(addr) {
		return Match{Rule: "1-9", Length: 9}, true
	}
	if straight18(addr) {
		return Match{Rule: "1-8", Length: 8}, true
	}
	last := nibble(addr, 39)
	if last > 9 {
		return Match{}, false
	}
	run := 0
	for i := 39; i >= 0; i-- {
		if nibble(addr, i) != last {
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

func straight19(addr [20]byte) bool {
	want := [9]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	for i := 0; i < len(want); i++ {
		if nibble(addr, 31+i) != want[i] {
			return false
		}
	}
	return true
}

func straight18(addr [20]byte) bool {
	want := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	for i := 0; i < len(want); i++ {
		if nibble(addr, 32+i) != want[i] {
			return false
		}
	}
	return true
}

func nibble(addr [20]byte, i int) byte {
	b := addr[i/2]
	if i%2 == 0 {
		return b >> 4
	}
	return b & 0x0f
}

// KeySource 每个工作线程一把。热路径只在栈上填私钥，不进堆。
type KeySource struct {
	stream *chacha20.Cipher
	left   int
}

func NewKeySource() (*KeySource, error) {
	s := &KeySource{}
	if err := s.refill(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *KeySource) refill() error {
	var seed [44]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return err
	}
	stream, err := chacha20.NewUnauthenticatedCipher(seed[:32], seed[32:])
	if err != nil {
		return err
	}
	s.stream = stream
	s.left = 1 << 20
	return nil
}

// Next 写入 priv 并返回地址。私钥无效时 ok 为 false，不要把它算进尝试次数。
// err 只表示随机数读失败。
func (s *KeySource) Next(priv *[32]byte) (addr [20]byte, ok bool, err error) {
	if s.left == 0 {
		if err = s.refill(); err != nil {
			return addr, false, err
		}
	}
	s.left--
	clear(priv[:])
	s.stream.XORKeyStream(priv[:], priv[:])
	addr, ok = DeriveAddress(priv)
	return addr, ok, nil
}
