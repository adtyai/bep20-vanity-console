package vanity

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func TestDeriveAddressMatchesEthereum(t *testing.T) {
	raw, err := hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatal(err)
	}
	var priv [32]byte
	copy(priv[:], raw)
	addr, ok := DeriveAddress(&priv)
	if !ok {
		t.Fatal("rejected key 1")
	}
	if hex.EncodeToString(addr[:]) != "7e5f4552091a69125d5dfcb7b8c2659029395bdf" {
		t.Fatalf("address = %x", addr)
	}
	for i := 0; i < 32; i++ {
		key, err := crypto.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		b := crypto.FromECDSA(key)
		if len(b) != 32 {
			t.Fatalf("key length %d", len(b))
		}
		copy(priv[:], b)
		got, ok := DeriveAddress(&priv)
		if !ok {
			t.Fatalf("rejected %x", priv)
		}
		want := crypto.PubkeyToAddress(key.PublicKey)
		if got != want {
			t.Fatalf("got %x want %x", got, want)
		}
	}
}

func TestDeriveAddressRejectsInvalidScalar(t *testing.T) {
	var zero [32]byte
	if _, ok := DeriveAddress(&zero); ok {
		t.Fatal("accepted zero")
	}
	var hi [32]byte
	for i := range hi {
		hi[i] = 0xff
	}
	if _, ok := DeriveAddress(&hi); ok {
		t.Fatal("accepted scalar above the curve order")
	}
}

func TestClassifyAddressMatchesStringRules(t *testing.T) {
	cases := []string{
		strings.Repeat("1", 31) + "888888888",
		strings.Repeat("0", 32) + "00000000",
		strings.Repeat("2", 31) + "888888888",
		strings.Repeat("3", 30) + "8888888888",
		strings.Repeat("a", 40),
		strings.Repeat("4", 31) + "987654321",
		strings.Repeat("5", 31) + "012345678",
		strings.Repeat("6", 31) + "123456789",
		strings.Repeat("7", 31) + "123456780",
		strings.Repeat("9", 40),
	}
	for _, addr := range cases {
		raw, err := hex.DecodeString(addr)
		if err != nil || len(raw) != 20 {
			t.Fatalf("fixture %s", addr)
		}
		var b [20]byte
		copy(b[:], raw)
		got, ok := ClassifyAddress(b)
		want, wantOK := Classify(addr)
		if ok != wantOK || got != want {
			t.Fatalf("addr %s bytes=%+v %v string=%+v %v", addr, got, ok, want, wantOK)
		}
	}
}

func TestKeccakMatchesEthereum(t *testing.T) {
	samples := [][]byte{
		nil,
		{},
		[]byte("abc"),
		bytesRepeat(64, 0x11),
	}
	for _, sample := range samples {
		var got [32]byte
		keccak256(sample, &got)
		want := crypto.Keccak256(sample)
		if hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
			t.Fatalf("keccak %q got %x want %x", sample, got, want)
		}
	}
}

func bytesRepeat(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestKeySourceMissDoesNotAllocate(t *testing.T) {
	src, err := NewKeySource()
	if err != nil {
		t.Fatal(err)
	}
	allocs := testing.AllocsPerRun(40, func() {
		var priv [32]byte
		addr, ok, err := src.Next(&priv)
		if err != nil || !ok {
			t.Fatal(err)
		}
		ClassifyAddress(addr)
	})
	if allocs != 0 {
		t.Fatalf("allocs per key = %.1f, want 0", allocs)
	}
}

func TestMissPathDoesNotAllocate(t *testing.T) {
	var priv [32]byte
	priv[31] = 1
	allocs := testing.AllocsPerRun(40, func() {
		addr, ok := DeriveAddress(&priv)
		if !ok {
			t.Fatal("derive")
		}
		ClassifyAddress(addr)
	})
	if allocs != 0 {
		t.Fatalf("allocs per miss = %.1f, want 0", allocs)
	}
}
