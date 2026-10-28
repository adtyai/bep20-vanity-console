package vanity

import (
	"math"
	"strings"
	"testing"
)

func TestKnownPrivateKeyAddress(t *testing.T) {
	const key = "0000000000000000000000000000000000000000000000000000000000000001"
	sum, lower, err := AddressFromPrivateKeyHex(key)
	if err != nil {
		t.Fatal(err)
	}
	if sum != "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf" {
		t.Fatalf("checksum = %s", sum)
	}
	if lower != "7e5f4552091a69125d5dfcb7b8c2659029395bdf" {
		t.Fatalf("lower = %s", lower)
	}
	sum2, _, err := AddressFromPrivateKeyHex("0x" + key)
	if err != nil {
		t.Fatal(err)
	}
	if sum2 != sum {
		t.Fatalf("prefix form = %s", sum2)
	}
}

func TestClassifyPriority(t *testing.T) {
	cases := []struct {
		name   string
		suffix string
		rule   string
		length int
		ok     bool
	}{
		{name: "exact 8A", suffix: "188888888", rule: "8A", length: 8, ok: true},
		{name: "zeros are digits", suffix: "00000000", rule: "8A", length: 8, ok: true},
		{name: "9 eights", suffix: "888888888", rule: "9A", length: 9, ok: true},
		{name: "10 eights", suffix: "8888888888", rule: "9A", length: 10, ok: true},
		{name: "letters", suffix: "aaaaaaaa", ok: false},
		{name: "reverse straight", suffix: "987654321", ok: false},
		{name: "embedded 1-8", suffix: "012345678", rule: "1-8", length: 8, ok: true},
		{name: "1-9 only", suffix: "123456789", rule: "1-9", length: 9, ok: true},
		{name: "not 1-8", suffix: "123456780", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr := strings.Repeat("1", 40-len(tc.suffix)) + tc.suffix
			if tc.name == "letters" {
				addr = strings.Repeat("a", 40)
			}
			got, ok := Classify(addr)
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v (%s)", ok, tc.ok, addr)
			}
			if !tc.ok {
				return
			}
			if got.Rule != tc.rule || got.Length != tc.length {
				t.Fatalf("got %+v", got)
			}
		})
	}
}

func TestDisabled9ADoesNotFallThrough(t *testing.T) {
	addr := strings.Repeat("1", 30) + strings.Repeat("8", 10)
	got, ok := Classify(addr)
	if !ok || got.Rule != "9A" || got.Length != 10 {
		t.Fatalf("classify = %+v ok=%v", got, ok)
	}
	enabled := map[string]bool{"8A": true, "9A": false, "1-8": true, "1-9": true}
	if _, ok := EnabledMatch(addr, enabled); ok {
		t.Fatal("10 eights were saved as another rule")
	}
}

func TestExpectedAttempts(t *testing.T) {
	if ExpectedAttempts("8A") != math.Pow(16, 9)/150 {
		t.Fatal(ExpectedAttempts("8A"))
	}
	if ExpectedAttempts("9A") != math.Pow(16, 9)/10 {
		t.Fatal(ExpectedAttempts("9A"))
	}
	if ExpectedAttempts("1-8") != math.Pow(16, 8) {
		t.Fatal(ExpectedAttempts("1-8"))
	}
	if ExpectedAttempts("1-9") != math.Pow(16, 9) {
		t.Fatal(ExpectedAttempts("1-9"))
	}
}

func TestGenerateShape(t *testing.T) {
	priv, sum, lower, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != 64 {
		t.Fatalf("priv len %d", len(priv))
	}
	again, againLower, err := AddressFromPrivateKeyHex(priv)
	if err != nil {
		t.Fatal(err)
	}
	if again != sum || againLower != lower {
		t.Fatalf("derived %s %s, generated %s %s", again, againLower, sum, lower)
	}
}
