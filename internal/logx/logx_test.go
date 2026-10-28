package logx

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"
)

func TestEventDropsSecrets(t *testing.T) {
	secret := "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	Event("hit", "0x"+secret, 3, 1, secret)
	if strings.Contains(buf.String(), secret) {
		t.Fatal(buf.String())
	}
	if !strings.Contains(buf.String(), "event=hit") || !strings.Contains(buf.String(), "id=3") {
		t.Fatal(buf.String())
	}
}
