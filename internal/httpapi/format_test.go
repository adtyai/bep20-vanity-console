package httpapi

import (
	"strings"
	"testing"

	"bep20-vanity-console/internal/job"
)

func TestStuckDoesNotShowInfiniteETA(t *testing.T) {
	snap := job.Snapshot{
		Running:   true,
		Stuck:     true,
		HaveSpeed: true,
		PerSecond: 0,
		Rules:     map[string]bool{"8A": true, "9A": true, "1-8": true, "1-9": true},
	}
	for _, rule := range []string{"8A", "9A", "1-8", "1-9"} {
		got := etaText(rule, snap)
		if got != "卡住" || strings.Contains(got, "Inf") {
			t.Fatalf("%s eta = %s", rule, got)
		}
	}
	if speedText(snap) != "卡住" {
		t.Fatal(speedText(snap))
	}
}

func TestDisabledRuleETA(t *testing.T) {
	snap := job.Snapshot{Rules: map[string]bool{"8A": false}, Running: true, HaveSpeed: true, PerSecond: 100}
	if etaText("8A", snap) != "已关闭" {
		t.Fatal(etaText("8A", snap))
	}
}
