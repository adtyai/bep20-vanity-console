package config

import "testing"

func TestLoadRequiresSetupToken(t *testing.T) {
	_, err := Load(func(string) string { return "" })
	if err == nil {
		t.Fatal("expected error")
	}
	_, err = Load(func(k string) string {
		if k == "SETUP_TOKEN" {
			return "123456789012345"
		}
		return ""
	})
	if err == nil {
		t.Fatal("15 chars should fail")
	}
	cfg, err := Load(func(k string) string {
		if k == "SETUP_TOKEN" {
			return "1234567890123456"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:3920" {
		t.Fatal(cfg.Listen)
	}
	if cfg.DataDir != "./data" {
		t.Fatal(cfg.DataDir)
	}
}

func TestLoadRejectsNonLoopback(t *testing.T) {
	token := func(listen string) func(string) string {
		return func(k string) string {
			switch k {
			case "SETUP_TOKEN":
				return "1234567890123456"
			case "LISTEN":
				return listen
			default:
				return ""
			}
		}
	}
	for _, listen := range []string{"0.0.0.0:3920", "[::]:3920", "192.168.1.8:3920", "127.0.0.1"} {
		if _, err := Load(token(listen)); err == nil || err.Error() != "listen" {
			t.Fatalf("%s err=%v", listen, err)
		}
	}
	for _, listen := range []string{"127.0.0.1:3920", "[::1]:3920", "localhost:3920"} {
		cfg, err := Load(token(listen))
		if err != nil || cfg.Listen != listen {
			t.Fatalf("%s cfg=%+v err=%v", listen, cfg, err)
		}
	}
}

func TestValidateCPU(t *testing.T) {
	for _, n := range []int{0, 4, 96, 100, -1} {
		if err := ValidateCPU(n); err == nil {
			t.Fatalf("%d should fail", n)
		}
	}
	for _, n := range []int{5, 50, 95} {
		if err := ValidateCPU(n); err != nil {
			t.Fatalf("%d should pass: %v", n, err)
		}
	}
}
