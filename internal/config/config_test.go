package config

import "testing"

func TestLoadRequiresSetupToken(t *testing.T) {
	cfg, err := Load(func(string) string { return "" })
	if err != nil || cfg.SetupToken != "" || SetupTokenOK("") || !SetupTokenOK("1234567890123456") {
		t.Fatalf("empty token should wait for admin check: %+v %v", cfg, err)
	}
	cfg, err = Load(func(k string) string {
		if k == "SETUP_TOKEN" {
			return "123456789012345"
		}
		return ""
	})
	if err != nil || cfg.SetupToken != "123456789012345" || SetupTokenOK(cfg.SetupToken) {
		t.Fatalf("short token should reach the admin check: %+v %v", cfg, err)
	}
	cfg, err = Load(func(k string) string {
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
	for _, n := range []int{0, 4, 96, 100, 200, 500, 501, -1} {
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
