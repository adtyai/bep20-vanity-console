package config

import (
	"errors"
	"net"
	"strings"
	"unicode/utf8"
)

var ErrCPU = errors.New("cpu")

const (
	DefaultListen  = "127.0.0.1:3920"
	DefaultDataDir = "./data"
	MinSecretLen   = 16
)

type Config struct {
	Listen     string
	DataDir    string
	SetupToken string
}

func Load(getenv func(string) string) (Config, error) {
	listen := getenv("LISTEN")
	if listen == "" {
		listen = DefaultListen
	}
	dataDir := getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	token := getenv("SETUP_TOKEN")
	listen = strings.TrimSpace(listen)
	if err := validateListen(listen); err != nil {
		return Config{}, err
	}
	return Config{Listen: listen, DataDir: dataDir, SetupToken: token}, nil
}

func SetupTokenOK(token string) bool {
	return utf8.RuneCountInString(token) >= MinSecretLen
}

func validateListen(listen string) error {
	host, port, err := net.SplitHostPort(listen)
	if err != nil || port == "" {
		return errors.New("listen")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("listen")
	}
	return nil
}

const (
	MinCPU = 5
	MaxCPU = 95
)

func ValidateCPU(n int) error {
	if n < MinCPU || n > MaxCPU {
		return ErrCPU
	}
	return nil
}

// ClampStoredCPU 把已经落库的值收进当前范围。高于上限的改成上限，低于下限的不装入。
func ClampStoredCPU(n int) (int, bool) {
	if n > MaxCPU {
		n = MaxCPU
	}
	if ValidateCPU(n) != nil {
		return 0, false
	}
	return n, true
}
