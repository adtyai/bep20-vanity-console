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
	if utf8.RuneCountInString(token) < MinSecretLen {
		return Config{}, errors.New("setup_token")
	}
	listen = strings.TrimSpace(listen)
	if err := validateListen(listen); err != nil {
		return Config{}, err
	}
	return Config{Listen: listen, DataDir: dataDir, SetupToken: token}, nil
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

func ValidateCPU(n int) error {
	if n < 5 || n > 95 {
		return ErrCPU
	}
	return nil
}
