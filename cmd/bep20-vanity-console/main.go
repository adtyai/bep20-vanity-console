package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"bep20-vanity-console/internal/auth"
	"bep20-vanity-console/internal/config"
	"bep20-vanity-console/internal/httpapi"
	"bep20-vanity-console/internal/job"
	"bep20-vanity-console/internal/logx"
	"bep20-vanity-console/internal/secret"
	"bep20-vanity-console/internal/single"
	"bep20-vanity-console/internal/store"
)

func main() {
	os.Exit(run())
}

func startupKind(err error) string {
	if err == nil {
		return "store"
	}
	switch err.Error() {
	case "lock", "lock_path", "data_dir", "secret_key":
		return err.Error()
	default:
		return "store"
	}
}

func openRuntime(dataDir string) (*store.Store, []byte, error) {
	if err := secret.EnsureDir(dataDir); err != nil {
		return nil, nil, errors.New("data_dir")
	}
	st, err := store.Open(filepath.Join(dataDir, "vanity.db"))
	if err != nil {
		return nil, nil, err
	}
	key, err := secret.LoadOrCreateKey(filepath.Join(dataDir, "secret.key"))
	if err != nil {
		_ = st.Close()
		return nil, nil, errors.New("secret_key")
	}
	return st, key, nil
}

func run() int {
	single.Tighten()
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		logx.Event("error", "", 0, 0, "config")
		fmt.Fprintln(os.Stderr, "启动失败")
		return 1
	}
	st, key, err := openRuntime(cfg.DataDir)
	if err != nil {
		logx.Event("error", "", 0, 0, startupKind(err))
		fmt.Fprintln(os.Stderr, "启动失败")
		return 1
	}
	defer st.Close()
	defer func() {
		if err := secret.SaveKey(filepath.Join(cfg.DataDir, "secret.key"), key); err != nil {
			logx.Event("error", "", 0, 0, "secret_key")
		}
	}()
	logf := func(event, rule string, id int64, count uint64, errorType string) {
		logx.Event(event, rule, id, count, errorType)
	}
	job.SetLowPriority(logf)
	runner := job.New(st, key, nil, 0, logf)
	if err := runner.Boot(); err != nil {
		logx.Event("error", "", 0, 0, "store")
		fmt.Fprintln(os.Stderr, "启动失败")
		return 1
	}
	handler, err := httpapi.New(st, runner, auth.New(st, auth.ProductionParams(), time.Now), cfg.SetupToken, logf)
	if err != nil {
		runner.Shutdown()
		logx.Event("error", "", 0, 0, "template")
		fmt.Fprintln(os.Stderr, "启动失败")
		return 1
	}
	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logx.Event("error", "", 0, 0, "listen")
		fmt.Fprintln(os.Stderr, "启动失败")
		runner.Shutdown()
		return 1
	}
	fmt.Fprintln(os.Stderr, "已启动")
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
		runner.Shutdown()
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		return 0
	case err := <-errCh:
		runner.Shutdown()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logx.Event("error", "", 0, 0, "listen")
			fmt.Fprintln(os.Stderr, "启动失败")
			return 1
		}
		return 0
	}
}
