//go:build !linux

package job

func setLowPriority() error { return nil }
