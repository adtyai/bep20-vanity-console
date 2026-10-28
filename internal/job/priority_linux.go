//go:build linux

package job

import "syscall"

func setLowPriority() error {
	return syscall.Setpriority(syscall.PRIO_PROCESS, 0, 10)
}
