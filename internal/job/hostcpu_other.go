//go:build !linux

package job

import "runtime"

func startHostWorkers(logf Logger) (workers, host, usable, dutyCap int, quotaUnknown bool) {
	_ = logf
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	runtime.GOMAXPROCS(n)
	return n, n, n, 0, false
}
