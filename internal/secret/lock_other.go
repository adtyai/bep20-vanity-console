//go:build !linux

package secret

import "sync"

var keyLocks sync.Map

func lockKey(path string) (func(), error) {
	mu, _ := keyLocks.LoadOrStore(path, &sync.Mutex{})
	mu.(*sync.Mutex).Lock()
	return func() { mu.(*sync.Mutex).Unlock() }, nil
}
