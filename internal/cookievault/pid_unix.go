//go:build !windows

package cookievault

import (
	"errors"
	"syscall"
)

// pidAlive reports whether a process with this id exists.
func pidAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
