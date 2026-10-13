//go:build !windows

package cookievault

import (
	"os"
	"os/exec"
	"syscall"
)

// portFallback is false on unix: the DevTools pipe always works, and a failed
// start must never fall back to a TCP debug port.
const portFallback = false

// configureChild hands the browser its pipe ends as fd 3 (read) and fd 4 (write)
// and puts it in its own process group so killTree reaches its helpers.
func configureChild(cmd *exec.Cmd, r, w *os.File) {
	cmd.ExtraFiles = []*os.File{r, w}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// pipeFlags: Chrome reads fd 3 and writes fd 4 by default, so no extra flag.
func pipeFlags(r, w *os.File) []string { return nil }

// killTree kills the browser and its helpers (the whole process group).
func killTree(cmd *exec.Cmd) { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
