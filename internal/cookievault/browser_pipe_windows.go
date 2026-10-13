//go:build windows

package cookievault

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// portFallback is true on Windows: a Chrome too old for --remote-debugging-io-pipes
// cannot use the pipe, so launchOnce may fall back to a loopback debug port.
const portFallback = true

// configureChild lets the browser inherit the two pipe ends. os.Pipe handles are
// inheritable; the parent's other two ends are not in the list, so they are not
// passed on.
func configureChild(cmd *exec.Cmd, r, w *os.File) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(r.Fd()), syscall.Handle(w.Fd())},
	}
}

// pipeFlags names the inherited handles: first the one the browser reads, then the
// one it writes, as decimal numbers.
func pipeFlags(r, w *os.File) []string {
	return []string{"--remote-debugging-io-pipes=" + strconv.FormatUint(uint64(r.Fd()), 10) + "," + strconv.FormatUint(uint64(w.Fd()), 10)}
}

// killTree ends the browser process. Its helpers exit with it, because they hold
// the browser's own handles and lose their parent.
func killTree(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
