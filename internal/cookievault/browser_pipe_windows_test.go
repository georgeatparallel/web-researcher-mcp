//go:build windows

package cookievault

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The profile browser must not open a DevTools TCP port: any local process could
// read a signed-in profile's cookies through it (issue #775). Checks the browser
// process only; netstat -ano lists the owning pid of each socket.
func TestProfileBrowserOpensNoDebugPortWindows(t *testing.T) {
	pb := launchTestBrowser(t)
	time.Sleep(500 * time.Millisecond) // let helper processes settle
	out, err := exec.CommandContext(t.Context(), "netstat", "-ano", "-p", "TCP").Output()
	if err != nil {
		t.Fatalf("netstat: %v", err)
	}
	pid := strconv.Itoa(pb.pid)
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// Proto  Local  Foreign  State  PID
		if len(f) == 5 && f[3] == "LISTENING" && f[4] == pid {
			t.Fatalf("browser listens on a TCP port: %s", strings.TrimSpace(line))
		}
	}
}
