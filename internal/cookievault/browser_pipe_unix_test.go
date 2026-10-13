//go:build !windows

package cookievault

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The profile browser must not open a DevTools TCP port: any local process could
// read a signed-in profile's cookies through it (issue #775).
func TestProfileBrowserOpensNoDebugPort(t *testing.T) {
	bin := ResolveBrowser("")
	if bin == "" {
		t.Skip("no browser installed")
	}
	if _, err := exec.LookPath("lsof"); err != nil {
		t.Skip("lsof not available")
	}
	dir, err := os.MkdirTemp("", "pipe-port-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeDir(dir) })
	pb, err := LaunchBrowser(BrowserLaunch{Bin: bin, Dir: dir, Headless: true, NoSandbox: os.Geteuid() == 0})
	if err != nil {
		t.Fatal(err)
	}
	defer pb.Shutdown()
	if pb.exited == nil || pb.addr != "" {
		t.Fatal("browser was not started in pipe mode")
	}
	time.Sleep(500 * time.Millisecond) // let helper processes settle
	// -g includes the browser's helpers via the process group.
	out, _ := exec.CommandContext(t.Context(), "lsof", "-nP", "-a", "-g", strconv.Itoa(pb.pid), "-iTCP", "-sTCP:LISTEN").Output() // #nosec G204 -- pid is our own child
	if strings.TrimSpace(string(out)) != "" {
		t.Fatalf("browser listens on a TCP port:\n%s", out)
	}
}
