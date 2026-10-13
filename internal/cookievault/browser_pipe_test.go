package cookievault

import (
	"os"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
)

// launchTestBrowser starts a headless profile browser, or skips when none is installed.
func launchTestBrowser(t *testing.T) *ProfileBrowser {
	t.Helper()
	bin := ResolveBrowser("")
	if bin == "" {
		t.Skip("no browser installed")
	}
	dir, err := os.MkdirTemp("", "pipe-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { removeDir(dir) })
	pb, err := LaunchBrowser(BrowserLaunch{Bin: bin, Dir: dir, Headless: true, NoSandbox: os.Geteuid() == 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pb.Shutdown)
	return pb
}

// The browser is reached over the DevTools pipe on every platform.
func TestProfileBrowserUsesPipe(t *testing.T) {
	pb := launchTestBrowser(t)
	if pb.exited == nil || pb.addr != "" {
		t.Fatal("browser was not started in pipe mode")
	}
}

// The browser answers a real DevTools call through the pipe.
func TestPipeBrowserAnswersCDP(t *testing.T) {
	pb := launchTestBrowser(t)
	page, err := pb.Browser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := page.Eval(`() => 1 + 1`)
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Value.Int(); got != 2 {
		t.Fatalf("1+1 = %d, want 2", got)
	}
}

// The browser exits when its pipe closes, so a crashed server leaves no browser.
func TestProfileBrowserExitsWhenPipeCloses(t *testing.T) {
	pb := launchTestBrowser(t)
	pb.closePipes()
	select {
	case <-pb.exited:
	case <-time.After(15 * time.Second):
		t.Fatal("browser still running after its pipe closed")
	}
}
