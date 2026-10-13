package cookievault

import (
	"os"
	"testing"

	"github.com/go-rod/rod/lib/launcher/flags"
)

// TestBrowserProfileModeNoOverrides: login and scrape start the browser with no
// user-agent, timezone, stealth or incognito override (issue #775, rule 7).
func TestBrowserProfileModeNoOverrides(t *testing.T) {
	t.Parallel()
	for _, headless := range []bool{false, true} {
		l := BrowserLaunch{Bin: "/usr/bin/chrome", Dir: t.TempDir(), Headless: headless}.newLauncher()
		for _, flag := range []string{"user-agent", "incognito", "lang", "force-timezone", "enable-automation"} {
			if l.Has(flags.Flag(flag)) {
				t.Errorf("headless=%v: flag --%s must not be set", headless, flag)
			}
		}
		if l.Get(flags.UserDataDir) == "" {
			t.Errorf("headless=%v: no user-data-dir", headless)
		}
		if got := l.Has(flags.Headless); got != headless {
			t.Errorf("headless=%v: --headless set = %v", headless, got)
		}
	}
}

func TestBrowserNoSandboxOnlyWhenAsked(t *testing.T) {
	t.Parallel()
	if (BrowserLaunch{Dir: t.TempDir()}).newLauncher().Has(flags.NoSandbox) && os.Geteuid() != 0 {
		t.Error("no-sandbox set without NoSandbox")
	}
	if !(BrowserLaunch{Dir: t.TempDir(), NoSandbox: true}.newLauncher().Has(flags.NoSandbox)) {
		t.Error("no-sandbox missing when requested")
	}
}
