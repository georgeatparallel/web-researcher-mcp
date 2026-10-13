package cookievault

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
)

// ErrBrowserLaunch is returned when the browser cannot be started or reached.
var ErrBrowserLaunch = errors.New("cookievault: could not start the browser")

const browserExitWait = 10 * time.Second

// lookPath finds an installed browser; a variable so tests can stub it.
var lookPath = launcher.LookPath

// ResolveBrowser returns the explicit chromePath, else the browser installed on
// the machine (Chrome first), else "" (go-rod then downloads Chromium). Login
// and profile scrape both use it, so a profile is always opened by the binary
// that created it (see issue #775).
func ResolveBrowser(chromePath string) string {
	if chromePath != "" {
		return chromePath
	}
	if bin, ok := lookPath(); ok {
		return bin
	}
	return ""
}

// BrowserLaunch describes one browser started on a tool-owned profile dir.
type BrowserLaunch struct {
	Bin      string // browser binary; "" lets go-rod pick one
	Dir      string // profile (user data) dir; never deleted here
	Headless bool
	// NoSandbox is set only where the OS requires it (root in a container, CI).
	NoSandbox bool
}

// newLauncher builds the flags. Login and scrape share them so the profile sees
// the same browser both times. There is deliberately no user-agent, timezone,
// stealth or incognito override: LinkedIn kept a profile signed in for 13 h
// without any (issue #775, rule 7). Add one only with a failing live test.
func (o BrowserLaunch) newLauncher() *launcher.Launcher {
	l := launcher.New().
		UserDataDir(o.Dir).
		Set("no-first-run").
		Delete("enable-automation").
		Set("disable-blink-features", "AutomationControlled")
	if o.Bin != "" {
		l = l.Bin(o.Bin)
	}
	if o.Headless {
		l = l.HeadlessNew(true).Set("disable-gpu")
	} else {
		l = l.Headless(false)
	}
	if o.NoSandbox || os.Geteuid() == 0 {
		l = l.Set("no-sandbox").Set("disable-dev-shm-usage")
	}
	return l
}

// ProfileBrowser is a running browser on a profile dir.
type ProfileBrowser struct {
	// Browser is the connected go-rod handle.
	Browser *rod.Browser
	l       *launcher.Launcher
	addr    string
	once    sync.Once
}

// LaunchBrowser starts a browser per o and connects to it. A failed start is
// retried once, after clearing stale singleton locks, because a browser that was
// killed earlier can leave them behind. Always call Shutdown.
func LaunchBrowser(o BrowserLaunch) (*ProfileBrowser, error) {
	b, err := launchOnce(o)
	if err == nil {
		return b, nil
	}
	slog.Warn("browser start failed; retrying once", "err", err)
	for name := range excludedProfileFiles {
		_ = os.Remove(filepath.Join(o.Dir, name))
	}
	time.Sleep(500 * time.Millisecond)
	return launchOnce(o)
}

func launchOnce(o BrowserLaunch) (*ProfileBrowser, error) {
	l := o.newLauncher()
	controlURL, err := l.Launch()
	if err != nil {
		l.Kill()
		return nil, fmt.Errorf("%w: %w", ErrBrowserLaunch, err)
	}
	u, err := url.Parse(controlURL)
	if err != nil {
		l.Kill()
		return nil, fmt.Errorf("%w: %w", ErrBrowserLaunch, err)
	}
	br := rod.New().ControlURL(controlURL)
	if err := br.Connect(); err != nil {
		l.Kill()
		return nil, fmt.Errorf("%w: %w", ErrBrowserLaunch, err)
	}
	return &ProfileBrowser{Browser: br, l: l, addr: u.Host}, nil
}

// Shutdown closes the browser and waits until its process has exited, so
// Chromium has written the profile (cookies included) to disk. Killing it right
// after Close loses cookies set in the last moments: measured 2026-10-13
// (issue #775). It never deletes the profile dir. Safe to call more than once.
func (b *ProfileBrowser) Shutdown() {
	b.once.Do(func() {
		_ = b.Browser.Close()
		deadline := time.Now().Add(browserExitWait)
		for time.Now().Before(deadline) {
			dialer := net.Dialer{Timeout: 200 * time.Millisecond}
			c, err := dialer.DialContext(context.Background(), "tcp", b.addr)
			if err != nil {
				return // debug port closed: the process is gone
			}
			_ = c.Close()
			time.Sleep(100 * time.Millisecond)
		}
		slog.Warn("browser did not exit in time; killing it")
		b.l.Kill()
	})
}
