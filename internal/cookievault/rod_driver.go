package cookievault

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
)

// RodDriver is the production Driver: a visible Chromium driven by go-rod.
// Construction launches nothing; the browser starts in Open.
type RodDriver struct {
	chromePath string
	headless   bool // tests only; production login must be visible
}

// lookPath finds an installed browser; a variable so tests can stub it.
var lookPath = launcher.LookPath

// NewRodDriver returns a headed Driver. An empty chromePath uses the
// browser already installed on the machine (Chrome first), so the user signs
// in with the browser they know. Only when none is installed does rod download
// its own Chromium.
func NewRodDriver(chromePath string) *RodDriver {
	return &RodDriver{chromePath: chromePath}
}

// browserBin returns the explicit path, else the installed browser, else "".
func (d *RodDriver) browserBin() string {
	if d.chromePath != "" {
		return d.chromePath
	}
	if bin, ok := lookPath(); ok {
		return bin
	}
	return ""
}

// Open launches Chromium on profileDir and navigates to loginURL.
func (d *RodDriver) Open(ctx context.Context, loginURL, profileDir string) (Session, error) {
	l := launcher.New().
		Headless(d.headless).
		UserDataDir(profileDir).
		Set("no-first-run").
		Delete("enable-automation").
		Set("disable-blink-features", "AutomationControlled")
	if bin := d.browserBin(); bin != "" {
		l = l.Bin(bin)
	}
	if d.headless {
		l = l.Set("no-sandbox").Set("disable-gpu")
	}
	controlURL, err := l.Launch()
	if err != nil {
		l.Cleanup()
		return nil, fmt.Errorf("chrome launch failed: %w", err)
	}
	browser := rod.New().ControlURL(controlURL)
	if err := browser.Connect(); err != nil {
		l.Kill()
		l.Cleanup()
		return nil, fmt.Errorf("chrome connect failed: %w", err)
	}
	s := &rodSession{browser: browser, launcher: l, done: make(chan struct{})}
	if _, err := browser.Context(ctx).Page(proto.TargetCreateTarget{URL: loginURL}); err != nil {
		_ = s.Close()
		return nil, fmt.Errorf("open login page: %w", err)
	}
	go s.watch()
	return s, nil
}

type rodSession struct {
	browser  *rod.Browser
	launcher *launcher.Launcher
	done     chan struct{}
	once     sync.Once
}

// watch closes done when the last window is gone or Chromium has exited.
func (s *rodSession) watch() {
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		pages, err := s.browser.Pages()
		if err != nil || len(pages) == 0 {
			s.finish()
			return
		}
	}
}

func (s *rodSession) finish() { s.once.Do(func() { close(s.done) }) }

func (s *rodSession) Done() <-chan struct{} { return s.done }

func (s *rodSession) Cookies(ctx context.Context) ([]Cookie, error) {
	raw, err := s.browser.Context(ctx).GetCookies()
	if err != nil {
		return nil, err
	}
	return fromRodCookies(raw), nil
}

func (s *rodSession) Close() error {
	s.finish()
	_ = s.browser.Close()
	s.launcher.Kill()
	s.launcher.Cleanup()
	return nil
}
