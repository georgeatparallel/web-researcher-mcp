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

// NewRodDriver returns a headed Driver. An empty chromePath lets rod find Chrome.
func NewRodDriver(chromePath string) *RodDriver {
	return &RodDriver{chromePath: chromePath}
}

// Open launches Chromium on profileDir and navigates to loginURL.
func (d *RodDriver) Open(ctx context.Context, loginURL, profileDir string) (Session, error) {
	l := launcher.New().
		Headless(d.headless).
		UserDataDir(profileDir).
		Set("no-first-run").
		Delete("enable-automation").
		Set("disable-blink-features", "AutomationControlled")
	if d.chromePath != "" {
		l = l.Bin(d.chromePath)
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
	out := make([]Cookie, 0, len(raw))
	for _, c := range raw {
		ck := Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			HostOnly: len(c.Domain) > 0 && c.Domain[0] != '.',
			SameSite: string(c.SameSite),
		}
		if !c.Session && c.Expires > 0 {
			ck.Expires = c.Expires.Time()
		}
		out = append(out, ck)
	}
	return out, nil
}

func (s *rodSession) Close() error {
	s.finish()
	_ = s.browser.Close()
	s.launcher.Kill()
	s.launcher.Cleanup()
	return nil
}
