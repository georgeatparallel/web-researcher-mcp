package cookievault

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"
)

// Errors returned by Capturer.
var (
	ErrCaptureBusy     = errors.New("cookievault: all login-capture slots are in use")
	ErrCaptureTimeout  = errors.New("cookievault: login window was not closed before the timeout")
	ErrInvalidLoginURL = errors.New("cookievault: login URL must be http(s) with a registrable domain")
	ErrNothingCaptured = errors.New("cookievault: no cookies were set for this domain")
	// ErrNotSignedIn: the user's browser was reached but holds no cookies for the site.
	ErrNotSignedIn = errors.New("cookievault: the browser holds no cookies for this site")
	// ErrLoginURLRejected wraps the HostValidator error when the login host is
	// not allowed (e.g. a private address).
	ErrLoginURLRejected = errors.New("cookievault: login URL host is not allowed")
)

const capturePollInterval = 500 * time.Millisecond

// Source says where captured cookies came from.
type Source string

// Capture sources.
const (
	// SourceBrowser: read from the user's own running browser via an Attacher.
	SourceBrowser Source = "browser"
	// SourceLoginWindow: the user signed in inside a fresh login window.
	SourceLoginWindow Source = "login_window"
)

// Driver opens a visible browser for a human to log in. It never launches a
// browser until Open is called.
type Driver interface {
	// Open starts a browser with profileDir as its profile and navigates to loginURL.
	Open(ctx context.Context, loginURL, profileDir string) (Session, error)
}

// Session is one open login browser.
type Session interface {
	// Cookies returns every cookie currently held by the browser.
	Cookies(ctx context.Context) ([]Cookie, error)
	// Done is closed when the user closes the browser.
	Done() <-chan struct{}
	// Close shuts the browser down. It is safe to call more than once.
	Close() error
}

// HostValidator rejects hosts that must not be contacted (SSRF guard).
type HostValidator func(ctx context.Context, host string) error

// Capturer runs interactive login sessions. A session ends when the user closes
// the browser window. It holds no global state: concurrency, timeout and driver
// are per instance.
type Capturer struct {
	driver   Driver
	validate HostValidator
	slots    chan struct{}
	timeout  time.Duration
	poll     time.Duration
	attacher Attacher
}

// WithAttacher sets how CaptureWithSource reads cookies from the user's own
// running browser. A nil attacher makes that path report ErrAttachUnavailable.
func (c *Capturer) WithAttacher(a Attacher) *Capturer {
	c.attacher = a
	return c
}

// NewCapturer returns a Capturer allowing at most maxConcurrent sessions, each
// limited to timeout. Construction launches nothing.
func NewCapturer(driver Driver, validate HostValidator, maxConcurrent int, timeout time.Duration) *Capturer {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	return &Capturer{
		driver:   driver,
		validate: validate,
		slots:    make(chan struct{}, maxConcurrent),
		timeout:  timeout,
		poll:     capturePollInterval,
	}
}

// Capture is CaptureWithSource in login-window mode, without the source.
func (c *Capturer) Capture(ctx context.Context, loginURL string) (string, []Cookie, error) {
	domain, cookies, _, err := c.CaptureWithSource(ctx, loginURL, true)
	return domain, cookies, err
}

// CaptureWithSource returns the registrable domain of loginURL and its cookies.
// By default (useWindow false) it reads them from the user's own signed-in
// browser through the Attacher, and never opens a window: ErrAttachUnavailable
// or ErrNotSignedIn tell the caller what to fix. With useWindow it skips the
// user's browser and opens loginURL in a visible browser with a fresh temp
// profile, returning the cookies once the user closes the window; that profile
// is removed on every exit path. Nothing is stored here: on timeout or
// cancellation the caller gets an error and no cookies.
func (c *Capturer) CaptureWithSource(ctx context.Context, loginURL string, useWindow bool) (string, []Cookie, Source, error) {
	domain, cookies, src, err := c.capture(ctx, loginURL, useWindow)
	if err != nil {
		return "", nil, "", err
	}
	return domain, cookies, src, nil
}

func (c *Capturer) capture(ctx context.Context, loginURL string, useWindow bool) (string, []Cookie, Source, error) {
	u, err := url.Parse(loginURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return "", nil, "", ErrInvalidLoginURL
	}
	domain := RegistrableDomain(u.Hostname())
	if domain == "" {
		return "", nil, "", ErrInvalidLoginURL
	}
	if c.validate != nil {
		if err := c.validate(ctx, u.Hostname()); err != nil {
			return "", nil, "", fmt.Errorf("%w: %w", ErrLoginURLRejected, err)
		}
	}

	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return "", nil, "", ErrCaptureBusy
	}

	if !useWindow {
		if c.attacher == nil {
			return "", nil, "", ErrAttachUnavailable
		}
		cookies, err := c.attacher.Attach(ctx, domain)
		if ctx.Err() != nil {
			return "", nil, "", ctx.Err()
		}
		if err != nil {
			return "", nil, "", ErrAttachUnavailable
		}
		if len(cookies) == 0 {
			return "", nil, "", ErrNotSignedIn
		}
		return domain, cookies, SourceBrowser, nil
	}

	profileDir, err := os.MkdirTemp("", "wrmcp-login-*")
	if err != nil {
		return "", nil, "", fmt.Errorf("create login profile: %w", err)
	}
	defer func() { _ = os.RemoveAll(profileDir) }()

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	sess, err := c.driver.Open(ctx, u.String(), profileDir)
	if err != nil {
		return "", nil, "", fmt.Errorf("open login browser: %w", err)
	}
	var closeOnce sync.Once
	closeSession := func() { closeOnce.Do(func() { _ = sess.Close() }) }
	defer closeSession()

	var last []Cookie
	snapshot := func() {
		if cookies, err := sess.Cookies(ctx); err == nil {
			last = cookies
		}
	}
	ticker := time.NewTicker(c.poll)
	defer ticker.Stop()
	for {
		select {
		case <-sess.Done():
			snapshot()
			cookies := FilterToDomain(last, domain, time.Now())
			if len(cookies) == 0 {
				return "", nil, "", ErrNothingCaptured
			}
			return domain, cookies, SourceLoginWindow, nil
		case <-ticker.C:
			snapshot()
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return "", nil, "", ErrCaptureTimeout
			}
			return "", nil, "", ctx.Err()
		}
	}
}
