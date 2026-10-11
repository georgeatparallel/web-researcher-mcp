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
)

const capturePollInterval = 500 * time.Millisecond

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

// Capture opens loginURL in a visible browser and returns the registrable
// domain and its cookies once the user closes the window. The browser profile
// is a fresh temp directory removed on every exit path. Nothing is stored here:
// on timeout or cancellation the caller gets an error and no cookies.
func (c *Capturer) Capture(ctx context.Context, loginURL string) (string, []Cookie, error) {
	u, err := url.Parse(loginURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return "", nil, ErrInvalidLoginURL
	}
	domain := RegistrableDomain(u.Hostname())
	if domain == "" {
		return "", nil, ErrInvalidLoginURL
	}
	if c.validate != nil {
		if err := c.validate(ctx, u.Hostname()); err != nil {
			return "", nil, fmt.Errorf("login URL rejected: %w", err)
		}
	}

	select {
	case c.slots <- struct{}{}:
		defer func() { <-c.slots }()
	default:
		return "", nil, ErrCaptureBusy
	}

	profileDir, err := os.MkdirTemp("", "wrmcp-login-*")
	if err != nil {
		return "", nil, fmt.Errorf("create login profile: %w", err)
	}
	defer func() { _ = os.RemoveAll(profileDir) }()

	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	sess, err := c.driver.Open(ctx, u.String(), profileDir)
	if err != nil {
		return "", nil, fmt.Errorf("open login browser: %w", err)
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
				return "", nil, ErrNothingCaptured
			}
			return domain, cookies, nil
		case <-ticker.C:
			snapshot()
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return "", nil, ErrCaptureTimeout
			}
			return "", nil, ctx.Err()
		}
	}
}
