package cookievault

import (
	"context"
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeSession struct {
	cookies  []Cookie
	cookErr  error
	done     chan struct{}
	closed   atomic.Int32
	doneOnce sync.Once
}

func newFakeSession(cookies ...Cookie) *fakeSession {
	return &fakeSession{cookies: cookies, done: make(chan struct{})}
}

func (s *fakeSession) Cookies(context.Context) ([]Cookie, error) { return s.cookies, s.cookErr }
func (s *fakeSession) Done() <-chan struct{}                     { return s.done }
func (s *fakeSession) Close() error                              { s.closed.Add(1); return nil }
func (s *fakeSession) userClosesWindow()                         { s.doneOnce.Do(func() { close(s.done) }) }

type fakeDriver struct {
	mu     sync.Mutex
	opens  int
	dirs   []string
	url    string
	err    error
	sess   *fakeSession
	opened chan struct{}
	onOpen func(dir string)
}

func (d *fakeDriver) Open(_ context.Context, loginURL, dir string) (Session, error) {
	d.mu.Lock()
	d.opens++
	d.dirs = append(d.dirs, dir)
	d.url = loginURL
	d.mu.Unlock()
	if d.onOpen != nil {
		d.onOpen(dir)
	}
	if d.err != nil {
		return nil, d.err
	}
	if d.opened != nil {
		close(d.opened)
	}
	return d.sess, nil
}

func (d *fakeDriver) lastDir() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dirs[len(d.dirs)-1]
}

func fastCapturer(d Driver, slots int, timeout time.Duration) *Capturer {
	c := NewCapturer(d, nil, slots, timeout)
	c.poll = 5 * time.Millisecond
	return c
}

func TestCaptureHappyPathFiltersToDomain(t *testing.T) {
	sess := newFakeSession(
		sessionCookie("sid", "v", ".example.com"),
		sessionCookie("trk", "x", ".tracker.net"),
	)
	d := &fakeDriver{sess: sess}
	c := fastCapturer(d, 1, time.Second)
	go func() { time.Sleep(30 * time.Millisecond); sess.userClosesWindow() }()
	domain, cookies, err := c.Capture(context.Background(), "https://www.example.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if domain != "example.com" || len(cookies) != 1 || cookies[0].Name != "sid" {
		t.Fatalf("got %q %+v", domain, cookies)
	}
	if sess.closed.Load() == 0 {
		t.Error("session not closed")
	}
}

func TestCaptureProfileDirRemovedOnEveryPath(t *testing.T) {
	boom := errors.New("boom")
	cases := map[string]func(t *testing.T) (*fakeDriver, *Capturer, context.Context, context.CancelFunc){
		"success": func(t *testing.T) (*fakeDriver, *Capturer, context.Context, context.CancelFunc) {
			s := newFakeSession(sessionCookie("sid", "v", "example.com"))
			s.userClosesWindow()
			d := &fakeDriver{sess: s}
			ctx, cancel := context.WithCancel(context.Background())
			return d, fastCapturer(d, 1, time.Second), ctx, cancel
		},
		"open error": func(t *testing.T) (*fakeDriver, *Capturer, context.Context, context.CancelFunc) {
			d := &fakeDriver{err: boom}
			ctx, cancel := context.WithCancel(context.Background())
			return d, fastCapturer(d, 1, time.Second), ctx, cancel
		},
		"timeout": func(t *testing.T) (*fakeDriver, *Capturer, context.Context, context.CancelFunc) {
			d := &fakeDriver{sess: newFakeSession()}
			ctx, cancel := context.WithCancel(context.Background())
			return d, fastCapturer(d, 1, 30*time.Millisecond), ctx, cancel
		},
		"cancel": func(t *testing.T) (*fakeDriver, *Capturer, context.Context, context.CancelFunc) {
			d := &fakeDriver{sess: newFakeSession()}
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(30*time.Millisecond, cancel)
			return d, fastCapturer(d, 1, 10*time.Second), ctx, cancel
		},
		"nothing captured": func(t *testing.T) (*fakeDriver, *Capturer, context.Context, context.CancelFunc) {
			s := newFakeSession()
			s.userClosesWindow()
			d := &fakeDriver{sess: s}
			ctx, cancel := context.WithCancel(context.Background())
			return d, fastCapturer(d, 1, time.Second), ctx, cancel
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			d, c, ctx, cancel := mk(t)
			defer cancel()
			var existedDuring bool
			d.onOpen = func(dir string) {
				st, err := os.Stat(dir)
				existedDuring = err == nil && st.IsDir()
				_ = os.WriteFile(dir+"/Cookies", []byte("x"), 0o600)
			}
			_, _, _ = c.Capture(ctx, "https://example.com/login")
			if !existedDuring {
				t.Fatal("profile dir did not exist while the browser was open")
			}
			if _, err := os.Stat(d.lastDir()); !os.IsNotExist(err) {
				t.Errorf("profile dir %s still exists (err=%v)", d.lastDir(), err)
			}
		})
	}
	t.Run("panic in driver", func(t *testing.T) {
		d := &fakeDriver{sess: newFakeSession()}
		d.onOpen = func(string) { panic("driver crashed") }
		c := fastCapturer(d, 1, time.Second)
		func() {
			defer func() { _ = recover() }()
			_, _, _ = c.Capture(context.Background(), "https://example.com/login")
		}()
		if _, err := os.Stat(d.lastDir()); !os.IsNotExist(err) {
			t.Errorf("profile dir survived a panic (err=%v)", err)
		}
		// The slot is released too.
		if len(c.slots) != 0 {
			t.Error("slot leaked after panic")
		}
	})
}

func TestCaptureSemaphoreBound(t *testing.T) {
	s := newFakeSession(sessionCookie("sid", "v", "example.com"))
	d := &fakeDriver{sess: s, opened: make(chan struct{})}
	c := fastCapturer(d, 1, 5*time.Second)
	errCh := make(chan error, 1)
	go func() {
		_, _, err := c.Capture(context.Background(), "https://example.com/login")
		errCh <- err
	}()
	<-d.opened
	if _, _, err := c.Capture(context.Background(), "https://example.com/login"); !errors.Is(err, ErrCaptureBusy) {
		t.Fatalf("second capture err = %v, want ErrCaptureBusy", err)
	}
	d.mu.Lock()
	opens := d.opens
	d.mu.Unlock()
	if opens != 1 {
		t.Errorf("driver opened %d times, want 1", opens)
	}
	s.userClosesWindow()
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	// Slot is free again.
	s2 := newFakeSession(sessionCookie("sid", "v", "example.com"))
	s2.userClosesWindow()
	d.sess, d.opened = s2, nil
	if _, _, err := c.Capture(context.Background(), "https://example.com/login"); err != nil {
		t.Errorf("capture after release: %v", err)
	}
}

func TestCaptureTimeoutAndCancel(t *testing.T) {
	d := &fakeDriver{sess: newFakeSession(sessionCookie("sid", "v", "example.com"))}
	c := fastCapturer(d, 1, 40*time.Millisecond)
	domain, cookies, err := c.Capture(context.Background(), "https://example.com/login")
	if !errors.Is(err, ErrCaptureTimeout) || domain != "" || cookies != nil {
		t.Errorf("timeout: %q %v %v", domain, cookies, err)
	}
	if d.sess.closed.Load() == 0 {
		t.Error("browser not closed on timeout")
	}

	d2 := &fakeDriver{sess: newFakeSession(sessionCookie("sid", "v", "example.com"))}
	c2 := fastCapturer(d2, 1, 10*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(30*time.Millisecond, cancel)
	_, cookies, err = c2.Capture(ctx, "https://example.com/login")
	if !errors.Is(err, context.Canceled) || cookies != nil {
		t.Errorf("cancel: %v %v", cookies, err)
	}
	if d2.sess.closed.Load() == 0 {
		t.Error("browser not closed on cancel")
	}
}

func TestCaptureRejectsBadURLsBeforeLaunch(t *testing.T) {
	d := &fakeDriver{sess: newFakeSession()}
	c := fastCapturer(d, 1, time.Second)
	for _, u := range []string{
		"", "not a url", "file:///etc/passwd", "javascript:alert(1)", "ftp://example.com",
		"http://127.0.0.1/login", "http://localhost:8080/", "https://[::1]/", "https://intranet/login",
		"https://user:pass@example.com/", "https://co.uk/",
	} {
		if _, _, err := c.Capture(context.Background(), u); !errors.Is(err, ErrInvalidLoginURL) {
			t.Errorf("Capture(%q) err = %v, want ErrInvalidLoginURL", u, err)
		}
	}
	// SSRF validator runs before launch and its error is surfaced.
	deny := errors.New("blocked")
	c.validate = func(context.Context, string) error { return deny }
	if _, _, err := c.Capture(context.Background(), "https://example.com/"); !errors.Is(err, deny) {
		t.Errorf("validator err = %v", err)
	}
	if d.opens != 0 {
		t.Errorf("browser opened %d times for rejected URLs", d.opens)
	}
}

func TestConstructionLaunchesNoBrowser(t *testing.T) {
	d := &fakeDriver{sess: newFakeSession()}
	_ = NewCapturer(d, nil, 2, time.Second)
	if d.opens != 0 {
		t.Error("NewCapturer opened a browser")
	}
	rd := NewRodDriver("/nonexistent/chrome")
	if rd == nil {
		t.Fatal("nil driver")
	}
	// Open is the only place a launch can fail, and it was never called.
	if rd.headless {
		t.Error("production driver must be headed")
	}
}

func TestMultiInstanceCapturer(t *testing.T) {
	s1 := newFakeSession(sessionCookie("sid", "one", "example.com"))
	d1 := &fakeDriver{sess: s1, opened: make(chan struct{})}
	c1 := fastCapturer(d1, 1, 5*time.Second)

	s2 := newFakeSession(sessionCookie("sid", "two", "example.com"))
	s2.userClosesWindow()
	d2 := &fakeDriver{sess: s2}
	c2 := fastCapturer(d2, 1, 5*time.Second)

	res := make(chan []Cookie, 1)
	go func() {
		_, cookies, _ := c1.Capture(context.Background(), "https://example.com/login")
		res <- cookies
	}()
	<-d1.opened
	// c1 is busy; c2 must be unaffected and see only its own session.
	_, cookies, err := c2.Capture(context.Background(), "https://example.com/login")
	if err != nil || len(cookies) != 1 || cookies[0].Value != "two" {
		t.Fatalf("c2: %+v %v", cookies, err)
	}
	s1.userClosesWindow()
	if got := <-res; len(got) != 1 || got[0].Value != "one" {
		t.Errorf("c1: %+v", got)
	}
	if d1.dirs[0] == d2.dirs[0] {
		t.Error("instances share a profile dir")
	}
}
