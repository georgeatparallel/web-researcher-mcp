package cookievault

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeBrowser is a CDP endpoint that answers Storage.getCookies with a fixed
// jar and records every method it receives.
type fakeBrowser struct {
	srv     *httptest.Server
	mu      sync.Mutex
	methods []string
	closed  chan struct{}
	deny    bool
}

func newFakeBrowser(t *testing.T, cookies []map[string]any) *fakeBrowser {
	t.Helper()
	fb := &fakeBrowser{closed: make(chan struct{})}
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	fb.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fb.deny {
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer close(fb.closed)
		defer func() { _ = conn.Close() }()
		for {
			var req struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
			}
			if err := conn.ReadJSON(&req); err != nil {
				return
			}
			fb.mu.Lock()
			fb.methods = append(fb.methods, req.Method)
			fb.mu.Unlock()
			_ = conn.WriteJSON(map[string]any{"id": req.ID, "result": map[string]any{"cookies": cookies}})
		}
	}))
	t.Cleanup(fb.srv.Close)
	return fb
}

func (fb *fakeBrowser) wsURL() string {
	return "ws" + strings.TrimPrefix(fb.srv.URL, "http") + "/devtools/browser/abc-123"
}

func (fb *fakeBrowser) seen() []string {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return append([]string(nil), fb.methods...)
}

func jar() []map[string]any {
	exp := float64(time.Now().Add(time.Hour).Unix())
	mk := func(name, domain string) map[string]any {
		return map[string]any{"name": name, "value": "v-" + name, "domain": domain, "path": "/", "expires": exp, "size": 1,
			"httpOnly": true, "secure": true, "session": false, "priority": "Medium", "sameParty": false, "sourceScheme": "Secure", "sourcePort": 443}
	}
	return []map[string]any{mk("li_at", ".linkedin.com"), mk("sid", "www.linkedin.com"), mk("bank", ".mybank.com"), mk("other", "example.org")}
}

func TestBrowserCookiesDisconnectsWithoutQuittingBrowser(t *testing.T) {
	t.Parallel()
	fb := newFakeBrowser(t, jar())
	cookies, err := browserCookies(context.Background(), fb.wsURL())
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 4 {
		t.Fatalf("got %d cookies, want the raw jar of 4", len(cookies))
	}
	select {
	case <-fb.closed:
	case <-time.After(3 * time.Second):
		t.Fatal("socket was not closed")
	}
	for _, m := range fb.seen() {
		if strings.HasPrefix(m, "Browser.close") || m == "Target.closeTarget" {
			t.Fatalf("attacher sent %s, which would close the user's browser", m)
		}
	}
	if got := fb.seen(); len(got) != 1 || got[0] != "Storage.getCookies" {
		t.Fatalf("methods = %v, want only Storage.getCookies", got)
	}
}

func writeActivePort(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "DevToolsActivePort"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func portOf(fb *fakeBrowser) string {
	return fb.srv.Listener.Addr().String()[strings.LastIndex(fb.srv.Listener.Addr().String(), ":")+1:]
}

func TestRodAttacherKeepsOnlyTheDomain(t *testing.T) {
	t.Parallel()
	fb := newFakeBrowser(t, jar())
	dir := t.TempDir()
	writeActivePort(t, dir, portOf(fb)+"\n/devtools/browser/abc-123\n")
	a := &RodAttacher{dirs: []string{filepath.Join(dir, "missing"), dir}, timeout: 5 * time.Second}

	cookies, err := a.Attach(context.Background(), "linkedin.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(cookies) != 2 {
		t.Fatalf("got %d cookies, want 2 linkedin.com cookies", len(cookies))
	}
	for _, c := range cookies {
		if !strings.HasSuffix(c.Domain, "linkedin.com") {
			t.Fatalf("cookie for %q leaked through the domain filter", c.Domain)
		}
	}
}

func TestRodAttacherUnavailable(t *testing.T) {
	t.Parallel()
	denied := newFakeBrowser(t, nil)
	denied.deny = true
	deniedDir := t.TempDir()
	writeActivePort(t, deniedDir, portOf(denied)+"\n/devtools/browser/abc-123\n")

	cases := map[string][]string{
		"no file":     {t.TempDir()},
		"no dirs":     nil,
		"user denied": {deniedDir},
		"unreachable": nil,
	}
	deadDir := t.TempDir()
	writeActivePort(t, deadDir, "1\n/devtools/browser/abc-123\n")
	cases["unreachable"] = []string{deadDir}

	for name, dirs := range cases {
		a := &RodAttacher{dirs: dirs, timeout: 3 * time.Second}
		if _, err := a.Attach(context.Background(), "linkedin.com"); !errors.Is(err, ErrAttachUnavailable) {
			t.Errorf("%s: err = %v, want ErrAttachUnavailable", name, err)
		}
	}
}

func TestReadActivePortRejectsBadContent(t *testing.T) {
	t.Parallel()
	bad := map[string]string{
		"empty":          "",
		"one line":       "9222\n",
		"non numeric":    "abc\n/devtools/browser/x\n",
		"port zero":      "0\n/devtools/browser/x\n",
		"port too big":   "70000\n/devtools/browser/x\n",
		"wrong path":     "9222\n/json/version\n",
		"host injection": "9222\n@evil.example/devtools/browser/x\n",
		"path traversal": "9222\n/devtools/browser/../x\n",
		"query":          "9222\n/devtools/browser/x?y=1\n",
	}
	for name, content := range bad {
		dir := t.TempDir()
		writeActivePort(t, dir, content)
		if u, ok := readActivePort(dir); ok {
			t.Errorf("%s: accepted, got %q", name, u)
		}
	}
	dir := t.TempDir()
	writeActivePort(t, dir, "9222\n/devtools/browser/0a1b-2c3d\n")
	if u, ok := readActivePort(dir); !ok || u != "ws://127.0.0.1:9222/devtools/browser/0a1b-2c3d" {
		t.Fatalf("valid file: got %q %v", u, ok)
	}
}

type fakeAttacher struct {
	cookies []Cookie
	err     error
	calls   int
}

func (f *fakeAttacher) Attach(context.Context, string) ([]Cookie, error) {
	f.calls++
	return f.cookies, f.err
}

func TestCapturerPrefersBrowserAttach(t *testing.T) {
	t.Parallel()
	drv := &fakeDriver{}
	att := &fakeAttacher{cookies: []Cookie{{Name: "li_at", Value: "x", Domain: ".linkedin.com", Path: "/"}}}
	c := NewCapturer(drv, nil, 1, time.Second).WithAttacher(att)
	domain, cookies, err := c.CaptureFromBrowser(context.Background(), "https://www.linkedin.com/login")
	if err != nil {
		t.Fatal(err)
	}
	if domain != "linkedin.com" || len(cookies) != 1 {
		t.Fatalf("got %q %d", domain, len(cookies))
	}
	if drv.opens != 0 {
		t.Fatal("login window opened although the browser attach worked")
	}
}

func TestCaptureFromBrowserNeverOpensWindow(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		att  Attacher
		want error
	}{
		"unavailable": {&fakeAttacher{err: ErrAttachUnavailable}, ErrAttachUnavailable},
		"no cookies":  {&fakeAttacher{}, ErrNotSignedIn},
		"no attacher": {nil, ErrAttachUnavailable},
	} {
		drv := &fakeDriver{}
		c := NewCapturer(drv, nil, 1, time.Second)
		if tc.att != nil {
			c = c.WithAttacher(tc.att)
		}
		_, cookies, err := c.CaptureFromBrowser(context.Background(), "https://www.linkedin.com/login")
		if !errors.Is(err, tc.want) || len(cookies) != 0 {
			t.Errorf("%s: got %d cookies, err %v, want %v", name, len(cookies), err, tc.want)
		}
		if drv.opens != 0 {
			t.Errorf("%s: login window opened", name)
		}
	}
}

func TestCaptureFromBrowserSkipsRejectedHost(t *testing.T) {
	t.Parallel()
	att := &fakeAttacher{cookies: []Cookie{{Name: "a", Value: "b", Domain: "x.com", Path: "/"}}}
	deny := func(context.Context, string) error { return errors.New("private") }
	c := NewCapturer(&fakeDriver{}, deny, 1, time.Second).WithAttacher(att)
	if _, _, err := c.CaptureFromBrowser(context.Background(), "https://x.com/"); !errors.Is(err, ErrLoginURLRejected) {
		t.Fatalf("err = %v", err)
	}
	if att.calls != 0 {
		t.Fatal("browser was contacted for a rejected host")
	}
}
