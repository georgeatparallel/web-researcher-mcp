package scraper

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zoharbabin/web-researcher-mcp/internal/auth"
)

func profilePipeline(allowPrivate bool) *Pipeline {
	return NewPipeline(PipelineConfig{AllowPrivateIPs: allowPrivate, MaxBrowserConcurrency: 1})
}

func profileSite(t *testing.T, h http.HandlerFunc) (srv *httptest.Server, domain string) {
	t.Helper()
	srv = httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return srv, u.Hostname()
}

// TestProfileScrapeRejectsBeforeLaunch: bad input never reaches the tier limit
// or a browser.
func TestProfileScrapeRejectsBeforeLaunch(t *testing.T) {
	t.Parallel()
	p := profilePipeline(false)
	cases := map[string]struct{ url, domain string }{
		"scheme":       {"file:///etc/passwd", "example.com"},
		"other site":   {"https://evil.example.net/", "example.com"},
		"suffix trick": {"https://notexample.com/", "example.com"},
		"private ip":   {"http://127.0.0.1/", "127.0.0.1"},
		"no domain":    {"https://example.com/", ""},
	}
	for name, c := range cases {
		_, err := p.ScrapeWithProfile(context.Background(), c.url, 1000, ProfileSpec{Dir: t.TempDir(), Domain: c.domain})
		var se *ScrapeError
		if !errors.As(err, &se) || se.Kind != ErrValidation {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
}

// TestProfileScrapeHonorsBrowserTierLimit: a profile scrape waits for the same
// browser slots as the other browser scrapes.
func TestProfileScrapeHonorsBrowserTierLimit(t *testing.T) {
	t.Parallel()
	p := profilePipeline(true)
	hold, err := p.acquireTier(context.Background(), "browser")
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err = p.ScrapeWithProfile(ctx, "http://127.0.0.1/", 1000, ProfileSpec{Dir: t.TempDir(), Domain: "127.0.0.1"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the context deadline while waiting for a slot", err)
	}
}

func TestProfileScrapeHonorsTenantLimit(t *testing.T) {
	t.Parallel()
	p := profilePipeline(true)
	ctxA := auth.WithIdentity(context.Background(), "tenant-a", "u1")
	hold, err := p.acquireTier(ctxA, "browser")
	if err != nil {
		t.Fatal(err)
	}
	defer hold()
	ctx, cancel := context.WithTimeout(ctxA, 100*time.Millisecond)
	defer cancel()
	if _, err := p.ScrapeWithProfile(ctx, "http://127.0.0.1/", 1000, ProfileSpec{Dir: t.TempDir(), Domain: "127.0.0.1"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

// TestProfileBlocksOffDomainNavigation: a redirect off the profile's site is
// refused before it is sent, and reads as a login request.
func TestProfileBlocksOffDomainNavigation(t *testing.T) {
	skipIfNoChrome(t)
	var mu sync.Mutex
	var other []string
	otherSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		other = append(other, r.Host)
		mu.Unlock()
	}))
	defer otherSrv.Close()
	otherURL := strings.Replace(otherSrv.URL, "127.0.0.1", "localhost", 1)
	srv, domain := profileSite(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, otherURL, http.StatusFound)
	})
	p := profilePipeline(true)
	_, err := p.ScrapeWithProfile(context.Background(), srv.URL+"/", 5000, ProfileSpec{Dir: t.TempDir(), Domain: domain})
	var se *ScrapeError
	if !errors.As(err, &se) || se.Kind != ErrAuth {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(other) != 0 {
		t.Errorf("the other site received %d request(s)", len(other))
	}
}

// TestProfileScrapeWaitsForLateContent: text rendered after load is returned.
func TestProfileScrapeWaitsForLateContent(t *testing.T) {
	skipIfNoChrome(t)
	srv, domain := profileSite(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `<html><head><title>Feed</title></head><body><main>loading</main>
<script>setTimeout(()=>{document.querySelector('main').textContent='LATE POST CONTENT '+'x'.repeat(300)},900)</script></body></html>`)
	})
	p := profilePipeline(true)
	res, err := p.ScrapeWithProfile(context.Background(), srv.URL+"/", 5000, ProfileSpec{Dir: t.TempDir(), Domain: domain})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Content, "LATE POST CONTENT") {
		t.Errorf("late content missing: %.120s", res.Content)
	}
	if res.Title != "Feed" || res.Tier != "browser" {
		t.Errorf("title %q tier %q", res.Title, res.Tier)
	}
}

// TestProfileScrapeUsesTheProfile: a persistent cookie set in one run reaches
// the site in the next run on the same dir, with no UA override.
func TestProfileScrapeUsesTheProfile(t *testing.T) {
	skipIfNoChrome(t)
	var mu sync.Mutex
	var uas []string
	srv, domain := profileSite(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		uas = append(uas, r.UserAgent())
		mu.Unlock()
		if r.URL.Path == "/login" {
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "SIGNED-IN", Path: "/", Expires: time.Now().Add(time.Hour)})
		}
		c, _ := r.Cookie("sid")
		who := "anonymous"
		if c != nil {
			who = c.Value
		}
		_, _ = fmt.Fprintf(w, "<html><body><main>you are %s %s</main></body></html>", who, strings.Repeat("pad ", 80))
	})
	p := profilePipeline(true)
	spec := ProfileSpec{Dir: t.TempDir(), Domain: domain}
	if _, err := p.ScrapeWithProfile(context.Background(), srv.URL+"/login", 5000, spec); err != nil {
		t.Fatal(err)
	}
	res, err := p.ScrapeWithProfile(context.Background(), srv.URL+"/home", 5000, spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Content, "you are SIGNED-IN") {
		t.Errorf("profile cookie did not reach the site: %.120s", res.Content)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, ua := range uas {
		if strings.Contains(ua, "Macintosh; Intel Mac OS X 10_15_7") && strings.Contains(ua, "Chrome/131.0.0.0") {
			t.Errorf("the stealth UA override leaked into the profile path: %s", ua)
		}
	}
}
