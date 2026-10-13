package scraper

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zoharbabin/web-researcher-mcp/internal/cookievault"
)

const filler = "This paragraph exists only so the page clears every extraction quality bar. " +
	"It repeats a plain sentence several times to reach a realistic article length. " +
	"The sentence says nothing, but a scraper still needs real prose to keep it. "

// cookieServer echoes the request Cookie header in the page body and records
// every Cookie header it receives.
type cookieServer struct {
	*httptest.Server
	mu   sync.Mutex
	seen []string
}

func newCookieServer(t *testing.T, h http.HandlerFunc) *cookieServer {
	t.Helper()
	cs := &cookieServer{}
	cs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cs.mu.Lock()
		cs.seen = append(cs.seen, r.Header.Get("Cookie"))
		cs.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><head><title>t</title></head><body><article><p>COOKIE[%s]</p><p>%s%s%s</p></article></body></html>",
			r.Header.Get("Cookie"), filler, filler, filler)
	}))
	t.Cleanup(cs.Close)
	return cs
}

func (cs *cookieServer) cookieHeaders() []string {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return append([]string(nil), cs.seen...)
}

func (cs *cookieServer) host() string {
	u, _ := url.Parse(cs.URL)
	return u.Hostname()
}

func hostOnly(name, value, host string) cookievault.Cookie {
	return cookievault.Cookie{Name: name, Value: value, Domain: host, Path: "/", HostOnly: true}
}

func localPipeline() *Pipeline {
	return NewPipeline(PipelineConfig{AllowPrivateIPs: true, ChromePath: chromeDisabled})
}

func anyHeaderContains(headers []string, sub string) bool {
	for _, h := range headers {
		if strings.Contains(h, sub) {
			return true
		}
	}
	return false
}

// mapHosts makes p's shared client dial the given test servers for fake public
// host names, so cookie-domain rules can be exercised without real DNS. (Go's
// cookie jar treats loopback hosts as secure origins, so loopback cannot be
// used to test Secure handling.)
func mapHosts(p *Pipeline, hosts map[string]*cookieServer) {
	p.client.Transport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			srv, ok := hosts[host]
			if !ok {
				return nil, fmt.Errorf("unmapped test host %q", host)
			}
			return (&net.Dialer{}).DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}
}

func TestSecureCookieNotSentOverHTTP(t *testing.T) {
	srv := newCookieServer(t, nil)
	p := localPipeline()
	mapHosts(p, map[string]*cookieServer{"app.example.com": srv})
	secure := cookievault.Cookie{Name: "sid", Value: "SECRET", Domain: "app.example.com", Path: "/", HostOnly: true, Secure: true}
	plain := cookievault.Cookie{Name: "pid", Value: "PUBLIC", Domain: "app.example.com", Path: "/", HostOnly: true}
	ctx := WithCookies(context.Background(), []cookievault.Cookie{secure, plain})

	if _, err := p.scrapeHTML(ctx, "http://app.example.com/", 5000, false); err != nil {
		t.Fatal(err)
	}
	headers := srv.cookieHeaders()
	if len(headers) != 1 || !strings.Contains(headers[0], "pid=PUBLIC") {
		t.Fatalf("control cookie not sent: %q", headers)
	}
	if anyHeaderContains(headers, "SECRET") {
		t.Errorf("Secure cookie sent over http: %q", headers)
	}

	// The same jar sends it over https.
	jar, err := newCookieJar([]cookievault.Cookie{secure}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got := jar.Cookies(&url.URL{Scheme: "https", Host: "app.example.com", Path: "/"}); len(got) != 1 {
		t.Errorf("https cookies = %v, want 1", got)
	}
	if got := jar.Cookies(&url.URL{Scheme: "http", Host: "app.example.com", Path: "/"}); len(got) != 0 {
		t.Errorf("http cookies = %v, want none", got)
	}
}

func TestHostOnlyVsDomainCookie(t *testing.T) {
	cookies := []cookievault.Cookie{
		{Name: "host", Value: "1", Domain: "app.example.com", Path: "/", HostOnly: true},
		{Name: "dom", Value: "2", Domain: ".example.com", Path: "/"},
		{Name: "scoped", Value: "3", Domain: ".example.com", Path: "/account"},
	}
	jar, err := newCookieJar(cookies, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	names := func(rawURL string) string {
		u, _ := url.Parse(rawURL)
		var n []string
		for _, c := range jar.Cookies(u) {
			n = append(n, c.Name)
		}
		return strings.Join(n, ",")
	}
	cases := []struct{ url, want string }{
		{"https://app.example.com/", "host,dom"},
		{"https://app.example.com/account/x", "scoped,host,dom"},
		{"https://example.com/", "dom"},
		{"https://other.example.com/", "dom"},
		{"https://deep.app.example.com/", "dom"},
		{"https://example.com.evil.net/", ""},
		{"https://evilexample.com/", ""},
		{"https://example.org/", ""},
	}
	for _, tc := range cases {
		if got := names(tc.url); got != tc.want {
			t.Errorf("cookies for %s = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestRedirectToOtherHostDoesNotLeakCookie(t *testing.T) {
	other := newCookieServer(t, nil)
	origin := newCookieServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://app.example.org/landing", http.StatusFound)
	})
	p := localPipeline()
	mapHosts(p, map[string]*cookieServer{"app.example.com": origin, "app.example.org": other})
	ctx := WithCookies(context.Background(), []cookievault.Cookie{
		{Name: "sid", Value: "SECRET", Domain: ".example.com", Path: "/"},
	})
	if _, err := p.scrapeHTML(ctx, "http://app.example.com/", 5000, false); err != nil {
		t.Fatal(err)
	}
	if !anyHeaderContains(origin.cookieHeaders(), "SECRET") {
		t.Fatal("origin never received its own cookie (test is vacuous)")
	}
	if len(other.cookieHeaders()) == 0 {
		t.Fatal("redirect target never contacted (test is vacuous)")
	}
	if anyHeaderContains(other.cookieHeaders(), "SECRET") {
		t.Errorf("cookie leaked across redirect: %q", other.cookieHeaders())
	}
}

func TestSSRFBlocksBeforeCookieSend(t *testing.T) {
	srv := newCookieServer(t, nil)
	p := NewPipeline(PipelineConfig{ChromePath: chromeDisabled}) // private IPs blocked
	ctx := WithCookies(context.Background(), []cookievault.Cookie{hostOnly("sid", "SECRET", srv.host())})
	if _, err := p.Scrape(ctx, srv.URL+"/", 5000); err == nil {
		t.Fatal("scrape of a private address succeeded")
	}
	if n := len(srv.cookieHeaders()); n != 0 {
		t.Errorf("server received %d request(s); SSRF block must precede any send", n)
	}
}

func TestResolveAndValidateHost(t *testing.T) {
	ctx := context.Background()
	blockedAlways := []string{"169.254.169.254", "metadata.google.internal", "foo.svc.cluster.local"}
	privateOnly := []string{"127.0.0.1", "localhost", "10.0.0.5", "192.168.1.1", "::1", "[::1]", "172.16.0.1"}
	for _, h := range blockedAlways {
		for _, allow := range []bool{false, true} {
			if err := ValidateHost(ctx, h, allow); !errors.Is(err, ErrSSRFBlocked) {
				t.Errorf("ValidateHost(%q, allow=%v) = %v, want ErrSSRFBlocked", h, allow, err)
			}
		}
	}
	for _, h := range privateOnly {
		if err := ValidateHost(ctx, h, false); !errors.Is(err, ErrSSRFBlocked) {
			t.Errorf("ValidateHost(%q, false) = %v, want ErrSSRFBlocked", h, err)
		}
		if err := ValidateHost(ctx, h, true); err != nil {
			t.Errorf("ValidateHost(%q, true) = %v, want nil", h, err)
		}
	}
	if err := ValidateHost(ctx, "93.184.216.34", false); err != nil {
		t.Errorf("public IP rejected: %v", err)
	}
	if err := ValidateHost(ctx, "no-such-host.invalid", false); err == nil {
		t.Error("unresolvable host accepted")
	}
}

func TestSessionCookieStaysSession(t *testing.T) {
	now := time.Now()
	cookies := []cookievault.Cookie{
		{Name: "s", Value: "1", Domain: "example.com", Path: "/", HostOnly: true},
		{Name: "p", Value: "2", Domain: ".example.com", Path: "/", Expires: now.Add(time.Hour), SameSite: "Lax", Secure: true},
	}
	cdp := toCDPCookies(cookies, now)
	if len(cdp) != 2 {
		t.Fatalf("got %d cookies", len(cdp))
	}
	if cdp[0].Expires != 0 || cdp[0].URL != "https://example.com/" || cdp[0].Domain != "" {
		t.Errorf("session host-only cookie wrong: %+v", cdp[0])
	}
	if cdp[1].Expires == 0 || cdp[1].Domain != ".example.com" || cdp[1].URL != "" || string(cdp[1].SameSite) != "Lax" || !cdp[1].Secure {
		t.Errorf("persistent domain cookie wrong: %+v", cdp[1])
	}

	// A session cookie stays session-scoped in the jar too: no expiry means it
	// is sent, and is not turned into a persistent entry that would be filtered.
	jar, _ := newCookieJar(cookies[:1], now)
	if got := jar.Cookies(&url.URL{Scheme: "https", Host: "example.com", Path: "/"}); len(got) != 1 {
		t.Errorf("session cookie not sent: %v", got)
	}
}

func TestExpiredCookiesDropped(t *testing.T) {
	now := time.Now()
	cookies := []cookievault.Cookie{
		{Name: "old", Value: "1", Domain: "example.com", Path: "/", HostOnly: true, Expires: now.Add(-time.Minute)},
		{Name: "now", Value: "2", Domain: "example.com", Path: "/", HostOnly: true, Expires: now},
	}
	if got := toCDPCookies(cookies, now); len(got) != 0 {
		t.Errorf("expired cookies reached CDP: %+v", got)
	}
	jar, _ := newCookieJar(cookies, now)
	if got := jar.Cookies(&url.URL{Scheme: "https", Host: "example.com", Path: "/"}); len(got) != 0 {
		t.Errorf("expired cookies in jar: %v", got)
	}
}

func TestConcurrentScrapesDoNotShareCookies(t *testing.T) {
	srv := newCookieServer(t, nil)
	p := localPipeline()
	const n = 8
	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mine := fmt.Sprintf("TOKEN%d", i)
			ctx := WithCookies(context.Background(), []cookievault.Cookie{hostOnly("sid", mine, srv.host())})
			res, err := p.Scrape(ctx, fmt.Sprintf("%s/p%d", srv.URL, i), 5000)
			if err != nil {
				errs <- err.Error()
				return
			}
			if !strings.Contains(res.Content, "sid="+mine) {
				errs <- fmt.Sprintf("scrape %d missing its own cookie: %.80s", i, res.Content)
			}
			for j := 0; j < n; j++ {
				if j != i && strings.Contains(res.Content, fmt.Sprintf("sid=TOKEN%d", j)) {
					errs <- fmt.Sprintf("scrape %d saw cookie of scrape %d", i, j)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	// A later anonymous scrape through the same pipeline carries nothing.
	before := len(srv.cookieHeaders())
	if _, err := p.Scrape(context.Background(), srv.URL+"/anon", 5000); err != nil {
		t.Fatal(err)
	}
	for _, h := range srv.cookieHeaders()[before:] {
		if h != "" {
			t.Errorf("anonymous scrape carried cookie %q", h)
		}
	}
}

func TestMultiInstancePipelineCookieIsolation(t *testing.T) {
	srv := newCookieServer(t, nil)
	a, b := localPipeline(), localPipeline()
	ctxA := WithCookies(context.Background(), []cookievault.Cookie{hostOnly("sid", "ALPHA", srv.host())})
	ctxB := WithCookies(context.Background(), []cookievault.Cookie{hostOnly("sid", "BETA", srv.host())})
	resA, errA := a.Scrape(ctxA, srv.URL+"/a", 5000)
	resB, errB := b.Scrape(ctxB, srv.URL+"/b", 5000)
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if !strings.Contains(resA.Content, "ALPHA") || strings.Contains(resA.Content, "BETA") {
		t.Errorf("instance A content: %.120s", resA.Content)
	}
	if !strings.Contains(resB.Content, "BETA") || strings.Contains(resB.Content, "ALPHA") {
		t.Errorf("instance B content: %.120s", resB.Content)
	}
	resC, err := a.Scrape(context.Background(), srv.URL+"/c", 5000)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(resC.Content, "ALPHA") || strings.Contains(resC.Content, "BETA") {
		t.Errorf("anonymous scrape on instance A saw cookies: %.120s", resC.Content)
	}
}

func TestVaultBackedSkipsCloudProxyTiers(t *testing.T) {
	var proxyHits int
	var mu sync.Mutex
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proxyHits++
		mu.Unlock()
		_, _ = w.Write([]byte(`{"code":200,"data":{"content":""},"results":[]}`))
	}))
	defer proxy.Close()
	withJinaEndpoint(t, proxy.URL+"/")
	prevExa := exaContentsURL
	exaContentsURL = proxy.URL
	t.Cleanup(func() { exaContentsURL = prevExa })

	// A thin page makes every free tier fail, so the ladder reaches jina and exa.
	thin := newCookieServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><body>tiny</body></html>"))
	})
	p := NewPipeline(PipelineConfig{AllowPrivateIPs: true, ChromePath: chromeDisabled, ExaAPIKey: "test-key"})

	_, _ = p.Scrape(context.Background(), thin.URL+"/", 5000)
	mu.Lock()
	control := proxyHits
	mu.Unlock()
	if control == 0 {
		t.Fatal("control: anonymous scrape never reached a cloud proxy tier (test is vacuous)")
	}

	ctx := WithCookies(context.Background(), []cookievault.Cookie{hostOnly("sid", "SECRET", thin.host())})
	_, _ = p.Scrape(ctx, thin.URL+"/", 5000)
	mu.Lock()
	defer mu.Unlock()
	if proxyHits != control {
		t.Errorf("cookie-bearing scrape reached cloud proxy tiers (%d extra hits)", proxyHits-control)
	}
}
