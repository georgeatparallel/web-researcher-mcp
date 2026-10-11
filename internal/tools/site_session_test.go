package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/zoharbabin/web-researcher-mcp/internal/cache"
	"github.com/zoharbabin/web-researcher-mcp/internal/consent"
	"github.com/zoharbabin/web-researcher-mcp/internal/content"
	"github.com/zoharbabin/web-researcher-mcp/internal/cookievault"
	"github.com/zoharbabin/web-researcher-mcp/internal/datasubject"
	"github.com/zoharbabin/web-researcher-mcp/internal/metrics"
	"github.com/zoharbabin/web-researcher-mcp/internal/persist"
	"github.com/zoharbabin/web-researcher-mcp/internal/scraper"
	"github.com/zoharbabin/web-researcher-mcp/internal/session"
)

// Tests for site_login / site_logout and the vault-backed scrape path (issue #241).

const (
	vaultTestDomain = "vaulttest.com"
	vaultTestHost   = "app.vaulttest.com"
	canaryValue     = "CANARY-9f3b7c1e-session-token"
	privateMarker   = "PRIVATE-MEMBER-DASHBOARD"
	publicMarker    = "PUBLIC-LOGIN-WALL"
)

// fakeLoginDriver stands in for the visible browser. The "user" closes the
// window immediately; cookies is what the browser held at that moment.
type fakeLoginDriver struct {
	mu      sync.Mutex
	cookies []cookievault.Cookie
	opens   int
}

func (d *fakeLoginDriver) Open(_ context.Context, _, _ string) (cookievault.Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.opens++
	done := make(chan struct{})
	close(done)
	return &fakeLoginSession{cookies: append([]cookievault.Cookie(nil), d.cookies...), done: done}, nil
}

func (d *fakeLoginDriver) openCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.opens
}

type fakeLoginSession struct {
	cookies []cookievault.Cookie
	done    chan struct{}
}

func (s *fakeLoginSession) Cookies(context.Context) ([]cookievault.Cookie, error) {
	return s.cookies, nil
}
func (s *fakeLoginSession) Done() <-chan struct{} { return s.done }
func (s *fakeLoginSession) Close() error          { return nil }

// useFakeDNS resolves every name in names to 127.0.0.1 through the process
// resolver, so tests can use real registrable domains (an IP or localhost has
// none) without network access. Tests that call it must not run in parallel.
func useFakeDNS(t *testing.T, names ...string) {
	t.Helper()
	pc, err := (&net.ListenConfig{}).ListenPacket(context.Background(), "udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, n := range names {
		known[n+"."] = true
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(buf[:n])
			if err != nil {
				continue
			}
			q, err := p.Question()
			if err != nil {
				continue
			}
			rh := dnsmessage.Header{ID: hdr.ID, Response: true, Authoritative: true, RecursionAvailable: true}
			if !known[strings.ToLower(q.Name.String())] {
				rh.RCode = dnsmessage.RCodeNameError
			}
			b := dnsmessage.NewBuilder(nil, rh)
			_ = b.StartQuestions()
			_ = b.Question(q)
			_ = b.StartAnswers()
			if known[strings.ToLower(q.Name.String())] && q.Type == dnsmessage.TypeA {
				_ = b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: 1}, dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}})
			}
			out, err := b.Finish()
			if err != nil {
				continue
			}
			_, _ = pc.WriteTo(out, addr)
		}
	}()
	prev := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", pc.LocalAddr().String())
		},
	}
	t.Cleanup(func() {
		net.DefaultResolver = prev
		_ = pc.Close()
	})
}

// loginSite is a login-gated origin: pages carry privateMarker only when the
// request has the canary session cookie.
type loginSite struct {
	*httptest.Server
	mu      sync.Mutex
	cookies []string
}

func newLoginSite(t *testing.T) *loginSite {
	t.Helper()
	ls := &loginSite{}
	ls.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.mu.Lock()
		ls.cookies = append(ls.cookies, r.Header.Get("Cookie"))
		ls.mu.Unlock()
		marker := publicMarker
		if c, err := r.Cookie("sid"); err == nil && c.Value == canaryValue {
			marker = privateMarker
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><head><title>Dash</title></head><body><article><p>" + marker + " " +
			strings.Repeat("Enough body text for the HTML tier to accept this page as real content. ", 6) +
			"</p></article></body></html>"))
	}))
	t.Cleanup(ls.Close)
	return ls
}

func (ls *loginSite) pageURL() string {
	_, port, _ := net.SplitHostPort(ls.Listener.Addr().String())
	return "http://" + vaultTestHost + ":" + port + "/dash"
}

func (ls *loginSite) requestCount() int {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return len(ls.cookies)
}

func (ls *loginSite) sawCookie() bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	for _, c := range ls.cookies {
		if strings.Contains(c, "sid=") {
			return true
		}
	}
	return false
}

// mapCache is a real, inspectable cache so tests can prove nothing was stored.
type mapCache struct {
	mu   sync.Mutex
	data map[string][]byte
	sets int
}

func newMapCache() *mapCache { return &mapCache{data: map[string][]byte{}} }

func (c *mapCache) Get(_ context.Context, k string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.data[k]
	return v, ok
}

func (c *mapCache) GetWithMeta(ctx context.Context, k string) ([]byte, *cache.EntryMeta, bool) {
	v, ok := c.Get(ctx, k)
	if !ok {
		return nil, nil, false
	}
	return v, &cache.EntryMeta{StoredAt: time.Now(), TTL: time.Hour}, true
}

func (c *mapCache) Set(_ context.Context, k string, v []byte, _ time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[k] = v
	c.sets++
}

func (c *mapCache) Delete(_ context.Context, k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, k)
}
func (c *mapCache) Flush()       {}
func (c *mapCache) Close() error { return nil }

func (c *mapCache) contains(s string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.data {
		if strings.Contains(k, s) || bytes.Contains(v, []byte(s)) {
			return true
		}
	}
	return false
}

func (c *mapCache) setCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sets
}

// vaultEnv is a full deps wiring for the vault tests.
type vaultEnv struct {
	deps    Dependencies
	site    *loginSite
	cache   *mapCache
	driver  *fakeLoginDriver
	consent *consent.StoreManager
	auditor *capturingAuditor
	logs    *bytes.Buffer
}

func canaryCookies() []cookievault.Cookie {
	return []cookievault.Cookie{{Name: "sid", Value: canaryValue, Domain: "." + vaultTestDomain, Path: "/", HTTPOnly: true}}
}

func newVaultEnv(t *testing.T) *vaultEnv {
	t.Helper()
	useFakeDNS(t, vaultTestHost)
	e := &vaultEnv{
		site:    newLoginSite(t),
		cache:   newMapCache(),
		driver:  &fakeLoginDriver{cookies: canaryCookies()},
		consent: consent.NewStoreManager(persist.NewMemoryStore()),
		auditor: &capturingAuditor{},
		logs:    &bytes.Buffer{},
	}
	e.deps = Dependencies{
		Cache:   e.cache,
		Search:  &mockProvider{},
		Scraper: scraper.NewPipeline(scraper.PipelineConfig{MaxConcurrency: 2, AllowPrivateIPs: true, ChromePath: "disabled", JinaDisabled: true}),
		Content: content.NewProcessor(),
		Sessions: func() session.Manager {
			m, _ := session.NewManager(session.Config{MaxSessions: 10})
			return m
		}(),
		Metrics:        metrics.NewCollector(),
		Auditor:        e.auditor,
		Logger:         slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Consent:        e.consent,
		CookieVault:    cookievault.NewPersistStore(persist.NewMemoryStore(), time.Hour),
		CookieCapturer: cookievault.NewCapturer(e.driver, nil, 1, time.Minute),
	}
	return e
}

func (e *vaultEnv) grant(t *testing.T, tenant, user string) {
	t.Helper()
	if err := e.consent.Record(context.Background(), consent.Record{
		TenantID: tenant, UserID: user, Purpose: consent.PurposeSessionCapture,
		Granted: true, DecidedAt: "2026-10-11T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
}

func (e *vaultEnv) seed(t *testing.T, tenant, user string) {
	t.Helper()
	if _, err := e.deps.CookieVault.Put(context.Background(), cookievault.Subject{TenantID: tenant, UserID: user}, vaultTestDomain, canaryCookies()); err != nil {
		t.Fatal(err)
	}
}

func (e *vaultEnv) client(t *testing.T, tenant, user string) *mcp.ClientSession {
	t.Helper()
	srv := createIdentityTestServer(e.deps, tenant, user)
	sess := connectTestClient(context.Background(), t, srv)
	t.Cleanup(func() { _ = sess.Close() })
	return sess
}

func callVaultTool(t *testing.T, sess *mcp.ClientSession, name string, args map[string]any) (map[string]any, string) {
	t.Helper()
	res, err := sess.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): %v", name, err)
	}
	if len(res.Content) == 0 {
		t.Fatalf("CallTool(%s): no content", name)
	}
	text := res.Content[0].(*mcp.TextContent).Text
	var out map[string]any
	_ = json.Unmarshal([]byte(text), &out)
	return out, text
}

func TestVaultBackedScrapeBypassesCache(t *testing.T) {
	e := newVaultEnv(t)
	e.grant(t, "default", "alice")
	e.seed(t, "default", "alice")
	sess := e.client(t, "default", "alice")

	for _, mode := range []string{"full", "preview", "raw"} {
		before := e.site.requestCount()
		for i := 0; i < 2; i++ {
			out, text := callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL(), "mode": mode})
			if out["authenticated"] != true {
				t.Fatalf("%s: authenticated = %v, want true (%s)", mode, out["authenticated"], text)
			}
			if !strings.Contains(text, privateMarker) {
				t.Fatalf("%s: private content missing", mode)
			}
		}
		if got := e.site.requestCount() - before; got < 2 {
			t.Errorf("%s: origin saw %d requests for 2 calls; the second was served from a cache", mode, got)
		}
	}
	if n := e.cache.setCount(); n != 0 {
		t.Errorf("cache received %d writes from vault-backed scrapes, want 0", n)
	}
	if e.cache.contains(privateMarker) {
		t.Error("authenticated content found in the cache")
	}
}

func TestAnonymousAfterAuthenticatedNeverServedFromCache(t *testing.T) {
	e := newVaultEnv(t)
	e.grant(t, "default", "alice")
	e.seed(t, "default", "alice")
	alice := e.client(t, "default", "alice")
	bob := e.client(t, "default", "bob")

	for _, mode := range []string{"full", "raw"} {
		if _, text := callVaultTool(t, alice, "scrape_page", map[string]any{"url": e.site.pageURL(), "mode": mode}); !strings.Contains(text, privateMarker) {
			t.Fatalf("%s: alice should see private content", mode)
		}
		out, text := callVaultTool(t, bob, "scrape_page", map[string]any{"url": e.site.pageURL(), "mode": mode})
		if strings.Contains(text, privateMarker) {
			t.Fatalf("%s: anonymous request after an authenticated one received private content", mode)
		}
		if !strings.Contains(text, publicMarker) {
			t.Fatalf("%s: bob should get the public page, got: %s", mode, text)
		}
		if _, set := out["authenticated"]; set {
			t.Errorf("%s: anonymous result must not carry the authenticated flag", mode)
		}
	}
}

func TestCanaryCookieNeverLeaks(t *testing.T) {
	e := newVaultEnv(t)
	e.grant(t, "default", "alice")
	sess := e.client(t, "default", "alice")

	var surfaces []string
	_, text := callVaultTool(t, sess, "site_login", map[string]any{"url": "http://" + vaultTestHost + "/login"})
	surfaces = append(surfaces, text)
	_, text = callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL()})
	surfaces = append(surfaces, text)
	_, text = callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL(), "mode": "raw"})
	surfaces = append(surfaces, text)

	// Data-subject export and every audit event and log line.
	exp, err := cookievault.AsDataSubject(e.deps.CookieVault).ExportSubject(context.Background(), datasubject.Subject{TenantID: "default", UserID: "alice"})
	if err != nil || exp == nil {
		t.Fatalf("export = %v, %v; want a summary", exp, err)
	}
	b, _ := json.Marshal(exp)
	surfaces = append(surfaces, string(b))
	e.auditor.mu.Lock()
	for _, ev := range e.auditor.events {
		eb, _ := json.Marshal(ev)
		surfaces = append(surfaces, string(eb))
	}
	e.auditor.mu.Unlock()
	surfaces = append(surfaces, e.logs.String())

	_, text = callVaultTool(t, sess, "site_logout", map[string]any{"domain": vaultTestHost})
	surfaces = append(surfaces, text)

	if !e.site.sawCookie() {
		t.Fatal("test is vacuous: the origin never received the session cookie")
	}
	for i, s := range surfaces {
		if strings.Contains(s, canaryValue) {
			t.Errorf("surface %d leaked the cookie value: %.200s", i, s)
		}
	}
}

func TestSiteLoginRequiresConsent(t *testing.T) {
	e := newVaultEnv(t)
	anon := e.client(t, "default", "anonymous")
	out, _ := callVaultTool(t, anon, "site_login", map[string]any{"url": "http://" + vaultTestHost + "/login"})
	if out["status"] != "unavailable" {
		t.Errorf("anonymous status = %v, want unavailable", out["status"])
	}

	alice := e.client(t, "default", "alice")
	out, _ = callVaultTool(t, alice, "site_login", map[string]any{"url": "http://" + vaultTestHost + "/login"})
	if out["status"] != "no_consent" {
		t.Errorf("status without consent = %v, want no_consent", out["status"])
	}
	if n := e.driver.openCount(); n != 0 {
		t.Errorf("browser opened %d times without consent", n)
	}
	if got := e.deps.CookieVault.List(context.Background(), cookievault.Subject{TenantID: "default", UserID: "alice"}); len(got) != 0 {
		t.Errorf("vault holds %d bundles without consent", len(got))
	}

	e.grant(t, "default", "alice")
	out, text := callVaultTool(t, alice, "site_login", map[string]any{"url": "http://" + vaultTestHost + "/login"})
	if out["status"] != "ok" || out["domain"] != vaultTestDomain {
		t.Fatalf("with consent: %s", text)
	}
	if out["cookieCount"] != float64(1) {
		t.Errorf("cookieCount = %v, want 1", out["cookieCount"])
	}
}

func TestScrapeSkipsVaultWithoutConsent(t *testing.T) {
	e := newVaultEnv(t)
	e.seed(t, "default", "alice") // bundle exists, consent was never granted
	sess := e.client(t, "default", "alice")
	out, text := callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL()})
	if strings.Contains(text, privateMarker) || out["authenticated"] == true {
		t.Fatalf("vault used without session_capture consent: %s", text)
	}
	if e.site.sawCookie() {
		t.Error("origin received a cookie without consent")
	}
}

func TestSiteLoginNotRegisteredWithoutCapturer(t *testing.T) {
	names := func(deps Dependencies) map[string]bool {
		sess := connectTestClient(context.Background(), t, createTestServer(deps))
		defer sess.Close()
		res, err := sess.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]bool{}
		for _, tl := range res.Tools {
			m[tl.Name] = true
		}
		return m
	}
	deps := setupTestDeps()
	deps.CookieCapturer = nil
	if got := names(deps); got["site_login"] || !got["site_logout"] {
		t.Errorf("no capturer: site_login=%v site_logout=%v, want false/true", got["site_login"], got["site_logout"])
	}
	deps.CookieVault = nil
	if got := names(deps); got["site_login"] || got["site_logout"] {
		t.Errorf("no vault: site_login=%v site_logout=%v, want false/false", got["site_login"], got["site_logout"])
	}
	if got := names(setupTestDeps()); !got["site_login"] || !got["site_logout"] {
		t.Error("with vault and capturer both tools must register")
	}
}

func TestSiteLogoutDeletesAndIsIdempotent(t *testing.T) {
	e := newVaultEnv(t)
	e.grant(t, "default", "alice")
	e.seed(t, "default", "alice")
	sess := e.client(t, "default", "alice")

	out, _ := callVaultTool(t, sess, "site_logout", map[string]any{"domain": "https://" + vaultTestHost + "/x"})
	if out["status"] != "ok" || out["removed"] != true || out["domain"] != vaultTestDomain {
		t.Fatalf("first logout = %v", out)
	}
	out, _ = callVaultTool(t, sess, "site_logout", map[string]any{"domain": vaultTestDomain})
	if out["status"] != "ok" || out["removed"] != false {
		t.Fatalf("second logout = %v, want ok/removed=false", out)
	}
	_, text := callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL()})
	if strings.Contains(text, privateMarker) {
		t.Error("scrape after logout still authenticated")
	}

	anon := e.client(t, "default", "anonymous")
	if out, _ := callVaultTool(t, anon, "site_logout", map[string]any{"domain": vaultTestDomain}); out["status"] != "unavailable" {
		t.Errorf("anonymous logout status = %v, want unavailable", out["status"])
	}
}

func TestSiteLogoutLeavesNoCacheEntries(t *testing.T) {
	e := newVaultEnv(t)
	e.grant(t, "default", "alice")
	e.seed(t, "default", "alice")
	sess := e.client(t, "default", "alice")
	for _, mode := range []string{"full", "raw"} {
		callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL(), "mode": mode})
	}
	callVaultTool(t, sess, "site_logout", map[string]any{"domain": vaultTestDomain})
	if e.cache.contains(privateMarker) || e.cache.contains("vaulttest") || e.cache.setCount() != 0 {
		t.Error("cache holds entries derived from the authenticated session")
	}
	if got := e.deps.CookieVault.List(context.Background(), cookievault.Subject{TenantID: "default", UserID: "alice"}); len(got) != 0 {
		t.Errorf("vault still lists %d bundles after logout", len(got))
	}
}

func TestSiteLoginRejectsBadURLs(t *testing.T) {
	e := newVaultEnv(t)
	e.deps.CookieCapturer = cookievault.NewCapturer(e.driver, func(ctx context.Context, h string) error {
		return scraper.ValidateHost(ctx, h, false)
	}, 1, time.Minute)
	e.grant(t, "default", "alice")
	sess := e.client(t, "default", "alice")

	cases := map[string]string{
		"ftp://" + vaultTestHost + "/":                  "invalid_url",
		"file:///etc/passwd":                            "invalid_url",
		"javascript:alert(1)":                           "invalid_url",
		"http://user:pw@" + vaultTestHost + "/":         "invalid_url",
		"http://127.0.0.1/login":                        "invalid_url",
		"http://localhost/login":                        "invalid_url",
		"http://169.254.169.254/latest/meta-data/":      "invalid_url",
		"http://" + vaultTestHost + "/login":            "blocked", // resolves to loopback
		"https://co.uk/login":                           "invalid_url",
		"http://[::1]/login":                            "invalid_url",
		"http://" + vaultTestHost + ".evil.invalid/x/y": "invalid_url",
	}
	for u, want := range cases {
		out, text := callVaultTool(t, sess, "site_login", map[string]any{"url": u})
		if out["status"] != want {
			t.Errorf("%s: status = %v, want %s (%s)", u, out["status"], want, text)
		}
	}
	if n := e.driver.openCount(); n != 0 {
		t.Errorf("browser opened %d times for rejected URLs", n)
	}
}

func TestSiteLoginDescriptionDisclosesToS(t *testing.T) {
	var desc string
	for _, tl := range listTools(t) {
		if tl.Name == "site_login" {
			desc = strings.ToLower(tl.Description)
		}
	}
	if desc == "" {
		t.Fatal("site_login is not registered in the default test deps")
	}
	for _, want := range []string{"terms of service", "cookies", "never your password", "session_capture", "site_logout", "encrypted", "ttl"} {
		if !strings.Contains(desc, want) {
			t.Errorf("site_login description does not mention %q", want)
		}
	}
}

// spyVault counts reads so a test can prove the vault was never consulted.
type spyVault struct {
	cookievault.Store
	gets atomic.Int32
}

func (s *spyVault) Get(ctx context.Context, sub cookievault.Subject, host string) (*cookievault.Bundle, bool) {
	s.gets.Add(1)
	return s.Store.Get(ctx, sub, host)
}

func TestNoVaultReadWhenDisabled(t *testing.T) {
	e := newVaultEnv(t)
	spy := &spyVault{Store: e.deps.CookieVault}
	e.deps.CookieVault = spy
	e.seed(t, "default", "alice")

	// No consent, anonymous identity and a non-identified tenant: no vault read.
	for _, who := range [][2]string{{"default", "alice"}, {"default", "anonymous"}} {
		sess := e.client(t, who[0], who[1])
		callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL()})
	}
	if n := spy.gets.Load(); n != 0 {
		t.Errorf("vault read %d times without identity+consent", n)
	}

	// Feature off entirely: scrape_page works and never panics on a nil vault.
	e.deps.CookieVault = nil
	e.deps.CookieCapturer = nil
	sess := e.client(t, "default", "alice")
	if _, text := callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL()}); !strings.Contains(text, publicMarker) {
		t.Errorf("scrape with the vault disabled failed: %s", text)
	}
}

// corruptingStore returns garbage for vault bundle reads once armed.
type corruptingStore struct {
	persist.Store
	armed atomic.Bool
}

func (c *corruptingStore) Get(ctx context.Context, key string) ([]byte, bool) {
	if c.armed.Load() && strings.HasPrefix(key, "cv:b:") {
		return []byte("\x00not-ciphertext-or-json"), true
	}
	return c.Store.Get(ctx, key)
}

func TestCorruptVaultEntryDegradesToAnonymous(t *testing.T) {
	e := newVaultEnv(t)
	kv := &corruptingStore{Store: persist.NewMemoryStore()}
	e.deps.CookieVault = cookievault.NewPersistStore(kv, time.Hour)
	e.grant(t, "default", "alice")
	e.seed(t, "default", "alice")
	kv.armed.Store(true)

	sess := e.client(t, "default", "alice")
	out, text := callVaultTool(t, sess, "scrape_page", map[string]any{"url": e.site.pageURL()})
	if out["authenticated"] == true || strings.Contains(text, privateMarker) {
		t.Fatalf("corrupt bundle was used: %s", text)
	}
	if !strings.Contains(text, publicMarker) {
		t.Errorf("scrape did not degrade to an anonymous result: %s", text)
	}
}

// sanity: audit events from the denial paths carry the identity but no input.
func TestSiteLoginDenialIsAudited(t *testing.T) {
	e := newVaultEnv(t)
	sess := e.client(t, "default", "alice")
	callVaultTool(t, sess, "site_login", map[string]any{"url": "http://" + vaultTestHost + "/login?token=" + canaryValue})
	e.auditor.mu.Lock()
	defer e.auditor.mu.Unlock()
	if len(e.auditor.events) != 1 {
		t.Fatalf("got %d audit events, want 1", len(e.auditor.events))
	}
	ev := e.auditor.events[0]
	b, _ := json.Marshal(ev)
	if ev.Success || ev.ErrorCode != "no_consent" || ev.ToolName != "site_login" || strings.Contains(string(b), canaryValue) {
		t.Errorf("unexpected audit event: %s", b)
	}
}
