//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"

	"github.com/zoharbabin/web-researcher-mcp/internal/consent"
	"github.com/zoharbabin/web-researcher-mcp/internal/cookievault"
	"github.com/zoharbabin/web-researcher-mcp/internal/persist"
)

// The interactive part of site_login (a human signing in) cannot run in CI, so
// these tests seed a saved browser profile from the test process, exactly as the
// login window would store it, then drive the real binary against it (#775).
// The profile holds one persistent cookie; the origin shows members-only content
// only when it receives that cookie.

const (
	profileHost   = "app.localtest.me"
	profileDomain = "localtest.me"
)

// profileOrigin serves a members page only to requests that carry the canary cookie.
func profileOrigin(t *testing.T) (pageURL string, withCookie *atomic.Int32) {
	t.Helper()
	ips, err := net.DefaultResolver.LookupHost(context.Background(), profileHost)
	if err != nil || !slices.Contains(ips, "127.0.0.1") {
		t.Skipf("%s does not resolve to 127.0.0.1 here (%v %v)", profileHost, ips, err)
	}
	withCookie = new(atomic.Int32)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		body := strings.Repeat("<p>Shared filler paragraph so the extractor keeps this page as article content.</p>", 12)
		if c, cerr := r.Cookie("sid"); cerr == nil && c.Value == e2eCanary {
			withCookie.Add(1)
			fmt.Fprintf(w, "<html><head><title>Members dashboard</title></head><body><article><h1>Members dashboard</h1><p>MEMBERS-ONLY-MARKER welcome back.</p>%s</article></body></html>", body)
			return
		}
		fmt.Fprintf(w, "<html><head><title>Public page</title></head><body><article><h1>Public page</h1><p>PUBLIC-MARKER signed-out view.</p>%s</article></body></html>", body)
	}))
	t.Cleanup(origin.Close)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	return fmt.Sprintf("http://%s:%s/dashboard", profileHost, port), withCookie
}

// seedProfile stores a profile for sub that holds the canary cookie, and grants
// session_capture consent, in cacheDir (the dir the binary under test will use).
func seedProfile(t *testing.T, cacheDir string, sub cookievault.Subject) string {
	t.Helper()
	bin := cookievault.ResolveBrowser("")
	if bin == "" {
		t.Skip("no Chrome or Chromium installed")
	}
	ctx := context.Background()
	store, err := cookievault.NewProfileStore(filepath.Join(cacheDir, "profiles"), e2eVaultKey, time.Hour)
	if err != nil {
		t.Fatalf("profile store: %v", err)
	}
	lease, err := store.Begin(ctx, sub, profileHost)
	if err != nil {
		t.Fatalf("begin profile: %v", err)
	}
	defer lease.Discard()
	pb, err := cookievault.LaunchBrowser(cookievault.BrowserLaunch{Bin: bin, Dir: lease.Dir, Headless: true, NoSandbox: true})
	if err != nil {
		t.Fatalf("launch browser: %v", err)
	}
	err = pb.Browser.SetCookies([]*proto.NetworkCookieParam{{
		Name: "sid", Value: e2eCanary, Domain: "." + profileDomain, Path: "/",
		Expires: proto.TimeSinceEpoch(time.Now().Add(time.Hour).Unix()),
	}})
	pb.Shutdown() // waits for exit so the cookie reaches disk
	if err != nil {
		t.Fatalf("set cookie: %v", err)
	}
	lease.Meta.Browser = bin
	if _, err := lease.Commit(ctx); err != nil {
		t.Fatalf("commit profile: %v", err)
	}
	// Prove the seeded profile really holds the cookie before the binary runs.
	check, err := store.Acquire(ctx, sub, profileHost)
	if err != nil {
		t.Fatalf("reacquire seeded profile: %v", err)
	}
	defer check.Discard()
	held, err := cookievault.NewRodDriver(bin).ReadCookies(ctx, check.Dir)
	if err != nil {
		t.Fatalf("read seeded cookies: %v", err)
	}
	if !slices.ContainsFunc(held, func(c cookievault.Cookie) bool { return c.Name == "sid" && c.Value == e2eCanary }) {
		t.Fatalf("seeded profile does not hold the sid cookie: %d cookies", len(held))
	}

	consentKV, err := persist.NewDiskStore(filepath.Join(cacheDir, "persist"), e2eCacheKey, "")
	if err != nil {
		t.Fatalf("consent store: %v", err)
	}
	if err := consent.NewStoreManager(consentKV).Record(ctx, consent.Record{
		TenantID: sub.TenantID, UserID: sub.UserID, Purpose: consent.PurposeSessionCapture,
		Granted: true, DecidedAt: time.Now().UTC().Format(time.RFC3339), DecidedFrom: "e2e",
	}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}
	return bin
}

// toolText returns the text of the first content block of a tools/call result.
func toolText(t *testing.T, raw json.RawMessage) (string, map[string]any) {
	t.Helper()
	var res struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &res); err != nil || len(res.Content) == 0 {
		t.Fatalf("bad tool result %v raw=%s", err, raw)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(res.Content[0].Text), &out)
	return res.Content[0].Text, out
}

// runProfileScenario is the transport-independent flow. call invokes a tool and
// returns its raw result.
func runProfileScenario(t *testing.T, pageURL string, withCookie *atomic.Int32, call func(tool string, args map[string]any) json.RawMessage) {
	t.Helper()
	var transcript []string
	do := func(tool string, args map[string]any) (string, map[string]any) {
		t.Helper()
		raw := call(tool, args)
		transcript = append(transcript, string(raw))
		return toolText(t, raw)
	}

	text, out := do("scrape_page", map[string]any{"url": pageURL})
	if !strings.Contains(text, "MEMBERS-ONLY-MARKER") {
		t.Fatalf("saved profile was not used, got: %.300s", text)
	}
	if out["authenticated"] != true {
		t.Fatalf("authenticated = %v, want true", out["authenticated"])
	}

	hits := withCookie.Load()
	if text, _ = do("scrape_page", map[string]any{"url": pageURL}); !strings.Contains(text, "MEMBERS-ONLY-MARKER") {
		t.Fatalf("second profile scrape lost the sign-in, got: %.300s", text)
	}
	if withCookie.Load() <= hits {
		t.Fatal("second signed-in scrape was served from cache instead of the origin")
	}

	if text, out = do("scrape_page", map[string]any{"url": pageURL, "anonymous": true}); !strings.Contains(text, "PUBLIC-MARKER") || strings.Contains(text, "MEMBERS-ONLY-MARKER") || out["authenticated"] == true {
		t.Fatalf("anonymous=true must read the signed-out page, got: %.300s", text)
	}

	if text, _ = do("scrape_page", map[string]any{"url": pageURL, "mode": "raw"}); !strings.Contains(text, "mode=raw is not available with a saved browser profile") {
		t.Fatalf("raw mode with a profile must be refused, got: %.300s", text)
	}

	_, lo := do("site_logout", map[string]any{"domain": profileHost})
	if lo["status"] != "ok" || lo["removed"] != true || lo["removedProfile"] != true || lo["removedCookies"] != false {
		t.Fatalf("site_logout = %v", lo)
	}
	if after, _ := do("scrape_page", map[string]any{"url": pageURL}); !strings.Contains(after, "PUBLIC-MARKER") || strings.Contains(after, "MEMBERS-ONLY-MARKER") {
		t.Fatalf("after site_logout the page must be anonymous, got: %.300s", after)
	}
	if _, again := do("site_logout", map[string]any{"domain": profileHost}); again["removed"] != false {
		t.Fatalf("second site_logout should report removed=false, got %v", again)
	}

	for i, line := range transcript {
		if strings.Contains(line, e2eCanary) {
			t.Fatalf("cookie value leaked into tool output #%d", i)
		}
	}
}

func profileEnv(cacheDir, chrome string) []string {
	return []string{
		"COOKIE_VAULT_ENABLED=true",
		"COOKIE_VAULT_ENCRYPTION_KEY=" + e2eVaultKey,
		"CACHE_ENCRYPTION_KEY=" + e2eCacheKey,
		"CACHE_DIR=" + cacheDir,
		"ALLOW_PRIVATE_IPS=true",
		"CHROME_PATH=" + chrome,
		"GOOGLE_CUSTOM_SEARCH_API_KEY=test",
		"GOOGLE_CUSTOM_SEARCH_ID=test",
	}
}

// TestE2EProfileScrapeSTDIO: a saved profile signs scrape_page in over STDIO,
// anonymous=true and site_logout take it away, and nothing leaks (#775).
func TestE2EProfileScrapeSTDIO(t *testing.T) {
	pageURL, withCookie := profileOrigin(t)
	cacheDir := t.TempDir()
	bin := seedProfile(t, cacheDir, cookievault.Subject{TenantID: "default", UserID: "tester"})

	h := newProviderHarness(t, append(profileEnv(cacheDir, bin), "STDIO_USER_ID=tester"))
	defer h.shutdown()
	h.initialize(t)
	runProfileScenario(t, pageURL, withCookie, func(tool string, args map[string]any) json.RawMessage {
		return h.callTool(t, tool, args)
	})
}

// TestE2EProfileScrapeHTTP: the same flow over Streamable HTTP with OAuth, where
// the identity (tenant-abc, user-42) comes from the token and the profile is
// found under that subject.
func TestE2EProfileScrapeHTTP(t *testing.T) {
	pageURL, withCookie := profileOrigin(t)
	cacheDir := t.TempDir()
	bin := seedProfile(t, cacheDir, cookievault.Subject{TenantID: "tenant-abc", UserID: "user-42"})

	h, key, issuer := newOAuthHarness(t, profileEnv(cacheDir, bin)...)
	h.bearer(signRS256(t, key, oauthClaims(issuer, "")))
	h.initialize()
	id := 10
	runProfileScenario(t, pageURL, withCookie, func(tool string, args map[string]any) json.RawMessage {
		id++
		resp := h.callTool(id, tool, args)
		if resp.Error != nil {
			t.Fatalf("%s: %s", tool, resp.Error)
		}
		return resp.Result
	})
}

// TestE2EProfileScrapeAcrossIdentities: over HTTP, another tenant's token with
// the same user ID never gets the profile, and the origin never sees the cookie.
func TestE2EProfileScrapeAcrossIdentities(t *testing.T) {
	pageURL, withCookie := profileOrigin(t)
	cacheDir := t.TempDir()
	bin := seedProfile(t, cacheDir, cookievault.Subject{TenantID: "tenant-abc", UserID: "user-42"})

	h, key, issuer := newOAuthHarness(t, profileEnv(cacheDir, bin)...)
	claims := oauthClaims(issuer, "")
	claims["tenant_id"] = "tenant-other" // same sub (user-42), different tenant
	h.bearer(signRS256(t, key, claims))
	h.initialize()

	resp := h.callTool(11, "scrape_page", map[string]any{"url": pageURL})
	if resp.Error != nil {
		t.Fatalf("scrape_page: %s", resp.Error)
	}
	text, out := toolText(t, resp.Result)
	if strings.Contains(text, "MEMBERS-ONLY-MARKER") || out["authenticated"] == true {
		t.Fatalf("another tenant must not use the profile, got: %.300s", text)
	}
	if withCookie.Load() != 0 {
		t.Fatal("origin received the canary cookie for another tenant")
	}
}

// TestE2ESiteLoginRegistrationByTransport: site_logout follows the vault in both
// modes; site_login is registered over STDIO, and over HTTP only with the
// explicit COOKIE_CAPTURE_IN_HTTP opt-in (and a display where one is needed).
func TestE2ESiteLoginRegistrationByTransport(t *testing.T) {
	base := func(extra ...string) []string {
		return append(profileEnv(t.TempDir(), "/nonexistent-chrome-for-registration-test"), extra...)
	}
	has := func(names []string, want string) bool { return slices.Contains(names, want) }

	httpTools := func(env ...string) []string {
		h, key, issuer := newOAuthHarness(t, env...)
		h.bearer(signRS256(t, key, oauthClaims(issuer, "")))
		h.initialize()
		resp := h.rpc(jsonRPCRequest{JSONRPC: "2.0", ID: 2, Method: "tools/list"})
		if resp.Error != nil {
			t.Fatalf("tools/list: %s", resp.Error)
		}
		var res struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, tl := range res.Tools {
			names = append(names, tl.Name)
		}
		return names
	}

	t.Run("http default has logout but no login", func(t *testing.T) {
		names := httpTools(base()...)
		if !has(names, "site_logout") || has(names, "site_login") {
			t.Fatalf("site_logout=%v site_login=%v, want true/false", has(names, "site_logout"), has(names, "site_login"))
		}
	})

	t.Run("http opt-in registers login where a display exists", func(t *testing.T) {
		names := httpTools(base("COOKIE_CAPTURE_IN_HTTP=true")...)
		displayless := runtime.GOOS == "linux" && !hasLinuxDisplay()
		if has(names, "site_login") == displayless {
			t.Fatalf("site_login registered=%v on %s (display=%v)", has(names, "site_login"), runtime.GOOS, !displayless)
		}
	})

	t.Run("stdio registers login", func(t *testing.T) {
		h := newProviderHarness(t, append(base(), "STDIO_USER_ID=tester"))
		defer h.shutdown()
		h.initialize(t)
		resp := h.rpc(t, "tools/list", map[string]any{})
		if !strings.Contains(string(resp.Result), `"site_login"`) || !strings.Contains(string(resp.Result), `"site_logout"`) {
			t.Fatalf("tools/list over STDIO lacks the login tools: %.300s", resp.Result)
		}
	})
}

func hasLinuxDisplay() bool {
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}
