//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zoharbabin/web-researcher-mcp/internal/consent"
	"github.com/zoharbabin/web-researcher-mcp/internal/cookievault"
	"github.com/zoharbabin/web-researcher-mcp/internal/persist"
)

const (
	e2eCacheKey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	e2eVaultKey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	e2eCanary   = "CANARY-sid-7f3a9c1e"
)

// TestSiteLogin241_E2E drives the real binary over STDIO against a login-gated
// origin. The vault and consent are pre-seeded through the same encrypted stores
// the binary opens, because the headed browser login is a manual step (#241).
// It proves: a consenting user's saved login is sent and the page is read; an
// unconsented user, and the same user after site_logout, get the anonymous page;
// the cookie value never appears in any tool output.
func TestSiteLogin241_E2E(t *testing.T) {
	const host = "app.localtest.me"
	ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil || !slices.Contains(ips, "127.0.0.1") {
		t.Skipf("%s does not resolve to 127.0.0.1 here (%v %v)", host, ips, err)
	}

	var withCookie, withoutCookie atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		body := strings.Repeat("<p>Shared filler paragraph so the extractor keeps this page as article content.</p>", 12)
		if c, cerr := r.Cookie("sid"); cerr == nil && c.Value == e2eCanary {
			withCookie.Add(1)
			fmt.Fprintf(w, "<html><head><title>Members dashboard</title></head><body><article><h1>Members dashboard</h1><p>MEMBERS-ONLY-MARKER welcome back.</p>%s</article></body></html>", body)
			return
		}
		withoutCookie.Add(1)
		fmt.Fprintf(w, "<html><head><title>Please sign in</title></head><body><article><h1>Please sign in</h1><p>PUBLIC-LOGIN-WALL-MARKER sign in to continue.</p>%s</article></body></html>", body)
	}))
	defer origin.Close()
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	pageURL := fmt.Sprintf("http://%s:%s/dashboard", host, port)

	cacheDir := t.TempDir()
	ctx := context.Background()

	vaultKV, err := persist.NewDiskStore(filepath.Join(cacheDir, "cookievault"), e2eVaultKey, "")
	if err != nil {
		t.Fatalf("vault store: %v", err)
	}
	vault := cookievault.NewPersistStore(vaultKV, time.Hour)
	if _, err := vault.Put(ctx, cookievault.Subject{TenantID: "default", UserID: "tester"}, "localtest.me",
		[]cookievault.Cookie{{Name: "sid", Value: e2eCanary, Domain: "localtest.me", Path: "/"}}); err != nil {
		t.Fatalf("seed vault: %v", err)
	}
	consentKV, err := persist.NewDiskStore(filepath.Join(cacheDir, "persist"), e2eCacheKey, "")
	if err != nil {
		t.Fatalf("consent store: %v", err)
	}
	if err := consent.NewStoreManager(consentKV).Record(ctx, consent.Record{
		TenantID: "default", UserID: "tester", Purpose: consent.PurposeSessionCapture,
		Granted: true, DecidedAt: time.Now().UTC().Format(time.RFC3339), DecidedFrom: "e2e",
	}); err != nil {
		t.Fatalf("seed consent: %v", err)
	}

	env := func(user string) []string {
		return []string{
			"COOKIE_VAULT_ENABLED=true",
			"COOKIE_VAULT_ENCRYPTION_KEY=" + e2eVaultKey,
			"CACHE_ENCRYPTION_KEY=" + e2eCacheKey,
			"CACHE_DIR=" + cacheDir,
			"ALLOW_PRIVATE_IPS=true",
			"STDIO_USER_ID=" + user,
			"GOOGLE_CUSTOM_SEARCH_API_KEY=test",
			"GOOGLE_CUSTOM_SEARCH_ID=test",
		}
	}
	var transcript []string
	call := func(h *providerHarness, tool string, args map[string]any) (string, map[string]any) {
		t.Helper()
		raw := h.callTool(t, tool, args)
		transcript = append(transcript, string(raw))
		var res struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		if err := json.Unmarshal(raw, &res); err != nil || len(res.Content) == 0 {
			t.Fatalf("%s: bad result %v raw=%s", tool, err, raw)
		}
		var out map[string]any
		_ = json.Unmarshal([]byte(res.Content[0].Text), &out)
		return res.Content[0].Text, out
	}

	t.Run("user without consent gets the anonymous page and no_consent", func(t *testing.T) {
		before := withCookie.Load()
		h := newProviderHarness(t, env("other"))
		defer h.shutdown()
		h.initialize(t)

		text, out := call(h, "scrape_page", map[string]any{"url": pageURL})
		if !strings.Contains(text, "PUBLIC-LOGIN-WALL-MARKER") || strings.Contains(text, "MEMBERS-ONLY-MARKER") {
			t.Fatalf("unconsented user must see the login wall, got: %.300s", text)
		}
		if out["authenticated"] == true {
			t.Fatal("authenticated must not be set without a saved login and consent")
		}
		_, login := call(h, "site_login", map[string]any{"url": "http://" + host + ":" + port + "/login"})
		if login["status"] != "no_consent" {
			t.Fatalf("site_login status = %v, want no_consent", login["status"])
		}
		if withCookie.Load() != before {
			t.Fatal("origin received the canary cookie for an unconsented user")
		}
	})

	t.Run("consenting user reads the page signed in, then site_logout removes it", func(t *testing.T) {
		h := newProviderHarness(t, env("tester"))
		defer h.shutdown()
		h.initialize(t)

		text, out := call(h, "scrape_page", map[string]any{"url": pageURL})
		if !strings.Contains(text, "MEMBERS-ONLY-MARKER") {
			t.Fatalf("saved login was not applied, got: %.300s", text)
		}
		if out["authenticated"] != true {
			t.Fatalf("authenticated = %v, want true", out["authenticated"])
		}
		hits := withCookie.Load()
		if _, _ = call(h, "scrape_page", map[string]any{"url": pageURL}); withCookie.Load() <= hits {
			t.Fatal("second signed-in scrape was served from cache instead of the origin")
		}

		_, lo := call(h, "site_logout", map[string]any{"domain": host})
		if lo["status"] != "ok" || lo["removed"] != true || lo["domain"] != "localtest.me" {
			t.Fatalf("site_logout = %v", lo)
		}
		after, _ := call(h, "scrape_page", map[string]any{"url": pageURL})
		if !strings.Contains(after, "PUBLIC-LOGIN-WALL-MARKER") || strings.Contains(after, "MEMBERS-ONLY-MARKER") {
			t.Fatalf("after site_logout the page must be anonymous, got: %.300s", after)
		}
		_, again := call(h, "site_logout", map[string]any{"domain": host})
		if again["removed"] != false {
			t.Fatalf("second site_logout should report removed=false, got %v", again)
		}
	})

	for i, line := range transcript {
		if strings.Contains(line, e2eCanary) {
			t.Fatalf("cookie value leaked into tool output #%d", i)
		}
	}
}

// TestSiteLoginStdioConsentOptIn_E2E proves the STDIO consent opt-in end to end
// with the real binary and no seeded consent. site_login is aimed at
// localtest.me (a registrable domain that resolves to loopback), which the
// capturer rejects before opening any browser: "blocked" means the consent
// gate passed, "no_consent" means it did not.
func TestSiteLoginStdioConsentOptIn_E2E(t *testing.T) {
	cases := []struct {
		name, optIn, want string
	}{
		{"default grants nothing", "", "no_consent"},
		{"explicit opt-in grants session_capture", "true", "blocked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := []string{
				"COOKIE_VAULT_ENABLED=true",
				"COOKIE_VAULT_ENCRYPTION_KEY=" + e2eVaultKey,
				"CACHE_ENCRYPTION_KEY=" + e2eCacheKey,
				"CACHE_DIR=" + t.TempDir(),
				"STDIO_USER_ID=optin",
				"GOOGLE_CUSTOM_SEARCH_API_KEY=test",
				"GOOGLE_CUSTOM_SEARCH_ID=test",
			}
			if tc.optIn != "" {
				env = append(env, "COOKIE_VAULT_STDIO_CONSENT="+tc.optIn)
			}
			h := newProviderHarness(t, env)
			defer h.shutdown()
			h.initialize(t)

			raw := h.callTool(t, "site_login", map[string]any{"url": "http://localtest.me/login"})
			var res struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			}
			if err := json.Unmarshal(raw, &res); err != nil || len(res.Content) == 0 {
				t.Fatalf("bad result %v raw=%s", err, raw)
			}
			var out map[string]any
			_ = json.Unmarshal([]byte(res.Content[0].Text), &out)
			if out["status"] != tc.want {
				t.Fatalf("site_login status = %v, want %s (raw: %.300s)", out["status"], tc.want, res.Content[0].Text)
			}
		})
	}
}
