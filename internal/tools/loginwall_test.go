package tools

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLooksLikeLoginWall(t *testing.T) {
	t.Parallel()
	const wall = "Sign in\n\nEmail or phone\nPassword\nForgot password?\nKeep me signed in\nSign in\n\nNew to LinkedIn? Join now"
	cases := []struct {
		name, url, title, body string
		words                  int
		want                   bool
	}{
		{"linkedin wall", "https://www.linkedin.com/feed/", "LinkedIn Login, Sign in | LinkedIn", wall, 56, true},
		{"facebook wall", "https://www.facebook.com/me", "Log into Facebook", "Log in to Facebook\nEmail\nPassword\nLog In", 30, true},
		{"title only", "https://x.com/home", "Sign in to X", "Something went wrong.", 4, true},
		{"body cues only", "https://example.com/account", "Account", "Please log in. Password:", 5, true},
		{"long page mentioning sign in", "https://example.com/blog", "How to sign in", strings.Repeat("word ", 400) + "sign in password", 400, false},
		{"thin page without cues", "https://example.com/a", "Empty", "Nothing here.", 2, false},
		{"password alone", "https://example.com/a", "Tips", "Use a strong password.", 5, false},
		{"login page requested on purpose", "https://example.com/login", "Sign in", wall, 20, false},
		{"signin path", "https://example.com/users/sign-in", "Sign in", wall, 20, false},
	}
	for _, c := range cases {
		if got := looksLikeLoginWall(c.url, c.title, c.body, c.words); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestLoginHintForNeedsSiteLogin(t *testing.T) {
	t.Parallel()
	if got := loginHintFor(Dependencies{}, false, "https://www.linkedin.com/feed/"); got != "" {
		t.Fatalf("no vault: hint = %q, want empty", got)
	}
	e := newVaultEnv(t)
	d := e.deps
	d.CookieCapturer = nil
	if got := loginHintFor(d, false, "https://www.linkedin.com/feed/"); got != "" {
		t.Fatalf("no capturer: hint = %q, want empty", got)
	}
	missing := loginHintFor(e.deps, false, "https://www.linkedin.com/feed/")
	stale := loginHintFor(e.deps, true, "https://www.linkedin.com/feed/")
	for _, h := range []string{missing, stale} {
		if !strings.Contains(h, "site_login") || !strings.Contains(h, "linkedin.com") {
			t.Errorf("hint %q must name site_login and the registrable domain", h)
		}
	}
	if !strings.Contains(stale, "expired") || strings.Contains(missing, "expired") {
		t.Errorf("stale and missing hints must differ: %q / %q", stale, missing)
	}
}

// wallSite serves a thin sign-in page (or a 401) at a vaulttest.com host.
func wallSite(t *testing.T, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(status)
		_, _ = w.Write([]byte("<html><head><title>Sign in | Example</title></head><body><main><h1>Sign in</h1><form><label>Email</label><label>Password</label><button>Sign in</button></form></main></body></html>"))
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	return "http://" + vaultTestHost + ":" + port + "/feed"
}

func TestScrapeFlagsLoginWallWithAndWithoutSavedLogin(t *testing.T) {
	e := newVaultEnv(t)
	e.grant(t, "default", "alice")
	url := wallSite(t, http.StatusOK)

	anon := e.client(t, "default", "bob")
	out, text := callVaultTool(t, anon, "scrape_page", map[string]any{"url": url})
	if out["loginRequired"] != true || !strings.Contains(out["loginHint"].(string), "needs a login") {
		t.Fatalf("no saved login: loginRequired/loginHint missing: %s", text)
	}
	if out["authenticated"] == true {
		t.Fatal("authenticated must not be set without a saved login")
	}

	e.seed(t, "default", "alice")
	alice := e.client(t, "default", "alice")
	out, text = callVaultTool(t, alice, "scrape_page", map[string]any{"url": url})
	if out["authenticated"] != true || out["loginRequired"] != true || !strings.Contains(out["loginHint"].(string), "expired") {
		t.Fatalf("stale saved login: want authenticated + loginRequired + expired hint: %s", text)
	}
	if strings.Contains(text, canaryValue) {
		t.Fatal("cookie value leaked into the result")
	}
}

func TestScrapeDoesNotFlagRealPageOrVaultlessServer(t *testing.T) {
	e := newVaultEnv(t)
	e.grant(t, "default", "alice")
	e.seed(t, "default", "alice")
	alice := e.client(t, "default", "alice")
	out, text := callVaultTool(t, alice, "scrape_page", map[string]any{"url": e.site.pageURL()})
	if _, ok := out["loginRequired"]; ok {
		t.Fatalf("a real page must not be flagged: %s", text)
	}

	e2 := newVaultEnv(t)
	e2.deps.CookieVault, e2.deps.CookieCapturer = nil, nil
	c := e2.client(t, "default", "bob")
	out, text = callVaultTool(t, c, "scrape_page", map[string]any{"url": wallSite(t, http.StatusOK)})
	if _, ok := out["loginRequired"]; ok {
		t.Fatalf("without site_login the hint must be absent: %s", text)
	}
}

func TestScrapeAuthErrorNamesSiteLogin(t *testing.T) {
	e := newVaultEnv(t)
	e.grant(t, "default", "alice")
	url := wallSite(t, http.StatusUnauthorized)
	_, text := callVaultTool(t, e.client(t, "default", "bob"), "scrape_page", map[string]any{"url": url})
	if !strings.Contains(text, "behind a login wall") || !strings.Contains(text, "site_login") {
		t.Fatalf("401 without a saved login should point to site_login: %s", text)
	}

	e.seed(t, "default", "alice")
	_, text = callVaultTool(t, e.client(t, "default", "alice"), "scrape_page", map[string]any{"url": url})
	if !strings.Contains(text, "expired") {
		t.Fatalf("401 with a saved login should say it looks expired: %s", text)
	}
}
