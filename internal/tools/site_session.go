package tools

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/zoharbabin/web-researcher-mcp/internal/auth"
	"github.com/zoharbabin/web-researcher-mcp/internal/consent"
	"github.com/zoharbabin/web-researcher-mcp/internal/cookievault"
)

type siteLoginInput struct {
	URL string `json:"url" jsonschema:"The login page URL (http or https) of the site you want scrape_page to read while signed in. A browser window opens on this page.,required"`
}

type siteLogoutInput struct {
	Domain string `json:"domain" jsonschema:"The site to forget: a hostname (e.g. example.com) or a URL on it. Removes the saved login for that site's registrable domain.,required"`
}

// vaultSubject returns the caller's vault subject, or false when the request has
// no identified user. Identity comes from the request context only (#241).
func vaultSubject(ctx context.Context) (cookievault.Subject, bool) {
	s := cookievault.Subject{TenantID: auth.TenantIDFromContext(ctx), UserID: auth.UserIDFromContext(ctx)}
	if s.TenantID == "" || s.UserID == "" || s.UserID == "anonymous" {
		return s, false
	}
	return s, true
}

// vaultCookiesFor returns the caller's saved login cookies for rawURL's site, or
// nil. It returns nil, and never reads the vault, unless the vault is enabled, the
// caller is identified and the caller has consented to session_capture. A missing,
// expired or corrupt bundle also reads as nil, so the scrape degrades to anonymous.
func vaultCookiesFor(ctx context.Context, deps Dependencies, rawURL string) []cookievault.Cookie {
	if deps.CookieVault == nil {
		return nil
	}
	subj, ok := vaultSubject(ctx)
	if !ok {
		return nil
	}
	if deps.Consent == nil || !deps.Consent.HasConsent(ctx, consent.PurposeSessionCapture) {
		return nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	b, found := deps.CookieVault.Get(ctx, subj, u.Hostname())
	if !found {
		return nil
	}
	return b.Cookies
}

// registerSiteLogin registers the WRITE tool that captures a login (#241). A
// human signs in inside a visible browser; only the resulting cookies are kept,
// encrypted, for scrape_page. Consent-gated on the session_capture purpose.
func registerSiteLogin(srv *mcp.Server, deps Dependencies) {
	addTool(srv, &mcp.Tool{
		Name: "site_login",
		Description: "Sign in to a website so scrape_page can read pages that need a login. " +
			"First it tries your own running Chrome, Edge or Brave: if you turned on remote debugging (chrome://inspect/#remote-debugging) and click Allow in the browser, it reads only that one site's cookies from your existing signed-in session and disconnects. It never reads other sites and never closes your browser. " +
			"If that is unavailable, or you are not signed in to the site there, it opens a visible window on the URL you give; you log in by hand (including 2FA or CAPTCHA) and close the window. " +
			"The result's source says which path was used (browser or login_window). Only cookies are saved, never your password. Cookies are stored encrypted, scoped to that site's registrable domain, " +
			"sent only to that site by scrape_page, expire on a short default TTL, and can be removed any time with site_logout or the data-subject erasure endpoint. " +
			"Blocks until the cookies are read, you close the login window, or the capture timeout passes (then nothing is saved). " +
			"Opt-in and consent-gated: requires the 'session_capture' consent purpose, which is never granted by default (the operator must opt in explicitly). " +
			"Use only on accounts and sites whose terms of service allow automated access on your behalf; you are responsible for that.",
		Annotations:  writeAnnotations(false),
		OutputSchema: siteLoginOutputSchema,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input siteLoginInput) (*mcp.CallToolResult, any, error) {
		start := time.Now()
		input.URL = strings.TrimSpace(input.URL)
		if input.URL == "" {
			return toolError("url is required"), nil, nil
		}
		subj, ok := vaultSubject(ctx)
		if !ok {
			auditToolDenial(ctx, deps, "site_login", time.Since(start), "unauthenticated")
			return structuredResult(mustJSON(map[string]any{"status": "unavailable", "reason": "site_login requires an identified user"})), nil, nil
		}
		if deps.Consent == nil || !deps.Consent.HasConsent(ctx, consent.PurposeSessionCapture) {
			auditToolDenial(ctx, deps, "site_login", time.Since(start), "no_consent")
			return structuredResult(mustJSON(map[string]any{"status": "no_consent", "reason": "no recorded consent for the 'session_capture' purpose; nothing is captured. In STDIO the operator grants it by setting COOKIE_VAULT_STDIO_CONSENT=true"})), nil, nil
		}

		domain, cookies, src, err := deps.CookieCapturer.CaptureWithSource(ctx, input.URL)
		if err != nil {
			return siteLoginFailure(ctx, deps, start, err), nil, nil
		}
		sum, err := deps.CookieVault.Put(ctx, subj, domain, cookies)
		if err != nil {
			if errors.Is(err, cookievault.ErrNoCookies) {
				return siteLoginFailure(ctx, deps, start, cookievault.ErrNothingCaptured), nil, nil
			}
			recordToolCall(deps, "site_login", time.Since(start), err, "upstream_error", false)
			auditToolCall(ctx, deps, "site_login", time.Since(start), err, "upstream_error")
			return toolError("could not save the login: " + err.Error()), nil, nil
		}
		recordToolCall(deps, "site_login", time.Since(start), nil, "", false)
		auditToolCall(ctx, deps, "site_login", time.Since(start), nil, "")
		return structuredResult(mustJSON(map[string]any{
			"status": "ok", "domain": sum.Domain, "cookieCount": sum.CookieCount,
			"capturedAt": sum.CapturedAt, "expiresAt": sum.ExpiresAt, "source": string(src),
		})), nil, nil
	})
}

// siteLoginFailure maps a capture error to a tool result and records the call.
// Messages are fixed strings: no URL query, cookie or upstream detail is echoed.
func siteLoginFailure(ctx context.Context, deps Dependencies, start time.Time, err error) *mcp.CallToolResult {
	status, msg := "failed", "login capture failed"
	switch {
	case errors.Is(err, cookievault.ErrCaptureBusy):
		status, msg = "busy", "another login window is already open; close it and try again"
	case errors.Is(err, cookievault.ErrCaptureTimeout):
		status, msg = "timeout", "the login window was not closed in time; nothing was saved"
	case errors.Is(err, cookievault.ErrInvalidLoginURL):
		status, msg = "invalid_url", "the login URL must be an http(s) URL on a site with a registrable domain, without credentials"
	case errors.Is(err, cookievault.ErrNothingCaptured):
		status, msg = "nothing_captured", "no cookies were captured for that site; nothing was saved"
	case errors.Is(err, cookievault.ErrLoginURLRejected):
		status, msg = "blocked", "that host is not allowed (private or internal address)"
	}
	recordToolCall(deps, "site_login", time.Since(start), err, "capture_"+status, false)
	auditToolCall(ctx, deps, "site_login", time.Since(start), errors.New(status), "capture_"+status)
	return structuredResult(mustJSON(map[string]any{"status": status, "reason": msg}))
}

// registerSiteLogout registers the WRITE tool that removes a saved login (#241).
// It needs an identified user but no consent: erasure is always allowed.
func registerSiteLogout(srv *mcp.Server, deps Dependencies) {
	addTool(srv, &mcp.Tool{
		Name:         "site_logout",
		Description:  "Forget the saved login for a site (saved earlier with site_login): deletes the stored cookies for that site's registrable domain. Idempotent: reports removed=false when nothing was saved. Scrapes made with a saved login are never cached, so there is no cached page content to clear. Needs no consent.",
		Annotations:  writeAnnotations(true),
		OutputSchema: siteLogoutOutputSchema,
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input siteLogoutInput) (*mcp.CallToolResult, any, error) {
		start := time.Now()
		host := siteHost(input.Domain)
		if host == "" {
			return toolError("domain is required (a hostname such as example.com, or a URL on it)"), nil, nil
		}
		subj, ok := vaultSubject(ctx)
		if !ok {
			auditToolDenial(ctx, deps, "site_logout", time.Since(start), "unauthenticated")
			return structuredResult(mustJSON(map[string]any{"status": "unavailable", "reason": "site_logout requires an identified user"})), nil, nil
		}
		removed, err := deps.CookieVault.Delete(ctx, subj, host)
		if err != nil {
			if errors.Is(err, cookievault.ErrInvalidDomain) {
				return toolError("that host has no registrable domain"), nil, nil
			}
			recordToolCall(deps, "site_logout", time.Since(start), err, "upstream_error", false)
			auditToolCall(ctx, deps, "site_logout", time.Since(start), err, "upstream_error")
			return upstreamErrorResponse("site_logout", err), nil, nil
		}
		recordToolCall(deps, "site_logout", time.Since(start), nil, "", false)
		auditToolCall(ctx, deps, "site_logout", time.Since(start), nil, "")
		return structuredResult(mustJSON(map[string]any{
			"status": "ok", "domain": cookievault.RegistrableDomain(host), "removed": removed,
		})), nil, nil
	})
}

// siteHost reduces a hostname or URL to its hostname ("" when unusable).
func siteHost(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	return strings.TrimSuffix(strings.ToLower(s), ".")
}
