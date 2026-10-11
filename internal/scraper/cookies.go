package scraper

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"

	"github.com/go-rod/rod/lib/proto"
	"golang.org/x/net/publicsuffix"

	"github.com/zoharbabin/web-researcher-mcp/internal/cookievault"
)

type cookiesCtxKey struct{}

// WithCookies returns a context that makes this one scrape send the given vault
// cookies (see issue #241). Cookies travel in the context, never in Pipeline
// state, so concurrent scrapes cannot see each other's cookies. An empty slice
// returns ctx unchanged.
func WithCookies(ctx context.Context, cookies []cookievault.Cookie) context.Context {
	if len(cookies) == 0 {
		return ctx
	}
	return context.WithValue(ctx, cookiesCtxKey{}, cookies)
}

func cookiesFrom(ctx context.Context) []cookievault.Cookie {
	c, _ := ctx.Value(cookiesCtxKey{}).([]cookievault.Cookie)
	return c
}

// newCookieJar builds a throwaway jar holding cookies. The jar, not our code,
// decides which requests carry which cookie: host-only vs domain match, path,
// Secure (https only) and expiry are all enforced per request, including on
// every redirect hop.
func newCookieJar(cookies []cookievault.Cookie, now time.Time) (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}
	for _, c := range cookies {
		if !c.Expires.IsZero() && !c.Expires.After(now) {
			continue
		}
		host := strings.TrimPrefix(c.Domain, ".")
		if host == "" {
			continue
		}
		hc := &http.Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Path:     cookiePath(c.Path),
			Secure:   c.Secure,
			HttpOnly: c.HTTPOnly,
			Expires:  c.Expires, // zero stays a session cookie
		}
		if !c.HostOnly {
			hc.Domain = host
		}
		jar.SetCookies(&url.URL{Scheme: "https", Host: host, Path: "/"}, []*http.Cookie{hc})
	}
	return jar, nil
}

func cookiePath(p string) string {
	if !strings.HasPrefix(p, "/") {
		return "/"
	}
	return p
}

// clientWithCookies returns base unchanged when ctx carries no cookies.
// Otherwise it returns a copy of base with a fresh per-request jar. The copy
// shares base's transport, so SSRF dial-time validation still applies.
func clientWithCookies(ctx context.Context, base *http.Client) (*http.Client, error) {
	cookies := cookiesFrom(ctx)
	if len(cookies) == 0 {
		return base, nil
	}
	jar, err := newCookieJar(cookies, time.Now())
	if err != nil {
		return nil, err
	}
	c := *base
	c.Jar = jar
	return &c, nil
}

// toCDPCookies converts vault cookies to Chrome DevTools params. Expired cookies
// are dropped and session cookies keep a zero expiry so Chrome keeps them
// session-scoped. Host-only cookies are set by URL (Chrome then makes them
// host-only); domain cookies by domain.
func toCDPCookies(cookies []cookievault.Cookie, now time.Time) []*proto.NetworkCookieParam {
	out := make([]*proto.NetworkCookieParam, 0, len(cookies))
	for _, c := range cookies {
		if !c.Expires.IsZero() && !c.Expires.After(now) {
			continue
		}
		host := strings.TrimPrefix(c.Domain, ".")
		if host == "" {
			continue
		}
		p := &proto.NetworkCookieParam{
			Name:     c.Name,
			Value:    c.Value,
			Path:     cookiePath(c.Path),
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
		}
		if c.HostOnly {
			p.URL = "https://" + host + p.Path
		} else {
			p.Domain = "." + host
		}
		if !c.Expires.IsZero() {
			p.Expires = proto.TimeSinceEpoch(float64(c.Expires.Unix()))
		}
		switch strings.ToLower(c.SameSite) {
		case "strict":
			p.SameSite = proto.NetworkCookieSameSiteStrict
		case "lax":
			p.SameSite = proto.NetworkCookieSameSiteLax
		case "none":
			p.SameSite = proto.NetworkCookieSameSiteNone
		}
		out = append(out, p)
	}
	return out
}
