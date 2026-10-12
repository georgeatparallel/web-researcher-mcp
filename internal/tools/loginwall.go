package tools

import (
	"net/url"
	"regexp"

	"github.com/zoharbabin/web-researcher-mcp/internal/cookievault"
)

// loginWallMaxWords is the most words a page may have and still count as a
// login wall. Real login walls are a form and a footer.
const loginWallMaxWords = 150

var (
	loginPathRe  = regexp.MustCompile(`(?i)/(log-?in|sign-?in|sign-?up|auth|checkpoint)\b`)
	signInCueRe  = regexp.MustCompile(`(?i)\b(sign[ -]?in|log[ -]?in)\b`)
	passwordCue  = regexp.MustCompile(`(?i)\bpassword\b`)
	loginWallTop = 2000 // bytes of body inspected; a wall is thin, so this covers it
)

// looksLikeLoginWall reports whether a scraped page is probably a sign-in page
// instead of the content asked for. It is a heuristic: a thin page whose title
// names sign-in, or whose text asks for a password next to a sign-in prompt.
// A request for a login page itself is never flagged.
func looksLikeLoginWall(requestedURL, title, body string, words int) bool {
	if words >= loginWallMaxWords {
		return false
	}
	if u, err := url.Parse(requestedURL); err == nil && loginPathRe.MatchString(u.Path) {
		return false
	}
	if signInCueRe.MatchString(title) {
		return true
	}
	if len(body) > loginWallTop {
		body = body[:loginWallTop]
	}
	return passwordCue.MatchString(body) && signInCueRe.MatchString(body)
}

// loginHintFor returns the next step for an agent that hit a login wall, or ""
// when site_login is not available (it registers only with a vault and a
// capturer). authed says saved cookies were already sent, so the login is
// stale or was rejected rather than missing.
func loginHintFor(deps Dependencies, authed bool, rawURL string) string {
	if deps.CookieVault == nil || deps.CookieCapturer == nil {
		return ""
	}
	site := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		if d := cookievault.RegistrableDomain(u.Hostname()); d != "" {
			site = d
		}
	}
	if authed {
		return "The saved login for " + site + " looks expired or was rejected. Call site_login with the site's login URL to sign in again, then retry."
	}
	return "This page needs a login. To read it as you, call site_login with " + site + "'s login URL, then retry."
}
