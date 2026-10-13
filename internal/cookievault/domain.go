package cookievault

import (
	"net"
	"strings"
	"time"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// RegistrableDomain returns the eTLD+1 of host, lower-cased and punycoded, or ""
// when host has none. "" is returned for IP literals, single-label hosts,
// hosts under an unknown single-label TLD (localhost, .local, .internal, .test),
// bare public suffixes (co.uk) and malformed input. Every vault operation
// refuses an empty result, so lookalike and non-DNS hosts can never receive a
// stored login (see issue #241). A "host:port" form and a leading/trailing dot
// are tolerated; the vault key never includes the port.
func RegistrableDomain(host string) string {
	host = strings.TrimSpace(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]"), "."), ".")
	if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return ""
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(host))
	if err != nil || ascii == "" {
		return ""
	}
	suffix, icann := publicsuffix.PublicSuffix(ascii)
	if !icann && !strings.Contains(suffix, ".") {
		return "" // unknown single-label TLD such as "localhost" or "internal"
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil {
		return ""
	}
	return domain
}

// FilterToDomain returns the cookies that belong to the registrable domain
// domain and are still valid at now. A cookie belongs when its own Domain
// attribute (leading dot ignored) has the same registrable domain, which keeps
// a cookie for evil.com out of a linkedin.com bundle even if a capture or a
// stored entry carries it. Session cookies (zero Expires) are kept as-is. The
// input slice is not modified.
func FilterToDomain(cookies []Cookie, domain string, now time.Time) []Cookie {
	out := make([]Cookie, 0, len(cookies))
	for _, c := range cookies {
		if c.Name == "" || RegistrableDomain(c.Domain) != domain {
			continue
		}
		if !c.Expires.IsZero() && !c.Expires.After(now) {
			continue
		}
		out = append(out, c)
	}
	return out
}
