// Package cookievault stores a user's login cookies, encrypted at rest, so
// scrape_page can read login-gated pages (see issue #241). A human logs in once
// in a real browser; only the resulting cookies are kept, never credentials.
//
// Bundles are keyed by (tenant, user, registrable domain) with every component
// hashed, so one user's logins are never visible to another tenant or user.
// Cookie names and values never leave this package except through Get (for
// injection into a request). Every log, audit and export surface uses Summary.
package cookievault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/zoharbabin/web-researcher-mcp/internal/persist"
)

// Size caps. Browsers allow 4096 bytes per cookie; 150 cookies is far above a
// real login. The bundle cap bounds one persist.Store value.
const (
	MaxCookiesPerBundle = 150
	MaxCookieBytes      = 4096
	MaxBundleBytes      = 256 << 10
)

// Errors returned by Store.
var (
	ErrInvalidDomain  = errors.New("cookievault: host has no registrable domain")
	ErrNoSubject      = errors.New("cookievault: no identified user")
	ErrNoCookies      = errors.New("cookievault: no valid cookies for this domain")
	ErrTooManyCookies = errors.New("cookievault: too many cookies")
	ErrCookieTooLarge = errors.New("cookievault: cookie too large")
	ErrBundleTooLarge = errors.New("cookievault: bundle too large")
)

// Cookie is one stored cookie. A zero Expires means a session cookie, which must
// stay session-scoped when injected. HostOnly cookies match only their exact
// host; others (Domain had a leading dot) also match subdomains.
type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Domain   string    `json:"domain"`
	Path     string    `json:"path"`
	Expires  time.Time `json:"expires,omitzero"`
	Secure   bool      `json:"secure,omitempty"`
	HTTPOnly bool      `json:"httpOnly,omitempty"`
	HostOnly bool      `json:"hostOnly,omitempty"`
	SameSite string    `json:"sameSite,omitempty"` // "", "Lax", "Strict" or "None"
}

// Bundle is the cookie set captured for one registrable domain.
type Bundle struct {
	Domain     string    `json:"domain"`
	CapturedAt time.Time `json:"capturedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
	Cookies    []Cookie  `json:"cookies"`
}

// Summary is the only view of a bundle allowed in logs, audit events, tool
// output and data-subject exports: no cookie names or values.
type Summary struct {
	Domain      string `json:"domain"`
	CapturedAt  string `json:"capturedAt"`
	ExpiresAt   string `json:"expiresAt"`
	CookieCount int    `json:"cookieCount"`
}

// Summary returns the redacted view of b.
func (b *Bundle) Summary() Summary {
	return Summary{
		Domain:      b.Domain,
		CapturedAt:  b.CapturedAt.UTC().Format(time.RFC3339),
		ExpiresAt:   b.ExpiresAt.UTC().Format(time.RFC3339),
		CookieCount: len(b.Cookies),
	}
}

// Subject identifies whose vault is addressed. Both fields come from the
// request's authenticated identity, never from tool input.
type Subject struct {
	TenantID string
	UserID   string
}

func (s Subject) valid() bool {
	return s.TenantID != "" && s.UserID != "" && s.UserID != "anonymous"
}

// Store is the cookie vault. host arguments may be a hostname (any subdomain of
// the target) and are reduced to their registrable domain.
type Store interface {
	// Put replaces the bundle for host's registrable domain with the valid
	// cookies in cookies and returns its summary.
	Put(ctx context.Context, s Subject, host string, cookies []Cookie) (Summary, error)
	// Get returns the live bundle for host's registrable domain. Missing,
	// expired, undecryptable and corrupt entries all read as (nil, false).
	Get(ctx context.Context, s Subject, host string) (*Bundle, bool)
	// Delete removes the bundle and reports whether one existed. Idempotent.
	Delete(ctx context.Context, s Subject, host string) (bool, error)
	// List returns redacted summaries of the subject's live bundles.
	List(ctx context.Context, s Subject) []Summary
	// EraseAll removes every bundle for the subject and returns how many.
	EraseAll(ctx context.Context, s Subject) (int, error)
}

// PersistStore is the Store backed by a persist.Store (encrypted disk in
// production). It is safe for concurrent use; the mutex only serializes the
// per-subject domain index update.
type PersistStore struct {
	mu    sync.Mutex
	kv    persist.Store
	ttl   time.Duration
	clock func() time.Time
}

// NewPersistStore wraps kv. ttl is the maximum lifetime of any bundle.
func NewPersistStore(kv persist.Store, ttl time.Duration) *PersistStore {
	return &PersistStore{kv: kv, ttl: ttl, clock: time.Now}
}

func hashPart(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// bundleKey hashes each component before joining, so no tenant/user/domain
// value can contain a separator that shifts a boundary.
func bundleKey(s Subject, domain string) string {
	return "cv:b:" + hashPart(s.TenantID) + "." + hashPart(s.UserID) + "." + hashPart(domain)
}

func indexKey(s Subject) string {
	return "cv:i:" + hashPart(s.TenantID) + "." + hashPart(s.UserID)
}

func (p *PersistStore) Put(ctx context.Context, s Subject, host string, cookies []Cookie) (Summary, error) {
	if !s.valid() {
		return Summary{}, ErrNoSubject
	}
	domain := RegistrableDomain(host)
	if domain == "" {
		return Summary{}, ErrInvalidDomain
	}
	now := p.clock()
	kept := FilterToDomain(cookies, domain, now)
	if len(kept) == 0 {
		return Summary{}, ErrNoCookies
	}
	if len(kept) > MaxCookiesPerBundle {
		return Summary{}, ErrTooManyCookies
	}
	latest, allPersistent := time.Time{}, true
	for _, c := range kept {
		if len(c.Name)+len(c.Value) > MaxCookieBytes {
			return Summary{}, ErrCookieTooLarge
		}
		if c.Expires.IsZero() {
			allPersistent = false
		} else if c.Expires.After(latest) {
			latest = c.Expires
		}
	}
	// The bundle never outlives COOKIE_VAULT_TTL, session cookies included, and
	// never outlives its last persistent cookie.
	expiresAt := now.Add(p.ttl)
	if allPersistent && latest.Before(expiresAt) {
		expiresAt = latest
	}
	b := Bundle{Domain: domain, CapturedAt: now, ExpiresAt: expiresAt, Cookies: kept}
	data, err := json.Marshal(b)
	if err != nil {
		return Summary{}, err
	}
	if len(data) > MaxBundleBytes {
		return Summary{}, ErrBundleTooLarge
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.kv.Set(ctx, bundleKey(s, domain), data, expiresAt.Sub(now))
	p.addToIndex(ctx, s, domain)
	return b.Summary(), nil
}

func (p *PersistStore) Get(ctx context.Context, s Subject, host string) (*Bundle, bool) {
	if !s.valid() {
		return nil, false
	}
	domain := RegistrableDomain(host)
	if domain == "" {
		return nil, false
	}
	return p.load(ctx, s, domain)
}

// load reads and re-validates one bundle. The domain re-check guards against a
// stored entry that does not match its key.
func (p *PersistStore) load(ctx context.Context, s Subject, domain string) (*Bundle, bool) {
	data, ok := p.kv.Get(ctx, bundleKey(s, domain))
	if !ok {
		return nil, false
	}
	var b Bundle
	if err := json.Unmarshal(data, &b); err != nil || b.Domain != domain {
		return nil, false
	}
	now := p.clock()
	if !b.ExpiresAt.After(now) {
		return nil, false
	}
	b.Cookies = FilterToDomain(b.Cookies, domain, now)
	if len(b.Cookies) == 0 {
		return nil, false
	}
	return &b, true
}

func (p *PersistStore) Delete(ctx context.Context, s Subject, host string) (bool, error) {
	if !s.valid() {
		return false, ErrNoSubject
	}
	domain := RegistrableDomain(host)
	if domain == "" {
		return false, ErrInvalidDomain
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, existed := p.kv.Get(ctx, bundleKey(s, domain))
	p.kv.Delete(ctx, bundleKey(s, domain))
	p.removeFromIndex(ctx, s, domain)
	return existed, nil
}

func (p *PersistStore) List(ctx context.Context, s Subject) []Summary {
	if !s.valid() {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []Summary{}
	live := []string{}
	for _, d := range p.readIndex(ctx, s) {
		if b, ok := p.load(ctx, s, d); ok {
			out = append(out, b.Summary())
			live = append(live, d)
		}
	}
	p.writeIndex(ctx, s, live) // prune expired entries from the index
	return out
}

func (p *PersistStore) EraseAll(ctx context.Context, s Subject) (int, error) {
	if !s.valid() {
		return 0, ErrNoSubject
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, d := range p.readIndex(ctx, s) {
		if _, ok := p.kv.Get(ctx, bundleKey(s, d)); ok {
			n++
		}
		p.kv.Delete(ctx, bundleKey(s, d))
	}
	p.kv.Delete(ctx, indexKey(s))
	return n, nil
}

func (p *PersistStore) readIndex(ctx context.Context, s Subject) []string {
	data, ok := p.kv.Get(ctx, indexKey(s))
	if !ok {
		return nil
	}
	var domains []string
	if json.Unmarshal(data, &domains) != nil {
		return nil
	}
	return domains
}

func (p *PersistStore) writeIndex(ctx context.Context, s Subject, domains []string) {
	if len(domains) == 0 {
		p.kv.Delete(ctx, indexKey(s))
		return
	}
	sort.Strings(domains)
	data, _ := json.Marshal(domains)
	p.kv.Set(ctx, indexKey(s), data, p.ttl)
}

func (p *PersistStore) addToIndex(ctx context.Context, s Subject, domain string) {
	domains := p.readIndex(ctx, s)
	for _, d := range domains {
		if d == domain {
			return
		}
	}
	p.writeIndex(ctx, s, append(domains, domain))
}

func (p *PersistStore) removeFromIndex(ctx context.Context, s Subject, domain string) {
	kept := []string{}
	for _, d := range p.readIndex(ctx, s) {
		if d != domain {
			kept = append(kept, d)
		}
	}
	p.writeIndex(ctx, s, kept)
}

var _ Store = (*PersistStore)(nil)
