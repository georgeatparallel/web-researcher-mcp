package cookievault

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zoharbabin/web-researcher-mcp/internal/cache"
)

// Profile store tuning (see issue #775).
const (
	// DefaultProfileTTL is the absolute lifetime of a stored profile.
	DefaultProfileTTL = 168 * time.Hour
	// MaxProfilesPerSubject bounds disk use per user.
	MaxProfilesPerSubject = 10

	profileMinGap    = 5 * time.Second
	profileLockWait  = 30 * time.Second
	staleWorkDirAge  = time.Hour
	profileFileExt   = ".wrp"
	profileAADPrefix = "wrmcp-profile-v1|"
)

// Errors returned by ProfileStore.
var (
	ErrNoProfile        = errors.New("cookievault: no saved browser profile for this site")
	ErrProfileBusy      = errors.New("cookievault: this site's browser profile is in use")
	ErrTooManyProfiles  = errors.New("cookievault: too many saved browser profiles")
	errProfileKeyNeeded = errors.New("cookievault: profile encryption key is required")
)

// ProfileSummary is the only view of a stored profile allowed in logs, audit
// events, tool output and data-subject exports.
type ProfileSummary struct {
	Domain    string `json:"domain"`
	CreatedAt string `json:"createdAt"`
	ExpiresAt string `json:"expiresAt"`
}

func (m ProfileMeta) summary() ProfileSummary {
	return ProfileSummary{
		Domain:    m.Domain,
		CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339),
		ExpiresAt: m.ExpiresAt.UTC().Format(time.RFC3339),
	}
}

// keyState is the per-profile lock, spacing clock and erase generation.
type keyState struct {
	sem     chan struct{}
	refs    int
	lastEnd time.Time
	gen     int
}

// ProfileStore keeps each user's browser profile as an encrypted archive, one
// per (tenant, user, registrable domain). A profile is unpacked into a private
// work dir only while a login or a scrape uses it (ProfileLease), and is
// repacked afterwards. Archives are node-local. State is per instance.
type ProfileStore struct {
	dir     string
	workDir string
	gcm     cipher.AEAD
	ttl     time.Duration
	clock   func() time.Time
	// wait sleeps for d or until ctx ends; replaceable in tests.
	wait     func(ctx context.Context, d time.Duration) error
	minGap   time.Duration
	lockWait time.Duration

	mu   sync.Mutex
	keys map[string]*keyState
}

// NewProfileStore opens (creating if needed) the archive directory dir, sealed
// with the 64-hex-character key. ttl is the absolute lifetime of an archive.
// Work dirs left behind by a crash and expired archives are removed now.
// Construction launches no browser.
func NewProfileStore(dir, hexKey string, ttl time.Duration) (*ProfileStore, error) {
	if hexKey == "" {
		return nil, errProfileKeyNeeded
	}
	gcm, err := cache.NewGCM(hexKey)
	if err != nil {
		return nil, fmt.Errorf("profile store key: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultProfileTTL
	}
	work := filepath.Join(dir, "work")
	for _, d := range []string{dir, work} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, fmt.Errorf("profile store dir: %w", err)
		}
		if err := os.Chmod(d, 0o700); err != nil { // #nosec G302 -- directory: owner-only, needs the execute bit
			return nil, fmt.Errorf("profile store dir: %w", err)
		}
	}
	s := &ProfileStore{
		dir: dir, workDir: work, gcm: gcm, ttl: ttl,
		clock: time.Now, wait: sleepCtx, minGap: profileMinGap, lockWait: profileLockWait,
		keys: map[string]*keyState{},
	}
	s.sweep()
	return s, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sweep removes stale work dirs and expired or unreadable archives.
func (s *ProfileStore) sweep() {
	now := s.clock()
	if entries, err := os.ReadDir(s.workDir); err == nil {
		for _, e := range entries {
			if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > staleWorkDirAge {
				_ = os.RemoveAll(filepath.Join(s.workDir, e.Name()))
			}
		}
	}
	entries, _ := os.ReadDir(s.dir)
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".tmp"):
			if info, err := e.Info(); err == nil && now.Sub(info.ModTime()) > staleWorkDirAge {
				_ = os.Remove(filepath.Join(s.dir, name))
			}
		case strings.HasSuffix(name, profileFileExt):
			s.dropIfDead(strings.TrimSuffix(name, profileFileExt))
		}
	}
}

// dropIfDead deletes the archive for key when it is expired or unreadable. It
// holds s.mu so it cannot delete an archive a Commit just renamed into place.
func (s *ProfileStore) dropIfDead(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.readMeta(key); !ok {
		_ = os.Remove(s.path(key))
	}
}

func profileKey(sub Subject, domain string) string {
	return hashPart(sub.TenantID) + "." + hashPart(sub.UserID) + "." + hashPart(domain)
}

func subjectPrefix(sub Subject) string {
	return hashPart(sub.TenantID) + "." + hashPart(sub.UserID) + "."
}

func (s *ProfileStore) path(key string) string { return filepath.Join(s.dir, key+profileFileExt) }

func profileAAD(key string) []byte { return []byte(profileAADPrefix + key) }

// readMeta returns the live meta for key; expired and unreadable read as false.
func (s *ProfileStore) readMeta(key string) (ProfileMeta, bool) {
	f, err := os.Open(s.path(key))
	if err != nil {
		return ProfileMeta{}, false
	}
	defer func() { _ = f.Close() }()
	meta, err := readProfileMeta(f, s.gcm, profileAAD(key))
	if err != nil || !meta.ExpiresAt.After(s.clock()) {
		return ProfileMeta{}, false
	}
	return meta, true
}

// resolve validates sub and host and returns the domain and storage key.
func resolve(sub Subject, host string) (domain, key string, err error) {
	if !sub.valid() {
		return "", "", ErrNoSubject
	}
	domain = RegistrableDomain(host)
	if domain == "" {
		return "", "", ErrInvalidDomain
	}
	return domain, profileKey(sub, domain), nil
}

// state returns the keyState for key, creating it, and prunes idle ones.
// The caller holds s.mu.
func (s *ProfileStore) state(key string) *keyState {
	now := s.clock()
	for k, ks := range s.keys {
		if k != key && ks.refs == 0 && now.Sub(ks.lastEnd) > s.minGap {
			delete(s.keys, k)
		}
	}
	ks := s.keys[key]
	if ks == nil {
		ks = &keyState{sem: make(chan struct{}, 1)}
		s.keys[key] = ks
	}
	return ks
}

// lock takes the profile's single-user lock and waits out the minimum gap since
// its last use. It returns ErrProfileBusy after lockWait.
func (s *ProfileStore) lock(ctx context.Context, key string) (*keyState, error) {
	s.mu.Lock()
	ks := s.state(key)
	ks.refs++
	s.mu.Unlock()

	giveUp := func() {
		s.mu.Lock()
		ks.refs--
		s.mu.Unlock()
	}
	lockCtx, cancel := context.WithTimeout(ctx, s.lockWait)
	defer cancel()
	select {
	case ks.sem <- struct{}{}:
	case <-lockCtx.Done():
		giveUp()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, ErrProfileBusy
	}
	s.mu.Lock()
	gap := s.minGap - s.clock().Sub(ks.lastEnd)
	s.mu.Unlock()
	if gap > 0 {
		if err := s.wait(ctx, gap); err != nil {
			s.unlock(ks)
			return nil, err
		}
	}
	return ks, nil
}

func (s *ProfileStore) unlock(ks *keyState) {
	s.mu.Lock()
	ks.lastEnd = s.clock()
	ks.refs--
	s.mu.Unlock()
	<-ks.sem
}

// ProfileLease is exclusive use of one subject's profile for one login or one
// scrape. Dir holds the unpacked profile. The caller must end the lease with
// Commit (keep changes) or Discard; both are safe to call again and both remove Dir.
type ProfileLease struct {
	// Dir is the private work dir holding the unpacked profile.
	Dir string
	// Meta describes the profile; set Meta.Browser before committing a login.
	Meta ProfileMeta
	// Fresh is true when no usable archive existed and Dir is empty.
	Fresh bool

	store *ProfileStore
	key   string
	ks    *keyState
	gen   int
	once  sync.Once
}

// Acquire leases the saved profile for host's registrable domain, unpacked
// into a private work dir. It returns ErrNoProfile when there is none (an
// expired or unreadable archive is deleted), and ErrProfileBusy when another
// login or scrape holds it for longer than 30 s.
func (s *ProfileStore) Acquire(ctx context.Context, sub Subject, host string) (*ProfileLease, error) {
	domain, key, err := resolve(sub, host)
	if err != nil {
		return nil, err
	}
	if _, ok := s.readMeta(key); !ok {
		s.dropIfDead(key)
		return nil, ErrNoProfile
	}
	lease, err := s.begin(ctx, key, domain)
	if err != nil {
		return nil, err
	}
	if lease.Fresh {
		lease.Discard()
		return nil, ErrNoProfile
	}
	return lease, nil
}

// Begin leases the profile for a login. It unpacks the saved profile when one
// exists so the user can sign in again over it; otherwise Dir is empty and
// Fresh is true. A new login always gets a new absolute lifetime.
func (s *ProfileStore) Begin(ctx context.Context, sub Subject, host string) (*ProfileLease, error) {
	domain, key, err := resolve(sub, host)
	if err != nil {
		return nil, err
	}
	if _, ok := s.readMeta(key); !ok {
		s.dropIfDead(key)
		if s.countFor(sub) >= MaxProfilesPerSubject {
			return nil, ErrTooManyProfiles
		}
	}
	lease, err := s.begin(ctx, key, domain)
	if err != nil {
		return nil, err
	}
	now := s.clock()
	lease.Meta.CreatedAt, lease.Meta.ExpiresAt = now, now.Add(s.ttl)
	return lease, nil
}

func (s *ProfileStore) begin(ctx context.Context, key, domain string) (*ProfileLease, error) {
	ks, err := s.lock(ctx, key)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(s.workDir, "p-*")
	if err != nil {
		s.unlock(ks)
		return nil, fmt.Errorf("create profile work dir: %w", err)
	}
	s.mu.Lock()
	gen := ks.gen
	s.mu.Unlock()
	l := &ProfileLease{Dir: dir, store: s, key: key, ks: ks, gen: gen, Fresh: true,
		Meta: ProfileMeta{Domain: domain, CreatedAt: s.clock(), ExpiresAt: s.clock().Add(s.ttl)}}

	f, err := os.Open(s.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return l, nil
	}
	if err != nil {
		l.Discard()
		return nil, err
	}
	defer func() { _ = f.Close() }()
	meta, err := extractProfileArchive(f, s.gcm, profileAAD(key), dir)
	if err != nil || meta.Domain != domain || !meta.ExpiresAt.After(s.clock()) {
		// Unreadable, mismatched or expired: start over with an empty profile.
		slog.Warn("saved browser profile unreadable; starting fresh", "domain", domain)
		_ = os.RemoveAll(dir)
		if err := os.Mkdir(dir, 0o700); err != nil {
			l.Discard()
			return nil, err
		}
		return l, nil
	}
	l.Meta, l.Fresh = meta, false
	return l, nil
}

// countFor counts the subject's live archives.
func (s *ProfileStore) countFor(sub Subject) int {
	n := 0
	for _, k := range s.keysFor(sub) {
		if _, ok := s.readMeta(k); ok {
			n++
		}
	}
	return n
}

func (s *ProfileStore) keysFor(sub Subject) []string {
	matches, _ := filepath.Glob(filepath.Join(s.dir, subjectPrefix(sub)+"*"+profileFileExt))
	keys := make([]string, 0, len(matches))
	for _, m := range matches {
		keys = append(keys, strings.TrimSuffix(filepath.Base(m), profileFileExt))
	}
	return keys
}

// Commit repacks Dir into the encrypted archive (replacing the old one),
// removes Dir and ends the lease. The profile keeps its original expiry unless
// it came from Begin. If the profile was deleted while leased, nothing is
// written and ErrNoProfile is returned. The browser must be closed first.
func (l *ProfileLease) Commit(ctx context.Context) (ProfileSummary, error) {
	var sum ProfileSummary
	err := ErrNoProfile
	l.once.Do(func() {
		defer l.end()
		sum, err = l.store.commit(ctx, l)
	})
	return sum, err
}

// Discard removes Dir and ends the lease without saving. Idempotent.
func (l *ProfileLease) Discard() { l.once.Do(l.end) }

func (l *ProfileLease) end() {
	_ = os.RemoveAll(l.Dir)
	l.store.unlock(l.ks)
}

func (s *ProfileStore) commit(ctx context.Context, l *ProfileLease) (ProfileSummary, error) {
	if err := ctx.Err(); err != nil {
		return ProfileSummary{}, err
	}
	tmp, err := os.CreateTemp(s.dir, "w-*.tmp")
	if err != nil {
		return ProfileSummary{}, fmt.Errorf("write profile archive: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	werr := writeProfileArchive(tmp, s.gcm, profileAAD(l.key), l.Dir, l.Meta)
	if werr == nil {
		werr = tmp.Sync()
	}
	if err := errors.Join(werr, tmp.Close()); err != nil {
		cleanup()
		if errors.Is(err, ErrProfileTooLarge) {
			return ProfileSummary{}, ErrProfileTooLarge
		}
		return ProfileSummary{}, fmt.Errorf("write profile archive: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.ks.gen != l.gen {
		cleanup()
		return ProfileSummary{}, ErrNoProfile
	}
	if err := os.Rename(tmpName, s.path(l.key)); err != nil {
		cleanup()
		return ProfileSummary{}, fmt.Errorf("store profile archive: %w", err)
	}
	return l.Meta.summary(), nil
}

// Delete removes the saved profile for host's registrable domain and reports
// whether one existed. A login or scrape in flight will not recreate it.
func (s *ProfileStore) Delete(ctx context.Context, sub Subject, host string) (bool, error) {
	_, key, err := resolve(sub, host)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteLocked(key), nil
}

func (s *ProfileStore) deleteLocked(key string) bool {
	if ks := s.keys[key]; ks != nil {
		ks.gen++
	}
	err := os.Remove(s.path(key))
	return err == nil
}

// List returns redacted summaries of the subject's live profiles.
func (s *ProfileStore) List(ctx context.Context, sub Subject) []ProfileSummary {
	out := []ProfileSummary{}
	if !sub.valid() {
		return out
	}
	for _, k := range s.keysFor(sub) {
		if m, ok := s.readMeta(k); ok {
			out = append(out, m.summary())
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Domain < out[j].Domain })
	return out
}

// EraseAll removes every profile of the subject and returns how many.
func (s *ProfileStore) EraseAll(ctx context.Context, sub Subject) (int, error) {
	if !sub.valid() {
		return 0, ErrNoSubject
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, k := range s.keysFor(sub) {
		if s.deleteLocked(k) {
			n++
		}
	}
	return n, nil
}
