package cookievault

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zoharbabin/web-researcher-mcp/internal/datasubject"
	"github.com/zoharbabin/web-researcher-mcp/internal/persist"
)

const (
	keyA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	keyB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var (
	alice = Subject{TenantID: "t1", UserID: "alice"}
	bob   = Subject{TenantID: "t1", UserID: "bob"}
)

func newStore(t *testing.T, ttl time.Duration) (*PersistStore, *time.Time) {
	t.Helper()
	s := NewPersistStore(persist.NewMemoryStore(), ttl)
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s.clock = func() time.Time { return now }
	return s, &now
}

func sessionCookie(name, value, domain string) Cookie {
	return Cookie{Name: name, Value: value, Domain: domain, Path: "/", Secure: true}
}

func TestRegistrableDomain(t *testing.T) {
	cases := []struct{ host, want string }{
		{"linkedin.com", "linkedin.com"},
		{"www.linkedin.com", "linkedin.com"},
		{"WWW.LinkedIn.COM.", "linkedin.com"},
		{"www.linkedin.com:8443", "linkedin.com"},
		{"a.b.example.co.uk", "example.co.uk"},
		{"foo.github.io", "foo.github.io"},
		{"bücher.de", "xn--bcher-kva.de"},
		{"xn--bcher-kva.de", "xn--bcher-kva.de"},
		{"evil-linkedin.com", "evil-linkedin.com"},
		{"linkedin.com.evil.net", "evil.net"},
		// no registrable domain
		{"", ""},
		{"localhost", ""},
		{"app.localhost", ""},
		{"printer.local", ""},
		{"svc.internal", ""},
		{"foo.test", ""},
		{"co.uk", ""},
		{"com", ""},
		{"127.0.0.1", ""},
		{"10.0.0.5:80", ""},
		{"::1", ""},
		{"[::1]", ""},
		{"[2001:db8::1]:443", ""},
		{"169.254.169.254", ""},
		{"exa mple.com", ""},
		{"http://example.com", ""},
		{"example.com/path", ""},
		{"..", ""},
		{"a..com", ""},
	}
	for _, tc := range cases {
		if got := RegistrableDomain(tc.host); got != tc.want {
			t.Errorf("RegistrableDomain(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

func TestVaultRefusesInvalidDomains(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	ctx := context.Background()
	for _, host := range []string{"", "localhost", "127.0.0.1", "::1", "co.uk", "x.internal"} {
		if _, err := s.Put(ctx, alice, host, []Cookie{sessionCookie("a", "v", "example.com")}); !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("Put(%q) err = %v, want ErrInvalidDomain", host, err)
		}
		if _, ok := s.Get(ctx, alice, host); ok {
			t.Errorf("Get(%q) returned a bundle", host)
		}
		if _, err := s.Delete(ctx, alice, host); !errors.Is(err, ErrInvalidDomain) {
			t.Errorf("Delete(%q) err = %v, want ErrInvalidDomain", host, err)
		}
	}
	for _, bad := range []Subject{{}, {TenantID: "t1"}, {UserID: "u"}, {TenantID: "t1", UserID: "anonymous"}} {
		if _, err := s.Put(ctx, bad, "example.com", []Cookie{sessionCookie("a", "v", "example.com")}); !errors.Is(err, ErrNoSubject) {
			t.Errorf("Put(subject=%+v) err = %v, want ErrNoSubject", bad, err)
		}
		if _, ok := s.Get(ctx, bad, "example.com"); ok {
			t.Errorf("Get(subject=%+v) returned a bundle", bad)
		}
	}
}

func TestCookieOutsideVaultDomainDropped(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	ctx := context.Background()
	in := []Cookie{
		sessionCookie("good", "1", ".linkedin.com"),
		sessionCookie("sub", "2", "www.linkedin.com"),
		sessionCookie("lookalike", "3", "evil-linkedin.com"),
		sessionCookie("suffix", "4", "linkedin.com.evil.net"),
		sessionCookie("other", "5", ".evil.com"),
		sessionCookie("empty", "6", ""),
		sessionCookie("ip", "7", "127.0.0.1"),
	}
	sum, err := s.Put(ctx, alice, "www.linkedin.com", in)
	if err != nil {
		t.Fatal(err)
	}
	if sum.CookieCount != 2 {
		t.Fatalf("cookieCount = %d, want 2", sum.CookieCount)
	}
	b, ok := s.Get(ctx, alice, "linkedin.com")
	if !ok || len(b.Cookies) != 2 {
		t.Fatalf("Get = %+v, %v", b, ok)
	}
	for _, c := range b.Cookies {
		if c.Name != "good" && c.Name != "sub" {
			t.Errorf("foreign cookie %q kept", c.Name)
		}
	}
	// Only foreign cookies: nothing to store.
	if _, err := s.Put(ctx, alice, "linkedin.com", in[2:]); !errors.Is(err, ErrNoCookies) {
		t.Errorf("err = %v, want ErrNoCookies", err)
	}
	// A bundle looked up under another domain is not found.
	if _, ok := s.Get(ctx, alice, "evil-linkedin.com"); ok {
		t.Error("lookalike domain read a linkedin.com bundle")
	}
}

func TestVaultKeyCollisionFree(t *testing.T) {
	tenants := []string{"a", "a|b", "a.b", "a:b", "a/b", "", "t", "t1"}
	users := []string{"b|c", "c", "b", "u", "1", ""}
	domains := []string{"example.com", "example.com.", "x.example.com", "example.org"}
	seen := map[string]string{}
	for _, tn := range tenants {
		for _, u := range users {
			for _, d := range domains {
				k := bundleKey(Subject{TenantID: tn, UserID: u}, d)
				id := tn + "\x00" + u + "\x00" + d
				if prev, dup := seen[k]; dup {
					t.Fatalf("key collision between %q and %q", prev, id)
				}
				seen[k] = id
			}
		}
	}
	if indexKey(alice) == indexKey(bob) {
		t.Error("index keys collide")
	}
}

func TestVaultTenantUserIsolation(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	ctx := context.Background()
	if _, err := s.Put(ctx, alice, "example.com", []Cookie{sessionCookie("sid", "alice-secret", "example.com")}); err != nil {
		t.Fatal(err)
	}
	other := []Subject{bob, {TenantID: "t2", UserID: "alice"}}
	for _, o := range other {
		if _, ok := s.Get(ctx, o, "example.com"); ok {
			t.Errorf("subject %+v read alice's bundle", o)
		}
		if got := s.List(ctx, o); len(got) != 0 {
			t.Errorf("subject %+v lists %v", o, got)
		}
		if existed, _ := s.Delete(ctx, o, "example.com"); existed {
			t.Errorf("subject %+v deleted alice's bundle", o)
		}
		if n, _ := s.EraseAll(ctx, o); n != 0 {
			t.Errorf("subject %+v erased %d of alice's bundles", o, n)
		}
	}
	if _, ok := s.Get(ctx, alice, "example.com"); !ok {
		t.Error("alice's bundle was lost")
	}
}

func TestMultiInstanceCookieVault(t *testing.T) {
	a, _ := newStore(t, time.Hour)
	b, _ := newStore(t, time.Minute)
	ctx := context.Background()
	if _, err := a.Put(ctx, alice, "example.com", []Cookie{sessionCookie("sid", "v", "example.com")}); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Get(ctx, alice, "example.com"); ok {
		t.Error("instance B sees instance A's bundle")
	}
	if got := b.List(ctx, alice); len(got) != 0 {
		t.Errorf("instance B lists %v", got)
	}
	if _, err := b.Put(ctx, alice, "example.com", []Cookie{sessionCookie("sid", "other", "example.com")}); err != nil {
		t.Fatal(err)
	}
	ba, _ := a.Get(ctx, alice, "example.com")
	bb, _ := b.Get(ctx, alice, "example.com")
	if ba.Cookies[0].Value != "v" || bb.Cookies[0].Value != "other" {
		t.Error("instances share cookie state")
	}
	if ba.ExpiresAt.Sub(ba.CapturedAt) != time.Hour || bb.ExpiresAt.Sub(bb.CapturedAt) != time.Minute {
		t.Error("instances share ttl")
	}
}

func TestBundleTTLCap(t *testing.T) {
	s, now := newStore(t, time.Hour)
	ctx := context.Background()

	// Session-only bundle: capped at the vault TTL.
	if _, err := s.Put(ctx, alice, "example.com", []Cookie{sessionCookie("sid", "v", "example.com")}); err != nil {
		t.Fatal(err)
	}
	b, _ := s.Get(ctx, alice, "example.com")
	if got := b.ExpiresAt.Sub(*now); got != time.Hour {
		t.Errorf("session bundle lifetime = %v, want 1h", got)
	}

	// A far-future persistent cookie does not extend the bundle past the TTL.
	far := sessionCookie("far", "v", "example.com")
	far.Expires = now.Add(365 * 24 * time.Hour)
	if _, err := s.Put(ctx, alice, "example.com", []Cookie{far}); err != nil {
		t.Fatal(err)
	}
	b, _ = s.Get(ctx, alice, "example.com")
	if got := b.ExpiresAt.Sub(*now); got != time.Hour {
		t.Errorf("persistent bundle lifetime = %v, want 1h", got)
	}

	// All-persistent bundle with an earlier last expiry ends then.
	soon := sessionCookie("soon", "v", "example.com")
	soon.Expires = now.Add(10 * time.Minute)
	if _, err := s.Put(ctx, alice, "example.com", []Cookie{soon}); err != nil {
		t.Fatal(err)
	}
	b, _ = s.Get(ctx, alice, "example.com")
	if got := b.ExpiresAt.Sub(*now); got != 10*time.Minute {
		t.Errorf("short bundle lifetime = %v, want 10m", got)
	}

	// Already-expired cookies are not stored.
	dead := sessionCookie("dead", "v", "example.com")
	dead.Expires = now.Add(-time.Minute)
	if _, err := s.Put(ctx, alice, "example.com", []Cookie{dead}); !errors.Is(err, ErrNoCookies) {
		t.Errorf("err = %v, want ErrNoCookies", err)
	}

	// The bundle disappears once the clock passes ExpiresAt.
	*now = now.Add(11 * time.Minute)
	if _, ok := s.Get(ctx, alice, "example.com"); ok {
		t.Error("expired bundle still readable")
	}
	if got := s.List(ctx, alice); len(got) != 0 {
		t.Errorf("expired bundle listed: %v", got)
	}
}

func TestBundleCaps(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	ctx := context.Background()

	many := make([]Cookie, MaxCookiesPerBundle+1)
	for i := range many {
		many[i] = sessionCookie("c"+string(rune('a'+i%26))+strings.Repeat("x", i), "v", "example.com")
	}
	if _, err := s.Put(ctx, alice, "example.com", many); !errors.Is(err, ErrTooManyCookies) {
		t.Errorf("err = %v, want ErrTooManyCookies", err)
	}

	huge := sessionCookie("big", strings.Repeat("v", MaxCookieBytes), "example.com")
	if _, err := s.Put(ctx, alice, "example.com", []Cookie{huge}); !errors.Is(err, ErrCookieTooLarge) {
		t.Errorf("err = %v, want ErrCookieTooLarge", err)
	}

	var bulky []Cookie
	for i := 0; i < MaxCookiesPerBundle; i++ {
		bulky = append(bulky, sessionCookie("n"+strings.Repeat("y", i), strings.Repeat("v", 3000), "example.com"))
	}
	if _, err := s.Put(ctx, alice, "example.com", bulky); !errors.Is(err, ErrBundleTooLarge) {
		t.Errorf("err = %v, want ErrBundleTooLarge", err)
	}

	ok := sessionCookie("fits", strings.Repeat("v", MaxCookieBytes-len("fits")), "example.com")
	if _, err := s.Put(ctx, alice, "example.com", []Cookie{ok}); err != nil {
		t.Errorf("max-size cookie rejected: %v", err)
	}
}

func TestVaultFilesAreEncrypted(t *testing.T) {
	dir := t.TempDir()
	disk, err := persist.NewDiskStore(dir, keyA, "")
	if err != nil {
		t.Fatal(err)
	}
	s := NewPersistStore(disk, time.Hour)
	ctx := context.Background()
	const secret = "SUPER-SECRET-SESSION-VALUE-9f3"
	if _, err := s.Put(ctx, alice, "private-bank.com", []Cookie{sessionCookie("sessionid", secret, "private-bank.com")}); err != nil {
		t.Fatal(err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) == 0 {
		t.Fatal("nothing written to disk")
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		for _, needle := range []string{secret, "sessionid", "private-bank", "cookies", "alice"} {
			if strings.Contains(string(raw), needle) {
				t.Errorf("%s contains plaintext %q", filepath.Base(f), needle)
			}
		}
	}

	// A restart with the right key reads it; the wrong key cannot.
	again, _ := persist.NewDiskStore(dir, keyA, "")
	if _, ok := NewPersistStore(again, time.Hour).Get(ctx, alice, "private-bank.com"); !ok {
		t.Error("bundle not readable after reopening with the same key")
	}
	wrong, _ := persist.NewDiskStore(dir, keyB, "")
	if _, ok := NewPersistStore(wrong, time.Hour).Get(ctx, alice, "private-bank.com"); ok {
		t.Error("bundle readable with the wrong key")
	}
}

func TestVaultDataSubjectRoundTrip(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	ctx := context.Background()
	const secret = "CANARY-COOKIE-VALUE-123"
	for _, h := range []string{"example.com", "example.org"} {
		if _, err := s.Put(ctx, alice, h, []Cookie{sessionCookie("sessionid", secret, h)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Put(ctx, bob, "example.com", []Cookie{sessionCookie("sessionid", secret, "example.com")}); err != nil {
		t.Fatal(err)
	}

	reg := datasubject.NewRegistry()
	reg.Register("cookie_vault", AsDataSubject(s), AsDataSubject(s))

	exp := reg.Export(ctx, datasubject.Subject{TenantID: "t1", UserID: "alice"})
	raw, _ := json.Marshal(exp)
	for _, forbidden := range []string{secret, "sessionid", `"value"`, `"name"`} {
		if strings.Contains(string(raw), forbidden) {
			t.Errorf("export contains %q: %s", forbidden, raw)
		}
	}
	for _, want := range []string{"example.com", "example.org", "cookieCount", "capturedAt", "expiresAt"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("export missing %q: %s", want, raw)
		}
	}

	if res := reg.Erase(ctx, datasubject.Subject{TenantID: "t1", UserID: "alice"}); res.Deleted["cookie_vault"] != 2 {
		t.Errorf("deleted = %v, want 2", res.Deleted)
	}
	if _, ok := s.Get(ctx, alice, "example.com"); ok {
		t.Error("alice's bundle survived erasure")
	}
	if _, ok := s.Get(ctx, bob, "example.com"); !ok {
		t.Error("erasure removed bob's bundle")
	}
	if exp := reg.Export(ctx, datasubject.Subject{TenantID: "t1", UserID: "alice"}); len(exp.Namespaces) != 0 {
		t.Errorf("export after erasure = %v", exp.Namespaces)
	}
	// Tenant-only subject (no user) holds nothing here.
	if res := reg.Erase(ctx, datasubject.Subject{TenantID: "t1"}); res.Deleted["cookie_vault"] != 0 {
		t.Errorf("tenant-only erase deleted %d", res.Deleted["cookie_vault"])
	}
}

func TestVaultDeleteIsIdempotent(t *testing.T) {
	s, _ := newStore(t, time.Hour)
	ctx := context.Background()
	if _, err := s.Put(ctx, alice, "example.com", []Cookie{sessionCookie("sid", "v", "example.com")}); err != nil {
		t.Fatal(err)
	}
	if existed, err := s.Delete(ctx, alice, "www.example.com"); err != nil || !existed {
		t.Errorf("first delete = %v, %v", existed, err)
	}
	if existed, err := s.Delete(ctx, alice, "example.com"); err != nil || existed {
		t.Errorf("second delete = %v, %v", existed, err)
	}
	if got := s.List(ctx, alice); len(got) != 0 {
		t.Errorf("list after delete = %v", got)
	}
}

func TestVaultCorruptEntryReadsAsMiss(t *testing.T) {
	kv := persist.NewMemoryStore()
	s := NewPersistStore(kv, time.Hour)
	ctx := context.Background()
	kv.Set(ctx, bundleKey(alice, "example.com"), []byte("{not json"), time.Hour)
	if _, ok := s.Get(ctx, alice, "example.com"); ok {
		t.Error("corrupt entry returned a bundle")
	}
	// An entry stored under the wrong key (domain mismatch) is rejected too.
	b, _ := json.Marshal(Bundle{Domain: "evil.com", ExpiresAt: time.Now().Add(time.Hour), Cookies: []Cookie{sessionCookie("a", "b", "evil.com")}})
	kv.Set(ctx, bundleKey(alice, "example.com"), b, time.Hour)
	if _, ok := s.Get(ctx, alice, "example.com"); ok {
		t.Error("mismatched entry returned a bundle")
	}
}
