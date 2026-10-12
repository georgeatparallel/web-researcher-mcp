package cookievault

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/cdp"
	"github.com/go-rod/rod/lib/proto"
)

// ErrAttachUnavailable means no running browser of the user's accepted a
// debugging connection: remote debugging is off, the browser is closed, or the
// user declined the permission prompt. Callers fall back to a login window.
var ErrAttachUnavailable = errors.New("cookievault: no running browser accepted a debugging connection")

// Attacher reads the cookies for one registrable domain from the user's own
// running browser, so an existing signed-in session can be reused (#241).
type Attacher interface {
	// Attach returns only cookies scoped to domain. Cookies of every other
	// site are dropped before they leave the implementation.
	Attach(ctx context.Context, domain string) ([]Cookie, error)
}

// RodAttacher attaches to a Chromium-family browser the user started with
// remote debugging enabled (chrome://inspect/#remote-debugging, Chrome 144+).
// The browser asks the user to approve each connection and shows a banner
// while it lasts. It never launches a browser and never closes the user's.
type RodAttacher struct {
	dirs    []string
	timeout time.Duration
}

// NewRodAttacher returns an Attacher that waits up to timeout for the user to
// approve the browser's permission prompt.
func NewRodAttacher(timeout time.Duration) *RodAttacher {
	return &RodAttacher{dirs: defaultBrowserDirs(), timeout: timeout}
}

// Attach tries each installed browser's debugging endpoint in turn and returns
// the domain's cookies from the first that accepts. ErrAttachUnavailable when
// none does.
func (a *RodAttacher) Attach(ctx context.Context, domain string) ([]Cookie, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	for _, dir := range a.dirs {
		wsURL, ok := readActivePort(dir)
		if !ok {
			continue
		}
		all, err := browserCookies(ctx, wsURL)
		if err != nil {
			continue
		}
		return FilterToDomain(all, domain, time.Now()), nil
	}
	return nil, ErrAttachUnavailable
}

// browserCookies connects, reads the browser's cookies and disconnects. It
// closes only its own socket: rod's Browser.Close would quit the user's browser.
func browserCookies(ctx context.Context, wsURL string) ([]Cookie, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	// rod's default handshake key is not valid base64; send a real one.
	hdr := http.Header{"Sec-WebSocket-Key": {base64.StdEncoding.EncodeToString(key)}}
	ws := &cdp.WebSocket{}
	if err := ws.Connect(ctx, wsURL, hdr); err != nil {
		return nil, err
	}
	defer func() { _ = ws.Close() }()
	b := rod.New().Client(cdp.New().Start(ws)).Context(ctx)
	res, err := proto.StorageGetCookies{}.Call(b)
	if err != nil {
		return nil, err
	}
	return fromRodCookies(res.Cookies), nil
}

// fromRodCookies converts CDP cookies to vault cookies.
func fromRodCookies(raw []*proto.NetworkCookie) []Cookie {
	out := make([]Cookie, 0, len(raw))
	for _, c := range raw {
		ck := Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Domain:   c.Domain,
			Path:     c.Path,
			Secure:   c.Secure,
			HTTPOnly: c.HTTPOnly,
			HostOnly: len(c.Domain) > 0 && c.Domain[0] != '.',
			SameSite: string(c.SameSite),
		}
		if !c.Session && c.Expires > 0 {
			ck.Expires = c.Expires.Time()
		}
		out = append(out, ck)
	}
	return out
}

var activePortPath = regexp.MustCompile(`^/devtools/browser/[0-9A-Za-z-]{1,64}$`)

// readActivePort reads dir/DevToolsActivePort and returns the loopback
// WebSocket URL, or false when the file is missing or malformed. The path
// carries a per-session token, so the URL is never logged.
func readActivePort(dir string) (string, bool) {
	f, err := os.Open(filepath.Join(dir, "DevToolsActivePort")) // #nosec G304 -- dir comes from the fixed per-OS browser list, not user input
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, 512))
	if err != nil {
		return "", false
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 2 {
		return "", false
	}
	port, err := strconv.Atoi(strings.TrimSpace(lines[0]))
	if err != nil || port < 1 || port > 65535 {
		return "", false
	}
	path := strings.TrimSpace(lines[1])
	if !activePortPath.MatchString(path) {
		return "", false
	}
	return "ws://127.0.0.1:" + strconv.Itoa(port) + path, true
}

// defaultBrowserDirs lists the default user-data directories of the common
// Chromium-family browsers on this OS (Chrome first).
func defaultBrowserDirs() []string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "darwin":
		base := filepath.Join(home, "Library", "Application Support")
		return []string{
			filepath.Join(base, "Google", "Chrome"),
			filepath.Join(base, "Microsoft Edge"),
			filepath.Join(base, "BraveSoftware", "Brave-Browser"),
		}
	case "windows":
		base := os.Getenv("LOCALAPPDATA")
		if base == "" {
			return nil
		}
		return []string{
			filepath.Join(base, "Google", "Chrome", "User Data"),
			filepath.Join(base, "Microsoft", "Edge", "User Data"),
			filepath.Join(base, "BraveSoftware", "Brave-Browser", "User Data"),
		}
	default:
		base := filepath.Join(home, ".config")
		return []string{
			filepath.Join(base, "google-chrome"),
			filepath.Join(base, "chromium"),
			filepath.Join(base, "microsoft-edge"),
			filepath.Join(base, "BraveSoftware", "Brave-Browser"),
		}
	}
}
