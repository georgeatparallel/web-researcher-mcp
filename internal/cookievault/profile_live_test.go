//go:build live

package cookievault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
)

// TestProfileLoginFastCloseLive: a persistent cookie set just before the window
// closes must be on disk after RodDriver's clean shutdown (issue #775, rule 8).
func TestProfileLoginFastCloseLive(t *testing.T) {
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("chrome not available")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "keep", Value: "v", Path: "/", Expires: time.Now().Add(time.Hour)})
		_, _ = w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer srv.Close()

	d := &RodDriver{headless: true}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sess, err := d.Open(ctx, srv.URL, dir)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cs, _ := sess.Cookies(ctx); len(cs) > 0 {
			break
		}
	}
	_ = sess.Close() // no grace wait: Close must wait for the exit itself

	cookies, err := d.ReadCookies(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range cookies {
		found = found || c.Name == "keep"
	}
	if !found {
		t.Fatalf("persistent cookie lost on close; got %+v", cookies)
	}
}
