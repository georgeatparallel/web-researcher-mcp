package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/zoharbabin/web-researcher-mcp/internal/audit"
	"github.com/zoharbabin/web-researcher-mcp/internal/config"
	"github.com/zoharbabin/web-researcher-mcp/internal/consent"
	"github.com/zoharbabin/web-researcher-mcp/internal/persist"
)

// TestOsintClientDedicatedTimeout proves ctLogResolver and archiveResolver
// share the same dedicated-timeout client (#592) rather than one of them
// falling back to the 30s shared SSRF client that crt.sh/Wayback CDX both
// regularly exceed under documented upstream latency.
func TestOsintClientDedicatedTimeout(t *testing.T) {
	c := osintClient(false)
	if c.Timeout != osintClientTimeout {
		t.Fatalf("osintClient timeout = %v, want %v", c.Timeout, osintClientTimeout)
	}
	if c.Timeout == 30*time.Second {
		t.Fatalf("osintClient must not use the default 30s shared SSRF client timeout")
	}
}

// TestStdioBootstrapNeverGrantsSessionCapture proves the STDIO startup grant
// covers the other opt-in purposes but never session_capture or workspace (#241).
func TestStdioBootstrapNeverGrantsSessionCapture(t *testing.T) {
	cfg := &config.Config{StdioUserID: "alice"}
	cfg.Features.CookieVault = true
	cfg.Features.Memory = true
	cfg.Features.UserAnalytics = true
	cfg.Features.Monitoring = true
	cfg.Features.Workspaces = true
	mgr := consent.NewStoreManager(persist.NewMemoryStore())

	grantStdioConsent(context.Background(), cfg, mgr, audit.NewNoop(), slog.Default())

	for _, p := range []consent.Purpose{consent.PurposeMemory, consent.PurposeAnalytics, consent.PurposeMonitoring} {
		if !granted(mgr, p) {
			t.Errorf("purpose %q should be auto-granted", p)
		}
	}
	for _, p := range []consent.Purpose{consent.PurposeSessionCapture, consent.PurposeWorkspace} {
		if granted(mgr, p) {
			t.Errorf("purpose %q must never be auto-granted", p)
		}
	}
}

func granted(mgr consent.Manager, p consent.Purpose) bool {
	rec, ok := mgr.Query(context.Background(), "default", "alice", p)
	return ok && rec.Granted
}
