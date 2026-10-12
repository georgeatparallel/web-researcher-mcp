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

// TestStdioBootstrapSessionCaptureNeedsExplicitOptIn proves the STDIO startup
// grant covers memory, analytics and monitoring, never workspace, and records
// session_capture only on the explicit COOKIE_VAULT_STDIO_CONSENT opt-in (#241).
func TestStdioBootstrapSessionCaptureNeedsExplicitOptIn(t *testing.T) {
	newCfg := func(vault, optIn bool) *config.Config {
		cfg := &config.Config{StdioUserID: "alice", CookieVaultStdioConsent: optIn}
		cfg.Features.CookieVault = vault
		cfg.Features.Memory = true
		cfg.Features.UserAnalytics = true
		cfg.Features.Monitoring = true
		cfg.Features.Workspaces = true
		return cfg
	}
	run := func(cfg *config.Config) consent.Manager {
		mgr := consent.NewStoreManager(persist.NewMemoryStore())
		grantStdioConsent(context.Background(), cfg, mgr, audit.NewNoop(), slog.Default())
		return mgr
	}

	t.Run("default never grants session_capture or workspace", func(t *testing.T) {
		mgr := run(newCfg(true, false))
		for _, p := range []consent.Purpose{consent.PurposeMemory, consent.PurposeAnalytics, consent.PurposeMonitoring} {
			if !granted(mgr, p) {
				t.Errorf("purpose %q should be auto-granted", p)
			}
		}
		for _, p := range []consent.Purpose{consent.PurposeSessionCapture, consent.PurposeWorkspace} {
			if granted(mgr, p) {
				t.Errorf("purpose %q must not be granted without opt-in", p)
			}
		}
	})

	t.Run("opt-in grants session_capture, still never workspace", func(t *testing.T) {
		mgr := run(newCfg(true, true))
		if !granted(mgr, consent.PurposeSessionCapture) {
			t.Fatal("session_capture should be granted on explicit opt-in")
		}
		if granted(mgr, consent.PurposeWorkspace) {
			t.Fatal("workspace must never be auto-granted")
		}
	})

	t.Run("opt-in without the vault grants nothing", func(t *testing.T) {
		if granted(run(newCfg(false, true)), consent.PurposeSessionCapture) {
			t.Fatal("session_capture granted although the vault is disabled")
		}
	})

	t.Run("a withdrawal is never resurrected", func(t *testing.T) {
		mgr := consent.NewStoreManager(persist.NewMemoryStore())
		rec := consent.Record{TenantID: "default", UserID: "alice", Purpose: consent.PurposeSessionCapture,
			Granted: false, DecidedAt: time.Now().UTC().Format(time.RFC3339), DecidedFrom: "test"}
		if err := mgr.Record(context.Background(), rec); err != nil {
			t.Fatal(err)
		}
		grantStdioConsent(context.Background(), newCfg(true, true), mgr, audit.NewNoop(), slog.Default())
		if granted(mgr, consent.PurposeSessionCapture) {
			t.Fatal("restart re-granted a withdrawn session_capture consent")
		}
	})
}

func granted(mgr consent.Manager, p consent.Purpose) bool {
	rec, ok := mgr.Query(context.Background(), "default", "alice", p)
	return ok && rec.Granted
}
