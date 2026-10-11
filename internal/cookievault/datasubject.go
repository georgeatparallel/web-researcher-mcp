package cookievault

import (
	"context"

	"github.com/zoharbabin/web-researcher-mcp/internal/datasubject"
)

// SubjectAdapter exposes the vault as a data-subject Exporter/Eraser (#85).
// Export returns redacted summaries only (domain, capturedAt, expiresAt,
// cookieCount): cookie names and values are credentials and are never exported.
type SubjectAdapter struct {
	store Store
}

// AsDataSubject wraps a Store for registration into the datasubject registry.
func AsDataSubject(store Store) *SubjectAdapter { return &SubjectAdapter{store: store} }

// ExportSubject implements datasubject.Exporter.
func (a *SubjectAdapter) ExportSubject(ctx context.Context, s datasubject.Subject) (any, error) {
	if s.UserID == "" {
		return nil, nil
	}
	sums := a.store.List(ctx, Subject{TenantID: s.TenantID, UserID: s.UserID})
	if len(sums) == 0 {
		return nil, nil
	}
	return map[string]any{"sessions": sums}, nil
}

// EraseSubject implements datasubject.Eraser.
func (a *SubjectAdapter) EraseSubject(ctx context.Context, s datasubject.Subject) (int, error) {
	if s.UserID == "" {
		return 0, nil
	}
	return a.store.EraseAll(ctx, Subject{TenantID: s.TenantID, UserID: s.UserID})
}

var (
	_ datasubject.Exporter = (*SubjectAdapter)(nil)
	_ datasubject.Eraser   = (*SubjectAdapter)(nil)
)
