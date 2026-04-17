package pipeline

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/example/walletguard/internal/alert"
	"github.com/example/walletguard/internal/audit"
	"github.com/example/walletguard/internal/classifiers"
	"github.com/example/walletguard/internal/domain"
	"github.com/example/walletguard/internal/enrichment"
	"github.com/example/walletguard/internal/incidents"
	"github.com/example/walletguard/internal/risk"
	"github.com/example/walletguard/internal/storage"
	"github.com/example/walletguard/internal/verifiers"
)

// ProcessDocument runs detect → verify → enrich → risk → persist for one stored document row.
type ProcessDocument struct {
	Store     *storage.PostgresStore
	Enrich    *enrichment.BalanceChecker
	Notifier  *alert.Notifier
	Incidents *incidents.Manager
}

// Handle ingests DB document id (uuid) and the logical document used for scanning.
func (p *ProcessDocument) Handle(ctx context.Context, docDBID uuid.UUID, doc domain.Document, findings []domain.Finding) error {
	for i := range findings {
		f := &findings[i]
		v := verifiers.Verify(*f)
		if ch := classifiers.DerivableChains(*f, v); len(ch) > 0 {
			if v.Details == nil {
				v.Details = map[string]string{}
			}
			v.Details["derivable_chains"] = strings.Join(ch, ",")
		}
		ex := p.Enrich.Enrich(ctx, *f, &v)
		for k, val := range ex {
			if v.Details == nil {
				v.Details = map[string]string{}
			}
			v.Details[k] = val
		}
		rs := risk.Compute(*f, v, ex)
		fid, err := p.Store.InsertFinding(ctx, docDBID, *f)
		if err != nil {
			return err
		}
		if err := p.Store.InsertVerification(ctx, fid, v); err != nil {
			return err
		}
		if err := p.Store.InsertRisk(ctx, fid, rs); err != nil {
			return err
		}
		_ = audit.Log(ctx, p.Store.Pool, "scanner", "finding_persisted", "finding", f.ID, map[string]any{
			"severity": string(rs.Severity),
			"valid":    v.IsValid,
		})
		if rs.Severity == domain.SeverityHigh || rs.Severity == domain.SeverityCritical {
			inc := p.Incidents.NewIncident(*f, rs)
			if _, err := p.Store.InsertIncident(ctx, inc, fid); err != nil {
				return err
			}
			p.Notifier.NotifyFinding(ctx, inc, *f, rs)
			_ = audit.Log(ctx, p.Store.Pool, "scanner", "incident_opened", "incident", inc.ID, map[string]any{
				"finding_id": f.ID,
				"severity":   string(rs.Severity),
			})
		}
		f.RawSnippet = nil
	}
	return nil
}
