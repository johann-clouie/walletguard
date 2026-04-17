package incidents

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/example/walletguard/internal/domain"
)

// Manager creates incidents and default playbook links for high-severity findings.
type Manager struct{}

// PlaybookFor returns a playbook id for UI / runbooks.
func (m *Manager) PlaybookFor(f domain.Finding, sev domain.Severity) string {
	switch f.SecretType {
	case domain.SecretMnemonic:
		return "mnemonic_cloud_exposure"
	case domain.SecretEVMKey:
		if sev == domain.SeverityCritical || sev == domain.SeverityHigh {
			return "evm_hot_wallet_compromise"
		}
		return "evm_key_rotation"
	case domain.SecretSolanaKey:
		return "solana_bot_wallet_leak"
	case domain.SecretBitcoinWIF:
		return "bitcoin_wif_rotation"
	default:
		return "generic_secret_exposure"
	}
}

// NewIncident builds an incident record for a confirmed risk.
func (m *Manager) NewIncident(f domain.Finding, rs domain.RiskScore) domain.Incident {
	path := ""
	if f.Metadata != nil {
		path = f.Metadata["path"]
	}
	title := fmt.Sprintf("%s exposure in %s", f.SecretType, shortPath(path))
	return domain.Incident{
		ID:           uuid.NewString(),
		FindingID:    f.ID,
		Title:        title,
		Status:       domain.StatusDetected,
		Owner:        "",
		PlaybookName: m.PlaybookFor(f, rs.Severity),
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}
}

func shortPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) > 120 {
		return "…" + p[len(p)-120:]
	}
	if p == "" {
		return "unknown path"
	}
	return p
}
