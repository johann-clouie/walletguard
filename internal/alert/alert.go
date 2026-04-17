package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/example/walletguard/internal/domain"
)

// Notifier sends human-readable alerts (Slack webhook MVP).
type Notifier struct {
	SlackWebhook string
	HTTP         *http.Client
}

// NewNotifier creates a notifier with sane HTTP timeouts.
func NewNotifier(slackURL string) *Notifier {
	return &Notifier{
		SlackWebhook: slackURL,
		HTTP:         &http.Client{Timeout: 12 * time.Second},
	}
}

// NotifyFinding emits a best-effort alert for critical/high items.
func (n *Notifier) NotifyFinding(ctx context.Context, inc domain.Incident, f domain.Finding, rs domain.RiskScore) {
	if n.SlackWebhook == "" {
		log.Printf("[ALERT] severity=%s finding=%s incident=%s path=%s", rs.Severity, f.ID, inc.ID, f.Metadata["path"])
		return
	}
	text := fmt.Sprintf(
		"*WalletGuard* %s\nFinding: `%s` (%s)\nIncident: `%s`\nPath: `%s`\nReasons: %s",
		rs.Severity, f.ID, f.SecretType, inc.ID, f.Metadata["path"], joinReasons(rs.Reasons),
	)
	payload := map[string]any{"text": text}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.SlackWebhook, bytes.NewReader(b))
	if err != nil {
		log.Printf("alert: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.HTTP.Do(req)
	if err != nil {
		log.Printf("alert: slack: %v", err)
		return
	}
	resp.Body.Close()
}

func joinReasons(r []string) string {
	if len(r) == 0 {
		return "(none)"
	}
	out := r[0]
	for i := 1; i < len(r); i++ {
		out += "; " + r[i]
	}
	return out
}
