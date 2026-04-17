package audit

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Log records an audit event (who did what on which resource).
func Log(ctx context.Context, pool *pgxpool.Pool, actor, action, resourceType, resourceID string, details map[string]any) error {
	if pool == nil {
		return nil
	}
	b, _ := json.Marshal(details)
	_, err := pool.Exec(ctx, `
		INSERT INTO audit_log (actor, action, resource_type, resource_id, details_json)
		VALUES ($1, $2, $3, $4, $5)
	`, actor, action, resourceType, resourceID, b)
	return err
}
