package connectors

import (
	"context"

	"github.com/example/walletguard/internal/domain"
)

// Connector streams normalized documents from an authorized source.
type Connector interface {
	Name() string
	Type() string
	Scan(ctx context.Context, out chan<- domain.Document) error
}
