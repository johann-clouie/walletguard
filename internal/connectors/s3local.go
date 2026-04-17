package connectors

import (
	"context"

	"github.com/example/walletguard/internal/domain"
)

// S3LocalConnector treats a local directory as an object-prefix root (dev / air-gapped MVP).
type S3LocalConnector struct {
	LocalRoot string
	Bucket    string
}

func (s *S3LocalConnector) Name() string {
	if s.Bucket != "" {
		return "s3:" + s.Bucket
	}
	return "s3-local"
}

func (s *S3LocalConnector) Type() string { return "s3" }

func (s *S3LocalConnector) Scan(ctx context.Context, out chan<- domain.Document) error {
	if s.LocalRoot == "" {
		return nil
	}
	fs := &FilesystemConnector{
		Roots: []string{s.LocalRoot},
		Name:  s.Name(),
	}
	ch := make(chan domain.Document, 32)
	errCh := make(chan error, 1)
	go func() {
		errCh <- fs.Scan(ctx, ch)
		close(ch)
	}()
	for doc := range ch {
		if doc.Metadata == nil {
			doc.Metadata = map[string]string{}
		}
		doc.Metadata["s3_bucket"] = s.Bucket
		doc.Metadata["s3_local_root"] = s.LocalRoot
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- doc:
		}
	}
	return <-errCh
}
