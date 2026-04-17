package connectors

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/example/walletguard/internal/domain"
)

func pathUnderRoot(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path == root {
		return true
	}
	sep := string(filepath.Separator)
	return strings.HasPrefix(path, root+sep)
}

// GitConnector scans a local clone like filesystem but tags metadata as git
// and records HEAD when available.
type GitConnector struct {
	RepoPaths []string
	Name      string
}

func (g *GitConnector) Name() string {
	if g.Name != "" {
		return g.Name
	}
	return "git"
}

func (g *GitConnector) Type() string { return "git" }

func (g *GitConnector) Scan(ctx context.Context, out chan<- domain.Document) error {
	fs := &FilesystemConnector{
		Roots: g.RepoPaths,
		Name:  g.Name(),
	}
	// Wrap documents with git metadata.
	ch := make(chan domain.Document, 32)
	errCh := make(chan error, 1)
	go func() {
		errCh <- fs.Scan(ctx, ch)
		close(ch)
	}()
	for doc := range ch {
		repoRoot := ""
		for _, p := range g.RepoPaths {
			p = filepath.Clean(p)
			if pathUnderRoot(p, doc.Path) {
				repoRoot = p
				break
			}
		}
		if doc.Metadata == nil {
			doc.Metadata = map[string]string{}
		}
		doc.Metadata["connector"] = "git"
		doc.Metadata["git"] = "true"
		doc.Metadata["repo_root"] = repoRoot
		if head := gitHead(ctx, repoRoot); head != "" {
			doc.Metadata["commit"] = head
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- doc:
		}
	}
	return <-errCh
}

func gitHead(ctx context.Context, repoRoot string) string {
	if repoRoot == "" {
		return ""
	}
	cmd := exec.CommandContext(ctx, "git", "-C", repoRoot, "rev-parse", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
