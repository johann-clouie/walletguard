package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/example/walletguard/internal/domain"
)

// FilesystemConnector walks local directories and emits file contents as documents.
type FilesystemConnector struct {
	Roots []string
	Name  string
}

func (f *FilesystemConnector) Name() string {
	if f.Name != "" {
		return f.Name
	}
	return "filesystem"
}

func (f *FilesystemConnector) Type() string { return "filesystem" }

func (f *FilesystemConnector) Scan(ctx context.Context, out chan<- domain.Document) error {
	for _, root := range f.Roots {
		root = filepath.Clean(root)
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			if d.IsDir() {
				base := d.Name()
				if base == ".git" || base == "node_modules" || base == "vendor" {
					return fs.SkipDir
				}
				return nil
			}
			if !looksTextCandidate(path) {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Size() > 50*1024*1024 {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if isMostlyBinary(b) {
				return nil
			}
			h := sha256.Sum256(b)
			doc := domain.Document{
				ID:          uuid.NewString(),
				Source:      f.Name(),
				Path:        path,
				ContentType: sniffContentType(path),
				Content:     b,
				Metadata: map[string]string{
					"connector": f.Type(),
					"sha256":    hex.EncodeToString(h[:]),
					"size":      strconv.FormatInt(info.Size(), 10),
				},
				Timestamp: time.Now().UTC(),
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case out <- doc:
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func looksTextCandidate(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".go", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".env", ".txt", ".md", ".sql", ".sh", ".ps1", ".toml", ".ini", ".cfg", ".log", ".pem", ".key":
		return true
	}
	base := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(base, ".env") {
		return true
	}
	return ext == "" && !strings.HasSuffix(path, ".exe")
}

func isMostlyBinary(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	zeros := 0
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			zeros++
		}
	}
	return zeros*10 > n
}

func sniffContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "application/json"
	case ".yaml", ".yml":
		return "application/yaml"
	case ".env":
		return "text/x-env"
	default:
		return "text/plain"
	}
}
