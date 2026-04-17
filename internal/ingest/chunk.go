package ingest

import (
	"bytes"

	"github.com/example/walletguard/internal/domain"
)

// Chunk splits a document into smaller overlapping text chunks for detection.
// Line numbers are 1-based in metadata as line_start / line_end.
func Chunk(doc domain.Document, maxBytes int) []domain.Document {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	if len(doc.Content) <= maxBytes {
		return []domain.Document{doc}
	}
	var out []domain.Document
	lines := bytes.Split(doc.Content, []byte("\n"))
	var buf bytes.Buffer
	startLine := 1
	curLine := 0
	for _, line := range lines {
		curLine++
		if buf.Len()+len(line)+1 > maxBytes && buf.Len() > 0 {
			clone := doc
			clone.ID = doc.ID
			clone.Content = append([]byte(nil), buf.Bytes()...)
			if clone.Metadata == nil {
				clone.Metadata = map[string]string{}
			}
			clone.Metadata["line_start"] = itoa(startLine)
			clone.Metadata["line_end"] = itoa(curLine - 1)
			clone.Metadata["chunk_parent_id"] = doc.ID
			out = append(out, clone)
			buf.Reset()
			startLine = curLine
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(line)
	}
	if buf.Len() > 0 {
		clone := doc
		clone.ID = doc.ID
		clone.Content = append([]byte(nil), buf.Bytes()...)
		if clone.Metadata == nil {
			clone.Metadata = map[string]string{}
		}
		clone.Metadata["line_start"] = itoa(startLine)
		clone.Metadata["line_end"] = itoa(curLine)
		clone.Metadata["chunk_parent_id"] = doc.ID
		out = append(out, clone)
	}
	if len(out) == 0 {
		return []domain.Document{doc}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [32]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
