package detectors

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/tyler-smith/go-bip39"

	"github.com/example/walletguard/internal/domain"
)

var (
	reEVMHex     = regexp.MustCompile(`(?i)(?:^|[^0-9a-f])(0x)?([0-9a-f]{64})(?:[^0-9a-f]|$)`)
	reWIF        = regexp.MustCompile(`(?:^|[\s'"=])([5KL][1-9A-HJ-NP-Za-km-z]{50,51})(?:[^1-9A-HJ-NP-Za-km-z]|$)`)
	reSolanaB58  = regexp.MustCompile(`(?:^|[\s'"=])([1-9A-HJ-NP-Za-km-z]{87,88})(?:[^1-9A-HJ-NP-Za-km-z]|$)`)
	reEnvKeyHint = regexp.MustCompile(`(?i)(mnemonic|seed|private[_-]?key|keypair|wallet|wif|solana)`)
)

// Engine runs regex, dictionary, and structural heuristics over document text.
type Engine struct{}

// NewEngine creates a detection engine.
func NewEngine() *Engine { return &Engine{} }

// Scan returns findings for a single document chunk.
func (e *Engine) Scan(doc domain.Document) []domain.Finding {
	text := string(doc.Content)
	var findings []domain.Finding
	findings = append(findings, e.scanMnemonic(doc, text)...)
	findings = append(findings, e.scanEVM(doc, text)...)
	findings = append(findings, e.scanWIF(doc, text)...)
	findings = append(findings, e.scanSolana(doc, text)...)
	return findings
}

func lineRangeForIndex(content []byte, idx int) (start, end int) {
	start, end = 1, 1
	if idx < 0 || idx > len(content) {
		return 1, 1
	}
	line := 1
	for i := 0; i < idx && i < len(content); i++ {
		if content[i] == '\n' {
			line++
		}
	}
	start = line
	end = line
	for j := idx; j < len(content) && content[j] != '\n'; j++ {
	}
	return start, end
}

func (e *Engine) scanEVM(doc domain.Document, text string) []domain.Finding {
	var out []domain.Finding
	seen := map[string]struct{}{}
	for _, m := range reEVMHex.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 6 {
			continue
		}
		hexPart := text[m[4]:m[5]]
		key := strings.ToLower(hexPart)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		conf := 0.55
		lo := max(0, m[0]-80)
		hi := min(len(text), m[1]+80)
		ctx := text[lo:hi]
		if reEnvKeyHint.MatchString(ctx) {
			conf += 0.35
		}
		if strings.Contains(strings.ToLower(doc.Path), ".env") {
			conf += 0.1
		}
		idx := m[4]
		ls, le := lineRangeForIndex(doc.Content, idx)
		out = append(out, domain.Finding{
			ID:          uuid.NewString(),
			DocID:       doc.ID,
			SecretType:  domain.SecretEVMKey,
			ChainFamily: domain.ChainEVM,
			MaskedValue: MaskHex(hexPart, 4),
			Confidence:  minf(conf, 0.99),
			LineStart:   ls,
			LineEnd:     le,
			RawSnippet:  []byte(hexPart),
			Metadata:    map[string]string{"path": doc.Path},
			CreatedAt:   time.Now().UTC(),
		})
	}
	return out
}

func (e *Engine) scanWIF(doc domain.Document, text string) []domain.Finding {
	var out []domain.Finding
	seen := map[string]struct{}{}
	for _, m := range reWIF.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		wif := text[m[2]:m[3]]
		if _, ok := seen[wif]; ok {
			continue
		}
		seen[wif] = struct{}{}
		conf := 0.5
		lo := max(0, m[0]-80)
		hi := min(len(text), m[1]+80)
		if reEnvKeyHint.MatchString(text[lo:hi]) {
			conf += 0.35
		}
		idx := m[2]
		ls, le := lineRangeForIndex(doc.Content, idx)
		mv := wif
		if len(mv) > 8 {
			mv = mv[:4] + "…" + mv[len(mv)-4:]
		}
		out = append(out, domain.Finding{
			ID:          uuid.NewString(),
			DocID:       doc.ID,
			SecretType:  domain.SecretBitcoinWIF,
			ChainFamily: domain.ChainBitcoin,
			MaskedValue: mv,
			Confidence:  minf(conf, 0.99),
			LineStart:   ls,
			LineEnd:     le,
			RawSnippet:  []byte(wif),
			Metadata:    map[string]string{"path": doc.Path},
			CreatedAt:   time.Now().UTC(),
		})
	}
	return out
}

func (e *Engine) scanSolana(doc domain.Document, text string) []domain.Finding {
	var out []domain.Finding
	// JSON array of 64 bytes
	if strings.Contains(text, "[") {
		for _, cand := range extractJSONArrayCandidates(text) {
			words := strings.Fields(strings.Trim(cand, "[]{}, \t\n\r"))
			if len(words) != 64 {
				continue
			}
			ok := true
			for _, w := range words {
				if len(w) > 3 || !isDigits(w) {
					ok = false
					break
				}
			}
			if !ok {
				continue
			}
			conf := 0.6
			if reEnvKeyHint.MatchString(text) {
				conf += 0.3
			}
			idx := strings.Index(text, cand)
			if idx < 0 {
				idx = 0
			}
			ls, le := lineRangeForIndex(doc.Content, idx)
			out = append(out, domain.Finding{
				ID:          uuid.NewString(),
				DocID:       doc.ID,
				SecretType:  domain.SecretSolanaKey,
				ChainFamily: domain.ChainSolana,
				MaskedValue: "[64 bytes]",
				Confidence:  minf(conf, 0.99),
				LineStart:   ls,
				LineEnd:     le,
				RawSnippet:  []byte(cand),
				Metadata:    map[string]string{"path": doc.Path, "format": "json_array"},
				CreatedAt:   time.Now().UTC(),
			})
		}
	}
	seen := map[string]struct{}{}
	for _, m := range reSolanaB58.FindAllStringSubmatchIndex(text, -1) {
		if len(m) < 4 {
			continue
		}
		s := text[m[2]:m[3]]
		if len(s) < 80 || len(s) > 90 {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		conf := 0.35
		lo := max(0, m[0]-100)
		hi := min(len(text), m[1]+100)
		ctx := text[lo:hi]
		if reEnvKeyHint.MatchString(ctx) || strings.Contains(strings.ToLower(ctx), "solana") {
			conf += 0.45
		}
		idx := m[2]
		ls, le := lineRangeForIndex(doc.Content, idx)
		mv := s
		if len(mv) > 8 {
			mv = mv[:4] + "…" + mv[len(mv)-4:]
		}
		out = append(out, domain.Finding{
			ID:          uuid.NewString(),
			DocID:       doc.ID,
			SecretType:  domain.SecretSolanaKey,
			ChainFamily: domain.ChainSolana,
			MaskedValue: mv,
			Confidence:  minf(conf, 0.99),
			LineStart:   ls,
			LineEnd:     le,
			RawSnippet:  []byte(s),
			Metadata:    map[string]string{"path": doc.Path, "format": "base58"},
			CreatedAt:   time.Now().UTC(),
		})
	}
	return out
}

func extractJSONArrayCandidates(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '[' {
			continue
		}
		depth := 0
		for j := i; j < len(s); j++ {
			switch s[j] {
			case '[':
				depth++
			case ']':
				depth--
				if depth == 0 {
					out = append(out, s[i:j+1])
					i = j
					goto next
				}
			}
		}
	next:
	}
	return out
}

func isDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}

func (e *Engine) scanMnemonic(doc domain.Document, text string) []domain.Finding {
	words := tokenizeWords(text)
	var out []domain.Finding
	for i := 0; i < len(words); i++ {
		for _, n := range []int{12, 15, 18, 21, 24} {
			if i+n > len(words) {
				continue
			}
			slice := words[i : i+n]
			phrase := strings.Join(slice, " ")
			if !bip39.IsMnemonicValid(phrase) {
				continue
			}
			conf := 0.55
			lineCtx := strings.ToLower(doc.Path)
			if strings.Contains(lineCtx, ".env") || strings.Contains(lineCtx, "note") {
				conf += 0.15
			}
			sub := strings.ToLower(text)
			if idx := strings.Index(sub, strings.ToLower(phrase)); idx >= 0 {
				lo := max(0, idx-120)
				hi := min(len(text), idx+len(phrase)+120)
				if reEnvKeyHint.MatchString(text[lo:hi]) {
					conf += 0.25
				}
			}
			ls, le := lineRangeForIndex(doc.Content, strings.Index(text, slice[0]))
			if ls == 0 {
				ls, le = 1, 1
			}
			out = append(out, domain.Finding{
				ID:          uuid.NewString(),
				DocID:       doc.ID,
				SecretType:  domain.SecretMnemonic,
				ChainFamily: domain.ChainUnknown,
				MaskedValue: MaskMnemonic(n),
				Confidence:  minf(conf, 0.99),
				LineStart:   ls,
				LineEnd:     le,
				RawSnippet:  []byte(phrase),
				Metadata: map[string]string{
					"path":       doc.Path,
					"word_count": strconv.Itoa(n),
				},
				CreatedAt: time.Now().UTC(),
			})
			i += n - 1
			break
		}
	}
	return out
}

func tokenizeWords(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !unicode.IsLetter(r) && r != '\''
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.Trim(strings.ToLower(f), "'")
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func minf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
