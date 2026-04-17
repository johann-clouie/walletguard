package storage

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/example/walletguard/internal/domain"
	"github.com/example/walletguard/migrations"
)

// PostgresStore persists findings and incidents (masked secrets only).
type PostgresStore struct {
	Pool *pgxpool.Pool
}

// ConnectPostgres opens a pool and applies embedded DDL.
func ConnectPostgres(ctx context.Context, dsn string) (*PostgresStore, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := pool.Exec(ctx, migrations.SQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &PostgresStore{Pool: pool}, nil
}

// Close releases the pool.
func (s *PostgresStore) Close() { s.Pool.Close() }

// EnsureSource returns source id, creating row if needed.
func (s *PostgresStore) EnsureSource(ctx context.Context, name, typ string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO sources (name, type) VALUES ($1, $2)
		ON CONFLICT (name, type) DO UPDATE SET name = EXCLUDED.name
		RETURNING id
	`, name, typ).Scan(&id)
	return id, err
}

// InsertDocument stores document metadata and returns id.
func (s *PostgresStore) InsertDocument(ctx context.Context, sourceID uuid.UUID, doc domain.Document) (uuid.UUID, error) {
	meta, _ := json.Marshal(doc.Metadata)
	h := doc.Metadata["sha256"]
	if h == "" {
		h = doc.ID
	}
	var id uuid.UUID
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO documents (source_id, path, content_hash, content_type, ts, metadata_json)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (source_id, path, content_hash) DO UPDATE SET ts = EXCLUDED.ts
		RETURNING id
	`, sourceID, doc.Path, h, doc.ContentType, doc.Timestamp, meta).Scan(&id)
	return id, err
}

// InsertFinding persists a finding using the detector's UUID when valid.
func (s *PostgresStore) InsertFinding(ctx context.Context, docUUID uuid.UUID, f domain.Finding) (uuid.UUID, error) {
	fid, parseErr := uuid.Parse(f.ID)
	if parseErr != nil {
		fid = uuid.New()
	}
	meta, _ := json.Marshal(f.Metadata)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO findings (id, document_id, secret_type, chain_family, masked_value, confidence, line_start, line_end, metadata_json)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO NOTHING
	`, fid, docUUID, string(f.SecretType), string(f.ChainFamily), f.MaskedValue, f.Confidence, f.LineStart, f.LineEnd, meta)
	return fid, err
}

// InsertVerification stores verification output.
func (s *PostgresStore) InsertVerification(ctx context.Context, findingID uuid.UUID, v domain.VerificationResult) error {
	addrs, _ := json.Marshal(v.DerivedAddresses)
	details, _ := json.Marshal(v.Details)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO verifications (finding_id, is_valid, derived_addresses_json, details_json, verified_at)
		VALUES ($1, $2, $3, $4, $5)
	`, findingID, v.IsValid, addrs, details, v.VerifiedAt)
	return err
}

// InsertRisk stores computed risk.
func (s *PostgresStore) InsertRisk(ctx context.Context, findingID uuid.UUID, rs domain.RiskScore) error {
	reasons, _ := json.Marshal(rs.Reasons)
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO risk_scores (finding_id, severity, score, reasons_json, calculated_at)
		VALUES ($1, $2, $3, $4, $5)
	`, findingID, string(rs.Severity), rs.Score, reasons, rs.CalculatedAt)
	return err
}

// InsertIncident stores an incident row using inc.ID as primary key when valid UUID.
func (s *PostgresStore) InsertIncident(ctx context.Context, inc domain.Incident, findingUUID uuid.UUID) (uuid.UUID, error) {
	iid, parseErr := uuid.Parse(inc.ID)
	if parseErr != nil {
		iid = uuid.New()
	}
	_, execErr := s.Pool.Exec(ctx, `
		INSERT INTO incidents (id, finding_id, title, status, owner, playbook_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (id) DO NOTHING
	`, iid, findingUUID, inc.Title, string(inc.Status), inc.Owner, inc.PlaybookName, inc.CreatedAt, inc.UpdatedAt)
	return iid, execErr
}

// FindingRow is an API projection.
type FindingRow struct {
	ID          string
	SecretType  string
	ChainFamily string
	MaskedValue string
	Confidence  float64
	LineStart   int
	LineEnd     int
	CreatedAt   interface{}
	Path        string
	Severity    string
	Score       float64
}

// ListFindings returns recent findings with latest risk severity.
func (s *PostgresStore) ListFindings(ctx context.Context, limit int) ([]FindingRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT f.id::text, f.secret_type, f.chain_family, f.masked_value, f.confidence, f.line_start, f.line_end, f.created_at,
		       d.path, COALESCE(r.severity, ''), COALESCE(r.score, 0)
		FROM findings f
		JOIN documents d ON d.id = f.document_id
		LEFT JOIN LATERAL (
			SELECT severity, score FROM risk_scores WHERE finding_id = f.id ORDER BY calculated_at DESC LIMIT 1
		) r ON true
		ORDER BY f.created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var r FindingRow
		if err := rows.Scan(&r.ID, &r.SecretType, &r.ChainFamily, &r.MaskedValue, &r.Confidence, &r.LineStart, &r.LineEnd, &r.CreatedAt, &r.Path, &r.Severity, &r.Score); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// IncidentRow is an API projection.
type IncidentRow struct {
	ID           string
	Title        string
	Status       string
	PlaybookName string
	CreatedAt    interface{}
	FindingID    string
}

// ListIncidents returns incidents ordered by recency.
func (s *PostgresStore) ListIncidents(ctx context.Context, limit int) ([]IncidentRow, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT i.id::text, i.title, i.status, i.playbook_name, i.created_at, i.finding_id::text
		FROM incidents i
		ORDER BY i.created_at DESC
		LIMIT $1
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IncidentRow
	for rows.Next() {
		var r IncidentRow
		if err := rows.Scan(&r.ID, &r.Title, &r.Status, &r.PlaybookName, &r.CreatedAt, &r.FindingID); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetFinding loads one finding by id string.
func (s *PostgresStore) GetFinding(ctx context.Context, id string) (FindingRow, error) {
	var r FindingRow
	err := s.Pool.QueryRow(ctx, `
		SELECT f.id::text, f.secret_type, f.chain_family, f.masked_value, f.confidence, f.line_start, f.line_end, f.created_at,
		       d.path, COALESCE(r.severity, ''), COALESCE(r.score, 0)
		FROM findings f
		JOIN documents d ON d.id = f.document_id
		LEFT JOIN LATERAL (
			SELECT severity, score FROM risk_scores WHERE finding_id = f.id ORDER BY calculated_at DESC LIMIT 1
		) r ON true
		WHERE f.id::text = $1
	`, id).Scan(&r.ID, &r.SecretType, &r.ChainFamily, &r.MaskedValue, &r.Confidence, &r.LineStart, &r.LineEnd, &r.CreatedAt, &r.Path, &r.Severity, &r.Score)
	return r, err
}
