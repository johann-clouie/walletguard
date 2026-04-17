package domain

import "time"

// Document is normalized content from any connector.
type Document struct {
	ID          string
	Source      string
	Path        string
	ContentType string
	Content     []byte
	Metadata    map[string]string
	Timestamp   time.Time
}

// SecretType identifies the class of sensitive material.
type SecretType string

const (
	SecretMnemonic    SecretType = "mnemonic"
	SecretEVMKey      SecretType = "evm_private_key"
	SecretBitcoinWIF  SecretType = "bitcoin_wif"
	SecretSolanaKey   SecretType = "solana_keypair"
	SecretKeystore    SecretType = "ethereum_keystore"
	SecretRelated     SecretType = "related_secret"
)

// ChainFamily is a high-level chain grouping.
type ChainFamily string

const (
	ChainEVM    ChainFamily = "evm"
	ChainBitcoin ChainFamily = "bitcoin"
	ChainSolana ChainFamily = "solana"
	ChainTron   ChainFamily = "tron"
	ChainUnknown ChainFamily = "unknown"
)

// Finding is a detector hit before full verification.
type Finding struct {
	ID          string
	DocID       string
	SecretType  SecretType
	ChainFamily ChainFamily
	MaskedValue string
	Confidence  float64
	LineStart   int
	LineEnd     int
	RawSnippet  []byte // in-memory only during scan; not persisted by default
	Metadata    map[string]string
	CreatedAt   time.Time
}

// VerificationResult is offline validation output.
type VerificationResult struct {
	FindingID         string
	IsValid           bool
	DerivedAddresses  []string
	Details           map[string]string
	VerifiedAt        time.Time
}

// RiskScore is computed after verification (and optional enrichment).
type RiskScore struct {
	FindingID    string
	Severity     Severity
	Score        float64
	Reasons      []string
	CalculatedAt time.Time
}

// Severity levels.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Incident tracks response workflow.
type Incident struct {
	ID           string
	FindingID    string
	Title        string
	Status       IncidentStatus
	Owner        string
	PlaybookName string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// IncidentStatus workflow states.
type IncidentStatus string

const (
	StatusDetected     IncidentStatus = "detected"
	StatusTriaged      IncidentStatus = "triaged"
	StatusConfirmed    IncidentStatus = "confirmed"
	StatusFundsSecured IncidentStatus = "funds_secured"
	StatusKeysRotated  IncidentStatus = "keys_rotated"
	StatusMonitoring   IncidentStatus = "monitoring"
	StatusClosed       IncidentStatus = "closed"
)

// IncidentAction is an audit timeline entry.
type IncidentAction struct {
	ID         string
	IncidentID string
	ActionType string
	Actor      string
	Notes      string
	CreatedAt  time.Time
}
