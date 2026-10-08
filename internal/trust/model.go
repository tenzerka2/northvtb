package trust

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/tenzerka2/northvtb/internal/cryptography"
	"github.com/tenzerka2/northvtb/internal/domain"
)

var ErrDenied = errors.New("trust denied")
var ErrConflict = errors.New("conflicting state")
var ErrNotFound = errors.New("not found")

func ID() string {
	var b [24]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func valid(s string) bool {
	if len(s) < 1 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

type Agent struct {
	ID, Owner, Provider, CredentialRef string
	Version                            int64
	Status                             string
	Risk                               int
	CreatedAt, RevokedAt               int64
}
type Terms struct {
	SchemaVersion     int           `json:"schema_version"`
	ID                string        `json:"id"`
	Version           int64         `json:"version"`
	PredecessorID     string        `json:"predecessor_id"`
	Owner             string        `json:"owner"`
	AgentID           string        `json:"agent_id"`
	Action            string        `json:"action"`
	Purpose           string        `json:"purpose"`
	Product           string        `json:"product"`
	Category          string        `json:"category"`
	Condition         string        `json:"condition"`
	MaxAmount         domain.Amount `json:"max_amount"`
	Currency          string        `json:"currency"`
	Merchants         []string      `json:"merchants"`
	RequireVerified   bool          `json:"require_verified"`
	AllowRiskApproval bool          `json:"allow_risk_approval"`
	MaxRisk           int           `json:"max_risk"`
	MaxUses           int64         `json:"max_uses"`
	CreatedAt         int64         `json:"created_at"`
	ExpiresAt         int64         `json:"expires_at"`
}

func (m Terms) Canonical() ([]byte, error) {
	if m.SchemaVersion != 1 || !valid(m.ID) || !valid(m.AgentID) || m.Version < 1 || m.Owner == "" || len(m.Owner) > 512 || m.Action != "purchase" || m.MaxAmount <= 0 || m.MaxUses < 1 || m.MaxUses > 1000000 || m.MaxRisk < 0 || m.MaxRisk > 100 || m.CreatedAt <= 0 || m.ExpiresAt <= m.CreatedAt {
		return nil, domain.ErrInvalid
	}
	if m.PredecessorID != "" && !valid(m.PredecessorID) {
		return nil, domain.ErrInvalid
	}
	if (m.Version == 1) != (m.PredecessorID == "") {
		return nil, domain.ErrInvalid
	}
	if m.Condition != "new" && m.Condition != "used" {
		return nil, domain.ErrInvalid
	}
	for _, s := range []string{m.Owner, m.Purpose, m.Product, m.Category} {
		if !utf8.ValidString(s) || strings.TrimSpace(s) == "" || len(s) > 512 {
			return nil, domain.ErrInvalid
		}
	}
	if len(m.Currency) != 3 {
		return nil, domain.ErrInvalid
	}
	for _, c := range m.Currency {
		if c < 'A' || c > 'Z' {
			return nil, domain.ErrInvalid
		}
	}
	if len(m.Merchants) > 100 {
		return nil, domain.ErrInvalid
	}
	m.Merchants = append([]string{}, m.Merchants...)
	sort.Strings(m.Merchants)
	for i, s := range m.Merchants {
		if !valid(s) || (i > 0 && s == m.Merchants[i-1]) {
			return nil, domain.ErrInvalid
		}
	}
	return json.Marshal(m)
}
func (m Terms) Digest() (string, error) {
	b, e := m.Canonical()
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(append([]byte("north:mandate-digest:v1\x00"), b...))
	return hex.EncodeToString(h[:]), nil
}

type Mandate struct {
	Terms              Terms
	State              domain.MandateState
	Signature          cryptography.Signature
	ApprovedAt         int64
	Reserved, Consumed int64
}
