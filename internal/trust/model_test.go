package trust

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/tenzerka2/northvtb/internal/cryptography"
	"github.com/tenzerka2/northvtb/internal/domain"
	"testing"
)

func terms() Terms {
	return Terms{SchemaVersion: 1, ID: "m", Version: 1, Owner: "issuer|user", AgentID: "a", Action: "purchase", Purpose: "console", Product: "PS5-Pro", Category: "gaming", Condition: "new", MaxAmount: 8500000, Currency: "RUB", Merchants: []string{"b", "a"}, RequireVerified: true, MaxRisk: 20, MaxUses: 1, CreatedAt: 100, ExpiresAt: 200}
}
func TestCanonicalAndSignature(t *testing.T) {
	_, key, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c, e := cryptography.NewEd25519("k", key)
	if e != nil {
		t.Fatal(e)
	}
	s := Service{Crypto: c, Now: func() int64 { return 150 }}
	ctx := context.Background()
	v := terms()
	b, e := v.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	sig, e := c.Sign(ctx, cryptography.MandateV1, b)
	if e != nil {
		t.Fatal(e)
	}
	a := Agent{ID: "a", Owner: v.Owner, Status: "ACTIVE"}
	m := Mandate{Terms: v, State: domain.Active, Signature: sig, ApprovedAt: 110}
	if e = s.Verify(ctx, a, m); e != nil {
		t.Fatal(e)
	}
	sorted := v
	sorted.Merchants = []string{"a", "b"}
	h, _ := v.Digest()
	h2, _ := sorted.Digest()
	if h != h2 {
		t.Fatal("set order changed canonical digest")
	}
	bad := m
	bad.Terms.MaxAmount++
	if s.Verify(ctx, a, bad) == nil {
		t.Fatal("tampered mandate accepted")
	}
	bad = m
	bad.State = domain.Revoked
	if s.Verify(ctx, a, bad) == nil {
		t.Fatal("revoked accepted")
	}
	bad = m
	bad.Signature.KeyID = "attacker"
	if s.Verify(ctx, a, bad) == nil {
		t.Fatal("key substitution accepted")
	}
	a.Status = "REVOKED"
	if s.Verify(ctx, a, m) == nil {
		t.Fatal("revoked agent accepted")
	}
	a.Status = "ACTIVE"
	a.ID = "stolen"
	if s.Verify(ctx, a, m) == nil {
		t.Fatal("stolen mandate accepted")
	}
	a.ID = "a"
	s.Now = func() int64 { return 200 }
	if s.Verify(ctx, a, m) == nil {
		t.Fatal("expiry boundary accepted")
	}
	if c.Verify(ctx, cryptography.GrantV1, b, sig) == nil {
		t.Fatal("cross-purpose signature accepted")
	}
}

func TestMerchantApprovalPreservesLegacyCanonicalBytes(t *testing.T) {
	v := terms()
	raw, e := v.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	const legacy = `{"schema_version":1,"id":"m","version":1,"predecessor_id":"","owner":"issuer|user","agent_id":"a","action":"purchase","purpose":"console","product":"PS5-Pro","category":"gaming","condition":"new","max_amount":8500000,"currency":"RUB","merchants":["a","b"],"require_verified":true,"allow_risk_approval":false,"max_risk":20,"max_uses":1,"created_at":100,"expires_at":200}`
	if string(raw) != legacy {
		t.Fatal("legacy signed payload changed")
	}
	before, _ := v.Digest()
	v.AllowMerchantApproval = true
	after, _ := v.Digest()
	if before == after {
		t.Fatal("new permission not signed")
	}
}
