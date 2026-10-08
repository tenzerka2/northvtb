package httpapi

import (
	"testing"
)

func TestStrictJSON(t *testing.T) {
	for _, s := range []string{`null`, `[]`, `{"agent_id":"a","agent_id":"b","mandate_id":"m"}`, `{"agent_id":"a","mandate_id":"m","extra":1}`, `{"agent_id":"a"} {}`, "{\"agent_id\":\"\xff\"}"} {
		var v RevokeRequest
		if strict([]byte(s), &v) == nil {
			t.Fatalf("accepted %q", s)
		}
	}
	var v RevokeRequest
	if e := strict([]byte(`{"agent_id":"a","mandate_id":"m"}`), &v); e != nil {
		t.Fatal(e)
	}
}

func TestRateLimiterBound(t *testing.T) {
	l := NewLimiter()
	if !l.Allow("a", 0, 2) || !l.Allow("a", 0, 2) || l.Allow("a", 0, 2) {
		t.Fatal("burst not enforced")
	}
	if !l.Allow("b", 0, 2) {
		t.Fatal("principal isolation failed")
	}
}
