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
