package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

type Event struct {
	Version  int    `json:"version"`
	Sequence int64  `json:"sequence"`
	ID       string `json:"id"`
	At       int64  `json:"at"`
	Actor    string `json:"actor"`
	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	Previous string `json:"previous"`
}

func (e Event) Bytes() ([]byte, error) {
	if e.Version != 1 || e.Sequence < 1 || e.ID == "" || e.At <= 0 || e.Actor == "" || e.Kind == "" || e.Subject == "" {
		return nil, errors.New("invalid audit event")
	}
	p, x := hex.DecodeString(e.Previous)
	if x != nil || len(p) != 32 {
		return nil, errors.New("invalid previous digest")
	}
	return json.Marshal(e)
}
func Hash(b []byte) []byte {
	h := sha256.Sum256(append([]byte("north:audit-event:v1\x00"), b...))
	return h[:]
}
