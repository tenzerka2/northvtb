package payments

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/tenzerka2/northvtb/internal/domain"
)

type Callback struct {
	Provider  string              `json:"provider"`
	EventID   string              `json:"event_id"`
	PaymentID string              `json:"payment_id"`
	Amount    domain.Amount       `json:"amount"`
	Currency  string              `json:"currency"`
	Status    domain.PaymentState `json:"status"`
}

func (c Callback) Bytes() ([]byte, error) {
	if c.Provider != "sandbox" || c.EventID == "" || len(c.EventID) > 128 || c.PaymentID == "" || c.Amount <= 0 || (c.Status != domain.Succeeded && c.Status != domain.Failed) {
		return nil, errors.New("invalid callback")
	}
	return json.Marshal(c)
}
func SignCallback(secret []byte, c Callback) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("callback secret too short")
	}
	b, e := c.Bytes()
	if e != nil {
		return "", e
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte("north:sandbox-callback:v1\x00"))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}
func VerifyCallback(secret []byte, c Callback, mac string) error {
	expected, e := SignCallback(secret, c)
	if e != nil {
		return e
	}
	want, _ := hex.DecodeString(expected)
	got, e := hex.DecodeString(mac)
	if e != nil || !hmac.Equal(want, got) {
		return errors.New("invalid callback authentication")
	}
	return nil
}
