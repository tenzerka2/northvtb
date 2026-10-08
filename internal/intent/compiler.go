// Package intent defines an optional untrusted natural-language adapter.
package intent

import (
	"context"
	"github.com/tenzerka2/northvtb/internal/trust"
)

// Compiler may suggest terms only. Identity, version and lifecycle fields must
// be overwritten by trust.Service.Draft and separately approved by the owner.
// No compiler is called by authorization or enforcement.
type Compiler interface {
	Draft(context.Context, string) (trust.Terms, error)
}
