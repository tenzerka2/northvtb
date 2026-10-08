// Generates the checked-in OpenAPI contract from implemented DTOs.
package main

import (
	"encoding/json"
	"github.com/tenzerka2/northvtb/internal/authorization"
	"github.com/tenzerka2/northvtb/internal/payments"
	"github.com/tenzerka2/northvtb/internal/platform/httpapi"
	"github.com/tenzerka2/northvtb/internal/policy"
	"github.com/tenzerka2/northvtb/internal/trust"
	"os"
	"reflect"
	"strings"
)

type M = map[string]any

var schemas = M{}

func schema(t reflect.Type) M {
	if t.Kind() == reflect.Pointer {
		return schema(t.Elem())
	}
	switch t.Kind() {
	case reflect.String:
		s := M{"type": "string"}
		switch t.Name() {
		case "Decision":
			s["enum"] = []string{"ALLOW", "DENY", "ASK_USER"}
		case "MandateState":
			s["enum"] = []string{"DRAFT", "ACTIVE", "REVOKED", "EXPIRED", "CONSUMED"}
		case "PaymentState":
			s["enum"] = []string{"PENDING", "SUBMITTED", "UNKNOWN", "SUCCEEDED", "FAILED", "CANCELLED"}
		}
		return s
	case reflect.Int, reflect.Int64:
		return M{"type": "integer", "format": "int64"}
	case reflect.Bool:
		return M{"type": "boolean"}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return M{"type": []string{"string", "null"}, "contentEncoding": "base64"}
		}
		return M{"type": []string{"array", "null"}, "items": schema(t.Elem())}
	case reflect.Struct:
		name := t.Name()
		if name != "" {
			if _, ok := schemas[name]; ok {
				return M{"$ref": "#/components/schemas/" + name}
			}
			schemas[name] = M{}
		}
		properties := M{}
		required := []string{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("json"), ",")
			if tag[0] == "-" {
				continue
			}
			n := tag[0]
			if n == "" {
				n = f.Name
			}
			properties[n] = schema(f.Type)
			if !strings.Contains(f.Tag.Get("json"), "omitempty") {
				required = append(required, n)
			}
		}
		s := M{"type": "object", "properties": properties, "additionalProperties": false}
		if len(required) > 0 {
			s["required"] = required
		}
		if name != "" {
			schemas[name] = s
			return M{"$ref": "#/components/schemas/" + name}
		}
		return s
	}
	panic("unsupported API type")
}
func obj(properties M, required ...string) M {
	return M{"type": "object", "properties": properties, "required": required, "additionalProperties": false}
}
func content(s M) M { return M{"application/json": M{"schema": s}} }
func main() {
	paths := M{}
	errorSchema := schema(reflect.TypeOf(httpapi.ErrorResponse{}))
	str := M{"type": "string"}
	status := obj(M{"status": str}, "status")
	add := func(path, method, summary string, req any, response M, auth string) {
		responses := M{"200": M{"description": "Successful result; payment/refund commands may still be PENDING", "content": content(response)}}
		for _, code := range []string{"400", "401", "403", "404", "409", "422", "429", "500", "503"} {
			responses[code] = M{"description": "Safe structured error; see error.code", "content": content(errorSchema)}
		}
		op := M{"summary": summary, "responses": responses}
		if auth != "" {
			op["security"] = []any{M{auth: []string{}}}
		}
		params := []any{}
		if method == "post" {
			op["requestBody"] = M{"required": true, "content": content(schema(reflect.TypeOf(req)))}
			if auth != "callbackHMAC" {
				params = append(params, M{"in": "header", "name": "Idempotency-Key", "required": true, "schema": M{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[!-~]+$"}})
			}
		}
		if strings.Contains(path, "{") {
			name := strings.Split(strings.Split(path, "{")[1], "}")[0]
			params = append(params, M{"in": "path", "name": name, "required": true, "schema": str})
		}
		if path == "/v1/offers" {
			params = append(params, M{"in": "query", "name": "product", "required": true, "schema": str})
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
		paths[path] = M{method: op}
	}
	add("/healthz", "get", "Process liveness", nil, status, "")
	add("/readyz", "get", "Dependency readiness; foundation mode always returns 503", nil, status, "")
	add("/v1/agents", "post", "Owner: register sandbox agent and receive credential once (retry returns same credential)", struct{}{}, obj(M{"agent_id": str, "agent_token": str, "agent": schema(reflect.TypeOf(trust.Agent{}))}, "agent_id", "agent_token", "agent"), "bearer")
	add("/v1/mandates", "post", "Owner: create draft; server replaces identity/version/creation fields", httpapi.DraftRequest{}, obj(M{"mandate_id": str, "digest": str, "mandate": schema(reflect.TypeOf(trust.Mandate{}))}, "mandate_id", "digest", "mandate"), "bearer")
	add("/v1/mandates/approve", "post", "Owner: explicitly approve exact canonical digest", httpapi.ApprovalRequest{}, schema(reflect.TypeOf(trust.Mandate{})), "bearer")
	add("/v1/mandates/revoke", "post", "Owner: revoke mandate", httpapi.RevokeRequest{}, status, "bearer")
	add("/v1/agents/revoke", "post", "Owner: revoke agent", struct {
		AgentID string `json:"agent_id"`
	}{}, status, "bearer")
	add("/v1/authorizations", "post", "Agent: evaluate proposal; return ALLOW grant, DENY trace or ASK_USER challenge", httpapi.AuthorizationRequest{}, schema(reflect.TypeOf(authorization.Response{})), "bearer")
	add("/v1/payments", "post", "Agent: enforce grant and enqueue one durable command; provider is worker-only", httpapi.ExecutionRequest{}, obj(M{"payment_id": str, "state": M{"const": "PENDING"}}, "payment_id", "state"), "bearer")
	add("/v1/challenges/approve", "post", "Owner: approve exact risk challenge; then agent retries with a new idempotency key", httpapi.RiskRequest{}, status, "bearer")
	add("/v1/refunds", "post", "Owner: enqueue full refund; no mandate capacity is restored", httpapi.RefundRequest{}, obj(M{"refund_id": str, "state": M{"const": "PENDING"}}, "refund_id", "state"), "bearer")
	add("/v1/mandates/{mandate_id}", "get", "Owner or bound agent: read current mandate", nil, schema(reflect.TypeOf(trust.Mandate{})), "bearer")
	add("/v1/payments/{payment_id}", "get", "Owner or bound agent: read current payment state", nil, obj(M{"payment_id": str, "state": str}, "payment_id", "state"), "bearer")
	add("/v1/offers", "get", "Authenticated structured merchant catalogue", nil, M{"type": "array", "items": schema(reflect.TypeOf(policy.Offer{}))}, "bearer")
	add("/v1/provider/callback", "post", "Sandbox provider: HMAC-authenticated, event-id-deduplicated result", payments.Callback{}, status, "callbackHMAC")
	// Draft input omits fields generated by the server. Canonical Terms responses retain them.
	terms := schemas["Terms"].(M)
	props := M{}
	for k, v := range terms["properties"].(M) {
		switch k {
		case "schema_version", "id", "version", "predecessor_id", "owner", "created_at":
		default:
			props[k] = v
		}
	}
	schemas["NewTerms"] = obj(props, "agent_id", "action", "purpose", "product", "category", "condition", "max_amount", "currency", "max_uses", "expires_at")
	schemas["DraftRequest"] = obj(M{"terms": M{"$ref": "#/components/schemas/NewTerms"}}, "terms")
	doc := M{"openapi": "3.1.0", "info": M{"title": "NORTH sandbox authorization API", "version": "0.4.0", "description": "Amounts are integer minor units (RUB kopecks). Timestamps are UTC Unix seconds. Owner and agent credentials are distinct. Sandbox adapter only; production OIDC is a replaceable authentication boundary. No real funds. Idempotency keys are scoped by principal+operation; canonical typed JSON is compared and changed bodies return 409. GET current state after an idempotent retry because the stored response may say PENDING."}, "paths": paths, "components": M{"schemas": schemas, "securitySchemes": M{"bearer": M{"type": "http", "scheme": "bearer", "description": "Sandbox owner or registered agent credential"}, "callbackHMAC": M{"type": "apiKey", "in": "header", "name": "X-Sandbox-Signature", "description": "Hex HMAC-SHA256 over purpose prefix plus canonical Callback JSON"}}}}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if e := enc.Encode(doc); e != nil {
		panic(e)
	}
}
