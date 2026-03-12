// Package hook handles request parsing, rule evaluation, and command execution.
package hook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"hooky/internal/config"
)

// RequestData holds the parsed representation of an incoming HTTP request.
type RequestData struct {
	// Payload is the parsed JSON body (nil for non-JSON or unparseable bodies).
	Payload map[string]any

	// Headers are the raw HTTP request headers.
	Headers http.Header

	// Query contains URL query parameters (first value per key).
	Query map[string]string

	// RawBody is the unmodified request body bytes.
	RawBody []byte

	// RemoteIP is the resolved client IP (may be from a proxy header).
	RemoteIP string
}

// ExtractValue retrieves a single string value from the request using a Parameter spec.
func ExtractValue(req *RequestData, param config.Parameter) (string, error) {
	switch param.Source {
	case "payload":
		return extractFromPayload(req.Payload, param.Name)

	case "header":
		return req.Headers.Get(param.Name), nil

	case "query":
		v, ok := req.Query[param.Name]
		if !ok {
			return "", fmt.Errorf("query parameter %q not found", param.Name)
		}
		return v, nil

	case "request":
		switch param.Name {
		case "remote-addr":
			return req.RemoteIP, nil
		default:
			return "", fmt.Errorf("unknown request field %q", param.Name)
		}

	case "entire-payload":
		if req.Payload == nil {
			return string(req.RawBody), nil
		}
		b, err := json.Marshal(req.Payload)
		if err != nil {
			return "", fmt.Errorf("marshaling entire payload: %w", err)
		}
		return string(b), nil

	case "entire-headers":
		b, err := json.Marshal(req.Headers)
		if err != nil {
			return "", fmt.Errorf("marshaling entire headers: %w", err)
		}
		return string(b), nil

	case "entire-query":
		b, err := json.Marshal(req.Query)
		if err != nil {
			return "", fmt.Errorf("marshaling entire query: %w", err)
		}
		return string(b), nil

	case "raw-body":
		return string(req.RawBody), nil

	case "literal":
		// Returns the Name field as a hard-coded string value.
		// Useful for passing static arguments to commands.
		return param.Name, nil

	default:
		return "", fmt.Errorf("unknown parameter source %q", param.Source)
	}
}

// extractFromPayload retrieves a value using dot-notation from a parsed JSON map.
// For example, "repository.full_name" drills into {"repository": {"full_name": "..."}}
func extractFromPayload(payload map[string]any, name string) (string, error) {
	if payload == nil {
		return "", fmt.Errorf("request payload is empty or not JSON")
	}

	key, rest, nested := strings.Cut(name, ".")
	val, ok := payload[key]
	if !ok {
		return "", fmt.Errorf("payload field %q not found", key)
	}

	if nested {
		child, ok := val.(map[string]any)
		if !ok {
			return "", fmt.Errorf("payload field %q is not an object", key)
		}
		return extractFromPayload(child, rest)
	}

	return anyToString(val)
}

func anyToString(v any) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case float64:
		// Avoid scientific notation for whole numbers (common for IDs).
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t)), nil
		}
		return fmt.Sprintf("%g", t), nil
	case bool:
		if t {
			return "true", nil
		}
		return "false", nil
	case nil:
		return "", nil
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}
