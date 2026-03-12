package hook

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"net"
	"regexp"
	"strings"

	"hooky/internal/config"
)

// ValidateSecret checks the hook's top-level secret against the request.
// It returns (false, nil) when the secret is present but does not match —
// the caller should treat this as a 403, not an error.
func ValidateSecret(secret config.Secret, req *RequestData) (bool, error) {
	resolved, err := config.ResolveValue(secret.Value)
	if err != nil {
		return false, fmt.Errorf("resolving secret value: %w", err)
	}

	switch secret.Type {
	case "token":
		provided := tokenFromRequest(req, secret.Header, secret.Query)
		if provided == "" {
			return false, nil
		}
		return hmac.Equal([]byte(provided), []byte(resolved)), nil

	case "hmac-sha1":
		return verifyHMAC(req, secret.Header, resolved, sha1.New)
	case "hmac-sha256":
		return verifyHMAC(req, secret.Header, resolved, sha256.New)
	case "hmac-sha512":
		return verifyHMAC(req, secret.Header, resolved, sha512.New)

	default:
		return false, fmt.Errorf("unknown secret type %q (expected: hmac-sha1, hmac-sha256, hmac-sha512, token)", secret.Type)
	}
}

// EvaluateRule evaluates a trigger rule against the request data.
func EvaluateRule(rule config.Rule, req *RequestData) (bool, error) {
	switch {
	case len(rule.And) > 0:
		for i, sub := range rule.And {
			ok, err := EvaluateRule(sub, req)
			if err != nil {
				return false, fmt.Errorf("and[%d]: %w", i, err)
			}
			if !ok {
				return false, nil
			}
		}
		return true, nil

	case len(rule.Or) > 0:
		for i, sub := range rule.Or {
			ok, err := EvaluateRule(sub, req)
			if err != nil {
				return false, fmt.Errorf("or[%d]: %w", i, err)
			}
			if ok {
				return true, nil
			}
		}
		return false, nil

	case rule.Not != nil:
		ok, err := EvaluateRule(*rule.Not, req)
		if err != nil {
			return false, fmt.Errorf("not: %w", err)
		}
		return !ok, nil

	case rule.Match != nil:
		return evaluateMatch(*rule.Match, req)

	default:
		return false, fmt.Errorf("rule has no conditions (and/or/not/match)")
	}
}

func evaluateMatch(m config.MatchRule, req *RequestData) (bool, error) {
	switch m.Type {
	case "value":
		val, err := ExtractValue(req, m.Parameter)
		if err != nil {
			return false, err
		}
		return val == m.Value, nil

	case "regex":
		val, err := ExtractValue(req, m.Parameter)
		if err != nil {
			return false, err
		}
		matched, err := regexp.MatchString(m.Value, val)
		if err != nil {
			return false, fmt.Errorf("invalid regex %q: %w", m.Value, err)
		}
		return matched, nil

	case "ip-whitelist":
		_, ipNet, err := net.ParseCIDR(m.IPRange)
		if err != nil {
			return false, fmt.Errorf("invalid CIDR %q: %w", m.IPRange, err)
		}
		ip := net.ParseIP(req.RemoteIP)
		if ip == nil {
			return false, fmt.Errorf("cannot parse remote IP %q", req.RemoteIP)
		}
		return ipNet.Contains(ip), nil

	case "payload-hmac-sha1":
		return verifyHMACFromParam(m, req, sha1.New)
	case "payload-hmac-sha256":
		return verifyHMACFromParam(m, req, sha256.New)
	case "payload-hmac-sha512":
		return verifyHMACFromParam(m, req, sha512.New)

	default:
		return false, fmt.Errorf("unknown match type %q", m.Type)
	}
}

// verifyHMAC checks an HMAC signature supplied in a request header.
func verifyHMAC(req *RequestData, header, secret string, hashFn func() hash.Hash) (bool, error) {
	sig := req.Headers.Get(header)
	if sig == "" {
		return false, nil
	}
	return compareHMAC(sig, secret, req.RawBody, hashFn)
}

// verifyHMACFromParam checks an HMAC signature extracted via a Parameter reference.
func verifyHMACFromParam(m config.MatchRule, req *RequestData, hashFn func() hash.Hash) (bool, error) {
	sig, err := ExtractValue(req, m.Parameter)
	if err != nil {
		return false, fmt.Errorf("extracting signature: %w", err)
	}
	secret, err := config.ResolveValue(m.Secret)
	if err != nil {
		return false, fmt.Errorf("resolving HMAC secret: %w", err)
	}
	return compareHMAC(sig, secret, req.RawBody, hashFn)
}

func compareHMAC(sig, secret string, body []byte, hashFn func() hash.Hash) (bool, error) {
	// Strip common prefixes like "sha256=", "sha1=", "v0=".
	if _, after, found := strings.Cut(sig, "="); found {
		sig = after
	}
	mac := hmac.New(hashFn, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected)), nil
}

func tokenFromRequest(req *RequestData, header, query string) string {
	if header != "" {
		v := req.Headers.Get(header)
		// Strip "Bearer " prefix if present.
		v = strings.TrimPrefix(v, "Bearer ")
		return v
	}
	if query != "" {
		return req.Query[query]
	}
	return ""
}
