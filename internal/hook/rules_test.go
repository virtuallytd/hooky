package hook_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"hooky/internal/config"
	"hooky/internal/hook"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func hmacSig(body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func reqWithHeader(key, val string) *hook.RequestData {
	h := make(http.Header)
	h.Set(key, val)
	return &hook.RequestData{Headers: h, RawBody: []byte("body"), RemoteIP: "127.0.0.1"}
}

// ── ValidateSecret ────────────────────────────────────────────────────────────

func TestValidateSecret_HMAC256_Valid(t *testing.T) {
	body := `{"ref":"main"}`
	sig := hmacSig(body, "mysecret")
	req := &hook.RequestData{
		Headers:  http.Header{"X-Hub-Signature-256": []string{sig}},
		RawBody:  []byte(body),
		RemoteIP: "1.2.3.4",
	}
	secret := config.Secret{Type: "hmac-sha256", Header: "X-Hub-Signature-256", Value: "mysecret"}
	ok, err := hook.ValidateSecret(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected valid HMAC")
	}
}

func TestValidateSecret_HMAC256_Invalid(t *testing.T) {
	body := `{"ref":"main"}`
	sig := hmacSig(body, "wrong-secret")
	req := &hook.RequestData{
		Headers:  http.Header{"X-Hub-Signature-256": []string{sig}},
		RawBody:  []byte(body),
		RemoteIP: "1.2.3.4",
	}
	secret := config.Secret{Type: "hmac-sha256", Header: "X-Hub-Signature-256", Value: "mysecret"}
	ok, err := hook.ValidateSecret(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected invalid HMAC")
	}
}

func TestValidateSecret_HMAC256_MissingHeader(t *testing.T) {
	req := &hook.RequestData{Headers: http.Header{}, RawBody: []byte("body"), RemoteIP: "1.2.3.4"}
	secret := config.Secret{Type: "hmac-sha256", Header: "X-Hub-Signature-256", Value: "mysecret"}
	ok, err := hook.ValidateSecret(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected false when header is absent")
	}
}

func TestValidateSecret_Token_Valid(t *testing.T) {
	req := reqWithHeader("X-Token", "supersecret")
	secret := config.Secret{Type: "token", Header: "X-Token", Value: "supersecret"}
	ok, err := hook.ValidateSecret(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected valid token")
	}
}

func TestValidateSecret_Token_Bearer(t *testing.T) {
	req := reqWithHeader("Authorization", "Bearer mytoken")
	secret := config.Secret{Type: "token", Header: "Authorization", Value: "mytoken"}
	ok, err := hook.ValidateSecret(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected Bearer prefix to be stripped")
	}
}

func TestValidateSecret_Token_Invalid(t *testing.T) {
	req := reqWithHeader("X-Token", "wrong")
	secret := config.Secret{Type: "token", Header: "X-Token", Value: "correct"}
	ok, err := hook.ValidateSecret(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected invalid token")
	}
}

func TestValidateSecret_Token_ViaQuery(t *testing.T) {
	req := &hook.RequestData{
		Headers:  http.Header{},
		Query:    map[string]string{"token": "qsecret"},
		RawBody:  []byte(""),
		RemoteIP: "1.2.3.4",
	}
	secret := config.Secret{Type: "token", Query: "token", Value: "qsecret"}
	ok, err := hook.ValidateSecret(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected valid query token")
	}
}

func TestValidateSecret_EnvResolution(t *testing.T) {
	t.Setenv("HOOK_TEST_SECRET", "envvalue")
	body := `{}`
	sig := hmacSig(body, "envvalue")
	req := &hook.RequestData{
		Headers:  http.Header{"X-Sig": []string{sig}},
		RawBody:  []byte(body),
		RemoteIP: "1.2.3.4",
	}
	secret := config.Secret{Type: "hmac-sha256", Header: "X-Sig", Value: "env:HOOK_TEST_SECRET"}
	ok, err := hook.ValidateSecret(secret, req)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected valid HMAC using env-resolved secret")
	}
}

func TestValidateSecret_UnknownType(t *testing.T) {
	req := reqWithHeader("X-Sig", "value")
	secret := config.Secret{Type: "md5", Header: "X-Sig", Value: "secret"}
	_, err := hook.ValidateSecret(secret, req)
	if err == nil {
		t.Fatal("expected error for unknown secret type")
	}
}

// ── EvaluateRule ──────────────────────────────────────────────────────────────

func req(payload map[string]any, remoteIP string) *hook.RequestData {
	return &hook.RequestData{
		Payload:  payload,
		Headers:  http.Header{},
		Query:    map[string]string{},
		RawBody:  []byte(""),
		RemoteIP: remoteIP,
	}
}

func TestEvaluateRule_ValueMatch(t *testing.T) {
	r := &hook.RequestData{
		Payload:  map[string]any{"event": "push"},
		Headers:  http.Header{},
		Query:    map[string]string{},
		RemoteIP: "1.2.3.4",
	}
	rule := config.Rule{Match: &config.MatchRule{
		Type:      "value",
		Parameter: config.Parameter{Source: "payload", Name: "event"},
		Value:     "push",
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected match")
	}
}

func TestEvaluateRule_ValueNoMatch(t *testing.T) {
	r := req(map[string]any{"event": "pr"}, "1.2.3.4")
	rule := config.Rule{Match: &config.MatchRule{
		Type:      "value",
		Parameter: config.Parameter{Source: "payload", Name: "event"},
		Value:     "push",
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected no match")
	}
}

func TestEvaluateRule_Regex(t *testing.T) {
	r := req(map[string]any{"ref": "refs/heads/main"}, "1.2.3.4")
	rule := config.Rule{Match: &config.MatchRule{
		Type:      "regex",
		Parameter: config.Parameter{Source: "payload", Name: "ref"},
		Value:     `^refs/heads/(main|master)$`,
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected regex match")
	}
}

func TestEvaluateRule_Regex_NoMatch(t *testing.T) {
	r := req(map[string]any{"ref": "refs/heads/feature"}, "1.2.3.4")
	rule := config.Rule{Match: &config.MatchRule{
		Type:      "regex",
		Parameter: config.Parameter{Source: "payload", Name: "ref"},
		Value:     `^refs/heads/(main|master)$`,
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected no regex match")
	}
}

func TestEvaluateRule_IPWhitelist_Allow(t *testing.T) {
	r := req(nil, "192.168.1.50")
	rule := config.Rule{Match: &config.MatchRule{
		Type:    "ip-whitelist",
		IPRange: "192.168.1.0/24",
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected IP to be in whitelist")
	}
}

func TestEvaluateRule_IPWhitelist_Deny(t *testing.T) {
	r := req(nil, "10.0.0.1")
	rule := config.Rule{Match: &config.MatchRule{
		Type:    "ip-whitelist",
		IPRange: "192.168.1.0/24",
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected IP to be denied")
	}
}

func TestEvaluateRule_And_AllTrue(t *testing.T) {
	r := req(map[string]any{"a": "1", "b": "2"}, "1.2.3.4")
	rule := config.Rule{And: []config.Rule{
		{Match: &config.MatchRule{Type: "value", Parameter: config.Parameter{Source: "payload", Name: "a"}, Value: "1"}},
		{Match: &config.MatchRule{Type: "value", Parameter: config.Parameter{Source: "payload", Name: "b"}, Value: "2"}},
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected AND to be true")
	}
}

func TestEvaluateRule_And_OneFalse(t *testing.T) {
	r := req(map[string]any{"a": "1", "b": "wrong"}, "1.2.3.4")
	rule := config.Rule{And: []config.Rule{
		{Match: &config.MatchRule{Type: "value", Parameter: config.Parameter{Source: "payload", Name: "a"}, Value: "1"}},
		{Match: &config.MatchRule{Type: "value", Parameter: config.Parameter{Source: "payload", Name: "b"}, Value: "2"}},
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected AND to be false")
	}
}

func TestEvaluateRule_Or_OneTrue(t *testing.T) {
	r := req(map[string]any{"event": "push"}, "1.2.3.4")
	rule := config.Rule{Or: []config.Rule{
		{Match: &config.MatchRule{Type: "value", Parameter: config.Parameter{Source: "payload", Name: "event"}, Value: "push"}},
		{Match: &config.MatchRule{Type: "value", Parameter: config.Parameter{Source: "payload", Name: "event"}, Value: "create"}},
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected OR to be true")
	}
}

func TestEvaluateRule_Or_AllFalse(t *testing.T) {
	r := req(map[string]any{"event": "delete"}, "1.2.3.4")
	rule := config.Rule{Or: []config.Rule{
		{Match: &config.MatchRule{Type: "value", Parameter: config.Parameter{Source: "payload", Name: "event"}, Value: "push"}},
		{Match: &config.MatchRule{Type: "value", Parameter: config.Parameter{Source: "payload", Name: "event"}, Value: "create"}},
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Error("expected OR to be false")
	}
}

func TestEvaluateRule_Not(t *testing.T) {
	r := req(map[string]any{"env": "prod"}, "1.2.3.4")
	rule := config.Rule{Not: &config.Rule{
		Match: &config.MatchRule{
			Type:      "value",
			Parameter: config.Parameter{Source: "payload", Name: "env"},
			Value:     "dev",
		},
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected NOT(false) = true")
	}
}

func TestEvaluateRule_PayloadHMAC256(t *testing.T) {
	body := `{"event":"push"}`
	sig := hmacSig(body, "rulesecret")
	r := &hook.RequestData{
		Payload:  map[string]any{"event": "push"},
		Headers:  http.Header{"X-Sig": []string{sig}},
		Query:    map[string]string{},
		RawBody:  []byte(body),
		RemoteIP: "1.2.3.4",
	}
	rule := config.Rule{Match: &config.MatchRule{
		Type:      "payload-hmac-sha256",
		Parameter: config.Parameter{Source: "header", Name: "X-Sig"},
		Secret:    "rulesecret",
	}}
	ok, err := hook.EvaluateRule(rule, r)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("expected payload-hmac-sha256 to match")
	}
}

func TestEvaluateRule_EmptyRule(t *testing.T) {
	r := req(nil, "1.2.3.4")
	_, err := hook.EvaluateRule(config.Rule{}, r)
	if err == nil {
		t.Fatal("expected error for empty rule")
	}
}

func TestEvaluateRule_InvalidCIDR(t *testing.T) {
	r := req(nil, "10.0.0.1")
	rule := config.Rule{Match: &config.MatchRule{
		Type:    "ip-whitelist",
		IPRange: "not-a-cidr",
	}}
	_, err := hook.EvaluateRule(rule, r)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestEvaluateRule_InvalidRegex(t *testing.T) {
	r := req(map[string]any{"ref": "main"}, "1.2.3.4")
	rule := config.Rule{Match: &config.MatchRule{
		Type:      "regex",
		Parameter: config.Parameter{Source: "payload", Name: "ref"},
		Value:     `[invalid`,
	}}
	_, err := hook.EvaluateRule(rule, r)
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}
