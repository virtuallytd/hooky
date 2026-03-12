package hook_test

import (
	"net/http"
	"testing"

	"hooky/internal/config"
	"hooky/internal/hook"
)

func makeReq(payload map[string]any, headers map[string]string, query map[string]string, raw string) *hook.RequestData {
	h := make(http.Header)
	for k, v := range headers {
		h.Set(k, v)
	}
	return &hook.RequestData{
		Payload:  payload,
		Headers:  h,
		Query:    query,
		RawBody:  []byte(raw),
		RemoteIP: "1.2.3.4",
	}
}

// ── payload source ────────────────────────────────────────────────────────────

func TestExtractValue_Payload_TopLevel(t *testing.T) {
	req := makeReq(map[string]any{"ref": "main"}, nil, nil, "")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "payload", Name: "ref"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "main" {
		t.Errorf("got %q, want %q", got, "main")
	}
}

func TestExtractValue_Payload_Nested(t *testing.T) {
	req := makeReq(map[string]any{"repo": map[string]any{"name": "hooky"}}, nil, nil, "")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "payload", Name: "repo.name"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "hooky" {
		t.Errorf("got %q, want %q", got, "hooky")
	}
}

func TestExtractValue_Payload_DeeplyNested(t *testing.T) {
	payload := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": "deep",
			},
		},
	}
	req := makeReq(payload, nil, nil, "")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "payload", Name: "a.b.c"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "deep" {
		t.Errorf("got %q, want %q", got, "deep")
	}
}

func TestExtractValue_Payload_Number(t *testing.T) {
	req := makeReq(map[string]any{"id": float64(42)}, nil, nil, "")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "payload", Name: "id"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "42" {
		t.Errorf("got %q, want %q", got, "42")
	}
}

func TestExtractValue_Payload_Bool(t *testing.T) {
	req := makeReq(map[string]any{"ok": true}, nil, nil, "")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "payload", Name: "ok"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "true" {
		t.Errorf("got %q, want %q", got, "true")
	}
}

func TestExtractValue_Payload_Missing(t *testing.T) {
	req := makeReq(map[string]any{}, nil, nil, "")
	_, err := hook.ExtractValue(req, config.Parameter{Source: "payload", Name: "missing"})
	if err == nil {
		t.Fatal("expected error for missing field")
	}
}

func TestExtractValue_Payload_Nil(t *testing.T) {
	req := makeReq(nil, nil, nil, "")
	_, err := hook.ExtractValue(req, config.Parameter{Source: "payload", Name: "ref"})
	if err == nil {
		t.Fatal("expected error for nil payload")
	}
}

// ── header source ─────────────────────────────────────────────────────────────

func TestExtractValue_Header(t *testing.T) {
	req := makeReq(nil, map[string]string{"X-Event": "push"}, nil, "")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "header", Name: "X-Event"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "push" {
		t.Errorf("got %q, want %q", got, "push")
	}
}

func TestExtractValue_Header_Missing(t *testing.T) {
	req := makeReq(nil, nil, nil, "")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "header", Name: "X-Missing"})
	if err != nil {
		t.Fatal(err)
	}
	// Missing header returns empty string (not an error — headers are optional).
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// ── query source ──────────────────────────────────────────────────────────────

func TestExtractValue_Query(t *testing.T) {
	req := makeReq(nil, nil, map[string]string{"token": "abc"}, "")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "query", Name: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc" {
		t.Errorf("got %q, want %q", got, "abc")
	}
}

func TestExtractValue_Query_Missing(t *testing.T) {
	req := makeReq(nil, nil, nil, "")
	_, err := hook.ExtractValue(req, config.Parameter{Source: "query", Name: "missing"})
	if err == nil {
		t.Fatal("expected error for missing query param")
	}
}

// ── special sources ───────────────────────────────────────────────────────────

func TestExtractValue_RemoteAddr(t *testing.T) {
	req := makeReq(nil, nil, nil, "")
	req.RemoteIP = "10.0.0.1"
	got, err := hook.ExtractValue(req, config.Parameter{Source: "request", Name: "remote-addr"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.0.0.1" {
		t.Errorf("got %q, want %q", got, "10.0.0.1")
	}
}

func TestExtractValue_RawBody(t *testing.T) {
	req := makeReq(nil, nil, nil, "hello world")
	got, err := hook.ExtractValue(req, config.Parameter{Source: "raw-body"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "hello world" {
		t.Errorf("got %q, want %q", got, "hello world")
	}
}

func TestExtractValue_EntirePayload_UsesRawWhenNotParsed(t *testing.T) {
	req := makeReq(nil, nil, nil, `{"raw":true}`)
	got, err := hook.ExtractValue(req, config.Parameter{Source: "entire-payload"})
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"raw":true}` {
		t.Errorf("got %q", got)
	}
}

func TestExtractValue_UnknownSource(t *testing.T) {
	req := makeReq(nil, nil, nil, "")
	_, err := hook.ExtractValue(req, config.Parameter{Source: "unknown"})
	if err == nil {
		t.Fatal("expected error for unknown source")
	}
}
