package server_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"hooky/internal/config"
	"hooky/internal/server"
)

// ── test helpers ──────────────────────────────────────────────────────────────

func newServer(t *testing.T, hooks []config.Hook) *httptest.Server {
	t.Helper()
	srv := server.New(server.Options{
		Addr:      "127.0.0.1:0",
		URLPrefix: "hooks",
	})
	if err := srv.SetConfig(&config.Config{Hooks: hooks}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts
}

// baseHook returns a minimal valid hook with all defaults pre-filled.
func baseHook(id, cmd string) config.Hook {
	return config.Hook{
		ID:          id,
		Command:     cmd,
		HTTPMethods: []string{"POST"},
		Timeout:     config.Duration{Duration: 5 * time.Second},
		Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403},
	}
}

func sign256(body, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(body))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func post(t *testing.T, url, body string, headers map[string]string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ── /health ───────────────────────────────────────────────────────────────────

func TestHealth(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "a", Command: "/bin/echo", HTTPMethods: []string{"POST"},
			Timeout:  config.Duration{Duration: 5 * time.Second},
			Response: config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403}},
	})
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", body["status"])
	}
	if hooks, _ := body["hooks"].(float64); hooks != 1 {
		t.Errorf("expected hooks=1, got %v", body["hooks"])
	}
}

func TestHealthz(t *testing.T) {
	ts := newServer(t, nil)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

// ── not found ─────────────────────────────────────────────────────────────────

func TestHook_NotFound(t *testing.T) {
	ts := newServer(t, nil)
	resp := post(t, ts.URL+"/hooks/nonexistent", "{}", nil)
	readBody(t, resp)
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ── method not allowed ────────────────────────────────────────────────────────

func TestHook_MethodNotAllowed(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "post-only", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403}},
	})
	resp, err := http.Get(ts.URL + "/hooks/post-only")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", resp.StatusCode)
	}
}

// ── no secret (open hook) ─────────────────────────────────────────────────────

func TestHook_NoSecret_Executes(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "open", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403, Message: "done"}},
	})
	resp := post(t, ts.URL+"/hooks/open", "{}", nil)
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d — body: %s", resp.StatusCode, body)
	}
}

// ── HMAC secret ───────────────────────────────────────────────────────────────

func TestHook_HMAC_Valid(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "secure", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			Secret:      &config.Secret{Type: "hmac-sha256", Header: "X-Sig", Value: "s3cr3t"},
			Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403, Message: "ok"}},
	})
	body := `{"event":"push"}`
	resp := post(t, ts.URL+"/hooks/secure", body, map[string]string{
		"X-Sig": sign256(body, "s3cr3t"),
	})
	readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestHook_HMAC_Invalid(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "secure2", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			Secret:      &config.Secret{Type: "hmac-sha256", Header: "X-Sig", Value: "s3cr3t"},
			Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403}},
	})
	resp := post(t, ts.URL+"/hooks/secure2", `{}`, map[string]string{
		"X-Sig": "sha256=badhash",
	})
	readBody(t, resp)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

func TestHook_HMAC_Missing(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "secure3", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			Secret:      &config.Secret{Type: "hmac-sha256", Header: "X-Sig", Value: "s3cr3t"},
			Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403}},
	})
	resp := post(t, ts.URL+"/hooks/secure3", `{}`, nil)
	readBody(t, resp)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// ── trigger rules ─────────────────────────────────────────────────────────────

func TestHook_TriggerRule_Match(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "ruled", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			TriggerRule: &config.Rule{Match: &config.MatchRule{
				Type:      "value",
				Parameter: config.Parameter{Source: "payload", Name: "event"},
				Value:     "push",
			}},
			Response: config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403, Message: "fired"}},
	})
	resp := post(t, ts.URL+"/hooks/ruled", `{"event":"push"}`, nil)
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d — body: %s", resp.StatusCode, body)
	}
}

func TestHook_TriggerRule_NoMatch(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "ruled2", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			TriggerRule: &config.Rule{Match: &config.MatchRule{
				Type:      "value",
				Parameter: config.Parameter{Source: "payload", Name: "event"},
				Value:     "push",
			}},
			Response: config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403}},
	})
	resp := post(t, ts.URL+"/hooks/ruled2", `{"event":"pr"}`, nil)
	readBody(t, resp)
	if resp.StatusCode != 403 {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
}

// ── include-output ────────────────────────────────────────────────────────────

func TestHook_IncludeOutput(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "output", Command: "/bin/echo",
			Args:        []config.Parameter{{Source: "literal", Name: "hello-from-hook"}},
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403, IncludeOutput: true}},
	})
	resp := post(t, ts.URL+"/hooks/output", "{}", nil)
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "hello-from-hook") {
		t.Errorf("expected output in body, got: %q", body)
	}
}

// ── rate limiting ─────────────────────────────────────────────────────────────

func TestHook_RateLimit(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "rl", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			RateLimit:   &config.RateLimitConfig{Requests: 2, Window: config.Duration{Duration: 10 * time.Second}},
			Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403}},
	})
	for i := 0; i < 2; i++ {
		resp := post(t, ts.URL+"/hooks/rl", "{}", nil)
		readBody(t, resp)
		if resp.StatusCode != 200 {
			t.Fatalf("call %d: expected 200, got %d", i+1, resp.StatusCode)
		}
	}
	resp := post(t, ts.URL+"/hooks/rl", "{}", nil)
	readBody(t, resp)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
	}
}

// ── custom response headers ───────────────────────────────────────────────────

func TestHook_ResponseHeaders(t *testing.T) {
	ts := newServer(t, []config.Hook{
		{ID: "hdrs", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			Response: config.Response{
				SuccessCode:  200,
				ErrorCode:    500,
				MismatchCode: 403,
				Headers:      map[string]string{"X-Custom": "test-value"},
			}},
	})
	resp := post(t, ts.URL+"/hooks/hdrs", "{}", nil)
	readBody(t, resp)
	if got := resp.Header.Get("X-Custom"); got != "test-value" {
		t.Errorf("X-Custom: got %q, want %q", got, "test-value")
	}
}

// ── real IP / proxy header ─────────────────────────────────────────────────────

func TestRealIP_ProxyHeader(t *testing.T) {
	// Test that the proxy header is used for the remote IP by checking an
	// ip-whitelist rule passes with the forwarded IP.
	srv := server.New(server.Options{
		Addr:        "127.0.0.1:0",
		URLPrefix:   "hooks",
		ProxyHeader: "X-Forwarded-For",
	})
	cfg := &config.Config{Hooks: []config.Hook{
		{ID: "ipcheck", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			TriggerRule: &config.Rule{Match: &config.MatchRule{
				Type:    "ip-whitelist",
				IPRange: "10.0.0.0/8",
			}},
			Response: config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403, Message: "ok"}},
	}}
	srv.SetConfig(cfg)

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/hooks/ipcheck", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.1.2.3")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 with forwarded IP in whitelist, got %d", resp.StatusCode)
	}
}

// ── hot reload ────────────────────────────────────────────────────────────────

func TestSetConfig_HotReload(t *testing.T) {
	srv := server.New(server.Options{Addr: "127.0.0.1:0", URLPrefix: "hooks"})
	srv.SetConfig(&config.Config{})

	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	// Hook doesn't exist yet.
	resp := post(t, ts.URL+"/hooks/new-hook", "{}", nil)
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("expected 404 before reload, got %d", resp.StatusCode)
	}

	// Reload with a new hook.
	srv.SetConfig(&config.Config{Hooks: []config.Hook{
		{ID: "new-hook", Command: "/bin/echo",
			HTTPMethods: []string{"POST"},
			Timeout:     config.Duration{Duration: 5 * time.Second},
			Response:    config.Response{SuccessCode: 200, ErrorCode: 500, MismatchCode: 403, Message: "reloaded"}},
	}})

	resp = post(t, ts.URL+"/hooks/new-hook", "{}", nil)
	body := readBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200 after reload, got %d — body: %s", resp.StatusCode, body)
	}
}

// ── graceful shutdown ─────────────────────────────────────────────────────────

func TestServer_GracefulShutdown(t *testing.T) {
	srv := server.New(server.Options{
		Addr:      "127.0.0.1:0",
		URLPrefix: "hooks",
	})
	srv.SetConfig(&config.Config{})

	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	srv2 := server.New(server.Options{
		Addr:      fmt.Sprintf("127.0.0.1:%d", port),
		URLPrefix: "hooks",
	})
	srv2.SetConfig(&config.Config{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- srv2.Run(ctx)
	}()

	// Give the server time to start.
	time.Sleep(50 * time.Millisecond)

	// Cancel should trigger shutdown with no error.
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected server error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}
