package hook_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"hooky/internal/config"
	"hooky/internal/hook"
)

func newHook(id, cmd string, opts ...func(*config.Hook)) config.Hook {
	h := config.Hook{
		ID:      id,
		Command: cmd,
		Timeout: config.Duration{Duration: 5 * time.Second},
		Response: config.Response{
			SuccessCode:  200,
			ErrorCode:    500,
			MismatchCode: 403,
		},
	}
	for _, o := range opts {
		o(&h)
	}
	return h
}

func emptyReq() *hook.RequestData {
	return &hook.RequestData{
		Headers:  http.Header{},
		Query:    map[string]string{},
		RawBody:  []byte(""),
		RemoteIP: "127.0.0.1",
	}
}

// ── rate limiter ──────────────────────────────────────────────────────────────

func TestRateLimit_AllowsWithinLimit(t *testing.T) {
	h := newHook("rl", echoCmd("ok"), func(h *config.Hook) {
		h.RateLimit = &config.RateLimitConfig{
			Requests: 3,
			Window:   config.Duration{Duration: 10 * time.Second},
		}
	})
	e := hook.NewExecutor(h)
	for i := 0; i < 3; i++ {
		if err := e.CheckRateLimit(); err != nil {
			t.Fatalf("call %d: unexpected rate limit: %v", i+1, err)
		}
	}
}

func TestRateLimit_BlocksOverLimit(t *testing.T) {
	h := newHook("rl2", echoCmd("ok"), func(h *config.Hook) {
		h.RateLimit = &config.RateLimitConfig{
			Requests: 2,
			Window:   config.Duration{Duration: 10 * time.Second},
		}
	})
	e := hook.NewExecutor(h)
	e.CheckRateLimit()
	e.CheckRateLimit()
	if err := e.CheckRateLimit(); err == nil {
		t.Fatal("expected rate limit error on third call")
	}
}

func TestRateLimit_ResetsAfterWindow(t *testing.T) {
	h := newHook("rl3", echoCmd("ok"), func(h *config.Hook) {
		h.RateLimit = &config.RateLimitConfig{
			Requests: 1,
			Window:   config.Duration{Duration: 50 * time.Millisecond},
		}
	})
	e := hook.NewExecutor(h)
	if err := e.CheckRateLimit(); err != nil {
		t.Fatal(err)
	}
	if err := e.CheckRateLimit(); err == nil {
		t.Fatal("expected rate limit")
	}
	time.Sleep(60 * time.Millisecond)
	if err := e.CheckRateLimit(); err != nil {
		t.Fatalf("expected limit to reset, got: %v", err)
	}
}

func TestRateLimit_NilAllowsAll(t *testing.T) {
	e := hook.NewExecutor(newHook("noratelimit", echoCmd("ok")))
	for i := 0; i < 100; i++ {
		if err := e.CheckRateLimit(); err != nil {
			t.Fatalf("unexpected rate limit: %v", err)
		}
	}
}

// ── execution ─────────────────────────────────────────────────────────────────

func TestExecute_Success(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell test on Windows")
	}
	e := hook.NewExecutor(newHook("echo", "/bin/echo", func(h *config.Hook) {
		h.Args = []config.Parameter{{Source: "literal", Name: "hello"}}
		h.Response.IncludeOutput = true
	}))
	result, err := e.Execute(context.Background(), emptyReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Err != nil {
		t.Fatalf("command failed: %v", result.Err)
	}
	if !strings.Contains(string(result.Output), "hello") {
		t.Errorf("expected 'hello' in output, got: %q", result.Output)
	}
}

func TestExecute_CommandNotFound(t *testing.T) {
	e := hook.NewExecutor(newHook("bad", "/nonexistent/command"))
	_, err := e.Execute(context.Background(), emptyReq())
	if err == nil {
		t.Fatal("expected error for missing command")
	}
}

func TestExecute_Timeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell test on Windows")
	}
	e := hook.NewExecutor(newHook("slow", "/bin/sleep", func(h *config.Hook) {
		h.Timeout = config.Duration{Duration: 50 * time.Millisecond}
		h.Args = []config.Parameter{{Source: "literal", Name: "10"}}
	}))
	result, err := e.Execute(context.Background(), emptyReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Err == nil {
		t.Error("expected command to be killed by timeout")
	}
}

func TestExecute_ExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell test on Windows")
	}
	e := hook.NewExecutor(newHook("fail", "/bin/sh", func(h *config.Hook) {
		h.Args = []config.Parameter{
			{Source: "literal", Name: "-c"},
			{Source: "literal", Name: "exit 42"},
		}
	}))
	result, err := e.Execute(context.Background(), emptyReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 42 {
		t.Errorf("expected exit code 42, got %d", result.ExitCode)
	}
}

func TestExecute_MaxConcurrent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell test on Windows")
	}
	dir := t.TempDir()
	readyFile := filepath.Join(dir, "ready")

	// Script touches a file to signal it has started, then sleeps.
	script := filepath.Join(dir, "block.sh")
	os.WriteFile(script, []byte(fmt.Sprintf("#!/bin/sh\ntouch %s\nsleep 10", readyFile)), 0755)

	e := hook.NewExecutor(newHook("conc", script, func(h *config.Hook) {
		h.MaxConcurrent = 1
	}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.Execute(ctx, emptyReq()) //nolint:errcheck
	}()

	// Wait until the script signals it is running.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("script did not start within deadline")
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Second execution must be rejected while the first holds the slot.
	_, err := e.Execute(context.Background(), emptyReq())
	if err == nil {
		t.Error("expected concurrent limit error")
	}

	cancel()
	<-done
}

func TestExecute_FireAndForget_ReturnsImmediately(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell test on Windows")
	}
	e := hook.NewExecutor(newHook("ff", "/bin/sleep", func(h *config.Hook) {
		h.FireAndForget = true
		h.Args = []config.Parameter{{Source: "literal", Name: "5"}}
	}))
	start := time.Now()
	result, err := e.Execute(context.Background(), emptyReq())
	elapsed := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if elapsed > 500*time.Millisecond {
		t.Errorf("fire-and-forget took too long: %v", elapsed)
	}
}

func TestExecute_EnvVarsReachCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell test on Windows")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "env.sh")
	os.WriteFile(script, []byte("#!/bin/sh\necho $HOOK_VALUE"), 0755)

	e := hook.NewExecutor(newHook("envtest", script, func(h *config.Hook) {
		h.Env = []config.EnvVar{
			{Name: "HOOK_VALUE", Source: "payload", Key: "value"},
		}
	}))

	req := &hook.RequestData{
		Payload:  map[string]any{"value": "from-payload"},
		Headers:  http.Header{},
		Query:    map[string]string{},
		RawBody:  []byte(""),
		RemoteIP: "127.0.0.1",
	}

	result, err := e.Execute(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Err != nil {
		t.Fatalf("command failed: %v", result.Err)
	}
	if !strings.Contains(string(result.Output), "from-payload") {
		t.Errorf("env var not passed to command, output: %q", result.Output)
	}
}

func TestExecute_WorkingDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("skipping shell test on Windows")
	}
	dir := t.TempDir()
	// Resolve symlinks — macOS TempDir returns a symlinked path.
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}

	e := hook.NewExecutor(newHook("wdtest", "/bin/pwd", func(h *config.Hook) {
		h.WorkingDir = dir
	}))

	result, err := e.Execute(context.Background(), emptyReq())
	if err != nil {
		t.Fatal(err)
	}
	if result.Err != nil {
		t.Fatalf("command failed: %v", result.Err)
	}
	got := strings.TrimSpace(string(result.Output))
	if got != realDir {
		t.Errorf("working dir: got %q, want %q", got, realDir)
	}
}

// echoCmd returns "/bin/echo" — used where we just need a fast no-op command.
func echoCmd(_ string) string {
	return "/bin/echo"
}
