package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"hooky/internal/config"
)

// ── ResolveValue ─────────────────────────────────────────────────────────────

func TestResolveValue_Literal(t *testing.T) {
	got, err := config.ResolveValue("mysecret")
	if err != nil {
		t.Fatal(err)
	}
	if got != "mysecret" {
		t.Errorf("got %q, want %q", got, "mysecret")
	}
}

func TestResolveValue_Env(t *testing.T) {
	t.Setenv("TEST_SECRET", "from-env")
	got, err := config.ResolveValue("env:TEST_SECRET")
	if err != nil {
		t.Fatal(err)
	}
	if got != "from-env" {
		t.Errorf("got %q, want %q", got, "from-env")
	}
}

func TestResolveValue_Env_Missing(t *testing.T) {
	os.Unsetenv("HOOKY_MISSING_VAR")
	_, err := config.ResolveValue("env:HOOKY_MISSING_VAR")
	if err == nil {
		t.Fatal("expected error for unset env var")
	}
}

func TestResolveValue_File(t *testing.T) {
	f := filepath.Join(t.TempDir(), "secret.txt")
	os.WriteFile(f, []byte("  file-secret\n"), 0600)

	got, err := config.ResolveValue("file:" + f)
	if err != nil {
		t.Fatal(err)
	}
	if got != "file-secret" {
		t.Errorf("got %q, want %q", got, "file-secret")
	}
}

func TestResolveValue_File_Missing(t *testing.T) {
	_, err := config.ResolveValue("file:/nonexistent/path/secret.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

// ── Load ─────────────────────────────────────────────────────────────────────

func writeTemp(t *testing.T, ext, content string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "hooks"+ext)
	if err := os.WriteFile(f, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestLoad_YAML(t *testing.T) {
	path := writeTemp(t, ".yaml", `
hooks:
  - id: deploy
    command: /bin/deploy.sh
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hooks) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(cfg.Hooks))
	}
	h := cfg.Hooks[0]
	if h.ID != "deploy" {
		t.Errorf("id: got %q, want %q", h.ID, "deploy")
	}
	// defaults
	if len(h.HTTPMethods) == 0 || h.HTTPMethods[0] != "POST" {
		t.Errorf("default HTTPMethods not applied: %v", h.HTTPMethods)
	}
	if h.Timeout.Duration != 30*time.Second {
		t.Errorf("default Timeout not applied: %v", h.Timeout.Duration)
	}
	if h.Response.SuccessCode != 200 {
		t.Errorf("default SuccessCode not applied: %d", h.Response.SuccessCode)
	}
	if h.Response.MismatchCode != 403 {
		t.Errorf("default MismatchCode not applied: %d", h.Response.MismatchCode)
	}
}

func TestLoad_JSON(t *testing.T) {
	path := writeTemp(t, ".json", `{"hooks":[{"id":"ping","command":"/bin/echo"}]}`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Hooks) != 1 || cfg.Hooks[0].ID != "ping" {
		t.Fatalf("unexpected hooks: %+v", cfg.Hooks)
	}
}

func TestLoad_CustomDefaults_NotOverwritten(t *testing.T) {
	path := writeTemp(t, ".yaml", `
hooks:
  - id: test
    command: /bin/test
    timeout: 2m
    response:
      success-code: 202
      mismatch-code: 401
`)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	h := cfg.Hooks[0]
	if h.Timeout.Duration != 2*time.Minute {
		t.Errorf("custom timeout overwritten: got %v", h.Timeout.Duration)
	}
	if h.Response.SuccessCode != 202 {
		t.Errorf("custom success-code overwritten: got %d", h.Response.SuccessCode)
	}
	if h.Response.MismatchCode != 401 {
		t.Errorf("custom mismatch-code overwritten: got %d", h.Response.MismatchCode)
	}
}

func TestLoad_MissingID(t *testing.T) {
	path := writeTemp(t, ".yaml", `hooks: [{command: /bin/foo}]`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestLoad_MissingCommand(t *testing.T) {
	path := writeTemp(t, ".yaml", `hooks: [{id: foo}]`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for missing command")
	}
}

func TestLoad_DuplicateID(t *testing.T) {
	path := writeTemp(t, ".yaml", `
hooks:
  - id: foo
    command: /bin/a
  - id: foo
    command: /bin/b
`)
	_, err := config.Load(path)
	if err == nil {
		t.Fatal("expected error for duplicate id")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/hooks.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}
