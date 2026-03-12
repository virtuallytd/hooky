// Package config handles loading and validating hook configuration files.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration structure.
type Config struct {
	Hooks []Hook `json:"hooks" yaml:"hooks"`
}

// Hook defines a single webhook endpoint.
type Hook struct {
	// ID is the unique identifier; creates the endpoint /{prefix}/{id}.
	ID string `json:"id" yaml:"id"`

	// Command is the executable to run when the hook fires.
	Command string `json:"command" yaml:"command"`

	// WorkingDir sets the working directory for the command.
	WorkingDir string `json:"working-dir" yaml:"working-dir"`

	// Timeout limits command execution time (default: 30s).
	Timeout Duration `json:"timeout" yaml:"timeout"`

	// HTTPMethods restricts accepted HTTP methods (default: [POST]).
	HTTPMethods []string `json:"http-methods" yaml:"http-methods"`

	// Secret validates the incoming request signature or token.
	Secret *Secret `json:"secret" yaml:"secret"`

	// TriggerRule adds additional conditions beyond the secret check.
	TriggerRule *Rule `json:"trigger-rule" yaml:"trigger-rule"`

	// Args are positional arguments passed to the command, extracted from the request.
	Args []Parameter `json:"args" yaml:"args"`

	// Env specifies extra environment variables passed to the command.
	Env []EnvVar `json:"env" yaml:"env"`

	// Response configures what the hook returns to the caller.
	Response Response `json:"response" yaml:"response"`

	// RateLimit restricts how frequently the hook can be called.
	RateLimit *RateLimitConfig `json:"rate-limit" yaml:"rate-limit"`

	// MaxConcurrent limits simultaneous executions of this hook (0 = unlimited).
	MaxConcurrent int `json:"max-concurrent" yaml:"max-concurrent"`

	// FireAndForget returns a response immediately without waiting for the command.
	FireAndForget bool `json:"fire-and-forget" yaml:"fire-and-forget"`
}

// Secret validates the incoming request signature or bearer token.
type Secret struct {
	// Type: hmac-sha256 | hmac-sha1 | hmac-sha512 | token
	Type string `json:"type" yaml:"type"`

	// Header is the header name carrying the signature or token.
	Header string `json:"header" yaml:"header"`

	// Query is an alternative URL query parameter name for the token.
	Query string `json:"query" yaml:"query"`

	// Value is the expected secret. Supports env:VAR_NAME and file:/path prefixes.
	Value string `json:"value" yaml:"value"`
}

// Parameter references a value from the incoming HTTP request.
type Parameter struct {
	// Source: payload | header | query | request | entire-payload | entire-headers | entire-query
	Source string `json:"source" yaml:"source"`

	// Name is the field name. Supports dot-notation for nested JSON payload fields.
	Name string `json:"name" yaml:"name"`
}

// EnvVar defines an environment variable to pass to the command.
type EnvVar struct {
	// Name is the environment variable name set on the child process.
	Name string `json:"name" yaml:"name"`

	// Source: payload | header | query | env | literal
	Source string `json:"source" yaml:"source"`

	// Key is the field name when Source is payload, header, or query.
	Key string `json:"key" yaml:"key"`

	// Value is the literal value (Source=literal) or env var name to forward (Source=env).
	Value string `json:"value" yaml:"value"`
}

// Response configures the HTTP response returned after hook execution.
type Response struct {
	// SuccessCode is the HTTP status on successful execution (default: 200).
	SuccessCode int `json:"success-code" yaml:"success-code"`

	// ErrorCode is the HTTP status when command execution fails (default: 500).
	ErrorCode int `json:"error-code" yaml:"error-code"`

	// MismatchCode is the HTTP status when secret or trigger rules fail (default: 403).
	MismatchCode int `json:"mismatch-code" yaml:"mismatch-code"`

	// Message is a static string returned in the response body on success.
	Message string `json:"message" yaml:"message"`

	// IncludeOutput includes the command's combined stdout/stderr in the response.
	IncludeOutput bool `json:"include-output" yaml:"include-output"`

	// Headers are additional HTTP headers to include in the response.
	Headers map[string]string `json:"headers" yaml:"headers"`
}

// RateLimitConfig defines a sliding-window rate limit for a hook.
type RateLimitConfig struct {
	// Requests is the maximum number of calls allowed within Window.
	Requests int `json:"requests" yaml:"requests"`

	// Window is the rolling time window (e.g. "1m", "10s").
	Window Duration `json:"window" yaml:"window"`
}

// Rule is a composable trigger condition supporting boolean logic.
// Exactly one of And, Or, Not, or Match should be set.
type Rule struct {
	And   []Rule     `json:"and"   yaml:"and"`
	Or    []Rule     `json:"or"    yaml:"or"`
	Not   *Rule      `json:"not"   yaml:"not"`
	Match *MatchRule `json:"match" yaml:"match"`
}

// MatchRule performs a single comparison against request data.
type MatchRule struct {
	// Type: value | regex | ip-whitelist | payload-hmac-sha1 | payload-hmac-sha256 | payload-hmac-sha512
	Type string `json:"type" yaml:"type"`

	// Parameter specifies where to extract the comparison value from.
	Parameter Parameter `json:"parameter" yaml:"parameter"`

	// Value is the expected string for "value" and "regex" types.
	Value string `json:"value" yaml:"value"`

	// Secret is the HMAC key for payload-hmac-* types. Supports env:/file: prefixes.
	Secret string `json:"secret" yaml:"secret"`

	// IPRange is a CIDR block for the "ip-whitelist" type (e.g. "192.168.1.0/24").
	IPRange string `json:"ip-range" yaml:"ip-range"`
}

// Duration wraps time.Duration with JSON and YAML unmarshaling support.
type Duration struct{ time.Duration }

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("parsing duration %q: %w", s, err)
	}
	d.Duration = dur
	return nil
}

// ResolveValue resolves a value string that may carry an env: or file: prefix.
//
//	env:MY_SECRET  → value of $MY_SECRET environment variable
//	file:/run/secrets/token → trimmed contents of the file
//	anything else  → the literal string
func ResolveValue(val string) (string, error) {
	if name, ok := strings.CutPrefix(val, "env:"); ok {
		v := os.Getenv(name)
		if v == "" {
			return "", fmt.Errorf("environment variable %q is not set or empty", name)
		}
		return v, nil
	}
	if path, ok := strings.CutPrefix(val, "file:"); ok {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("reading secret file %q: %w", path, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return val, nil
}

// Load reads and parses a hook configuration file.
// Both JSON (.json) and YAML (.yaml / .yml) are supported.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	var cfg Config
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parsing YAML config: %w", err)
		}
	default:
		if err := json.Unmarshal(data, &cfg); err != nil {
			// Try YAML as a fallback for files without a recognised extension.
			if err2 := yaml.Unmarshal(data, &cfg); err2 != nil {
				return nil, fmt.Errorf("parsing config as JSON: %w", err)
			}
		}
	}

	if err := validate(&cfg); err != nil {
		return nil, err
	}
	for i := range cfg.Hooks {
		applyDefaults(&cfg.Hooks[i])
	}
	return &cfg, nil
}

func validate(cfg *Config) error {
	seen := make(map[string]bool, len(cfg.Hooks))
	for i, h := range cfg.Hooks {
		if h.ID == "" {
			return fmt.Errorf("hook[%d]: id is required", i)
		}
		if h.Command == "" {
			return fmt.Errorf("hook %q: command is required", h.ID)
		}
		if seen[h.ID] {
			return fmt.Errorf("duplicate hook id %q", h.ID)
		}
		seen[h.ID] = true
	}
	return nil
}

func applyDefaults(h *Hook) {
	if len(h.HTTPMethods) == 0 {
		h.HTTPMethods = []string{"POST"}
	}
	if h.Timeout.Duration == 0 {
		h.Timeout.Duration = 30 * time.Second
	}
	if h.Response.SuccessCode == 0 {
		h.Response.SuccessCode = 200
	}
	if h.Response.ErrorCode == 0 {
		h.Response.ErrorCode = 500
	}
	if h.Response.MismatchCode == 0 {
		h.Response.MismatchCode = 403
	}
}
