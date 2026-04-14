package hook

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"

	"hooky/internal/config"
)

// rateLimiter implements a sliding-window (fixed-window approximation) rate limiter.
type rateLimiter struct {
	mu     sync.Mutex
	times  []time.Time
	limit  int
	window time.Duration
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		limit:  limit,
		window: window,
		times:  make([]time.Time, 0, limit),
	}
}

// allow returns true and records the call if within the rate limit.
func (r *rateLimiter) allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.window)

	// Evict entries outside the window.
	valid := r.times[:0]
	for _, t := range r.times {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	r.times = valid

	if len(r.times) >= r.limit {
		return false
	}
	r.times = append(r.times, now)
	return true
}

// Result holds the outcome of a command execution.
type Result struct {
	Output   []byte
	ExitCode int
	Err      error
}

// Executor manages rate limiting, concurrency control, and execution for one hook.
type Executor struct {
	hook       config.Hook
	rl         *rateLimiter
	concurrent atomic.Int32
}

// NewExecutor creates an Executor for the given hook.
func NewExecutor(h config.Hook) *Executor {
	e := &Executor{hook: h}
	if h.RateLimit != nil && h.RateLimit.Requests > 0 && h.RateLimit.Window.Duration > 0 {
		e.rl = newRateLimiter(h.RateLimit.Requests, h.RateLimit.Window.Duration)
	}
	return e
}

// Hook returns the hook configuration.
func (e *Executor) Hook() config.Hook {
	return e.hook
}

// CheckRateLimit returns an error when the hook's rate limit is exceeded.
func (e *Executor) CheckRateLimit() error {
	if e.rl != nil && !e.rl.allow() {
		return fmt.Errorf("rate limit exceeded")
	}
	return nil
}

// Execute runs the hook command and returns the result.
// The caller is responsible for checking rate limits before calling Execute.
func (e *Executor) Execute(ctx context.Context, req *RequestData) (*Result, error) {
	// Enforce concurrency limit.
	if e.hook.MaxConcurrent > 0 {
		n := e.concurrent.Add(1)
		defer e.concurrent.Add(-1)
		if int(n) > e.hook.MaxConcurrent {
			return nil, fmt.Errorf("max concurrent executions (%d) reached", e.hook.MaxConcurrent)
		}
	}

	args, err := buildArgs(e.hook.Args, req)
	if err != nil {
		return nil, fmt.Errorf("building args: %w", err)
	}

	env, err := buildEnv(e.hook.Env, req)
	if err != nil {
		return nil, fmt.Errorf("building env: %w", err)
	}

	timeout := e.hook.Timeout.Duration
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, e.hook.Command, args...)
	cmd.Dir = e.hook.WorkingDir
	cmd.Env = env

	slog.Debug("executing hook",
		"hook", e.hook.ID,
		"command", e.hook.Command,
		"args", args,
		"timeout", timeout,
	)

	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting command %q: %w", e.hook.Command, err)
	}

	if e.hook.FireAndForget {
		go func() {
			if err := cmd.Wait(); err != nil {
				slog.Warn("fire-and-forget command failed",
					"hook", e.hook.ID,
					"error", err,
				)
			}
		}()
		return &Result{}, nil
	}

	waitErr := cmd.Wait()
	result := &Result{Output: buf.Bytes()}
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		}
		result.Err = waitErr
	}
	return result, nil
}

func buildArgs(params []config.Parameter, req *RequestData) ([]string, error) {
	args := make([]string, 0, len(params))
	for _, p := range params {
		val, err := ExtractValue(req, p)
		if err != nil {
			return nil, fmt.Errorf("{source:%s name:%s}: %w", p.Source, p.Name, err)
		}
		args = append(args, val)
	}
	return args, nil
}

func buildEnv(vars []config.EnvVar, req *RequestData) ([]string, error) {
	// Inherit the parent process environment so scripts have access to PATH, etc.
	env := os.Environ()

	for _, v := range vars {
		val, err := resolveEnvVar(v, req)
		if err != nil {
			return nil, fmt.Errorf("env var %q: %w", v.Name, err)
		}
		env = append(env, v.Name+"="+val)
	}
	return env, nil
}

func resolveEnvVar(v config.EnvVar, req *RequestData) (string, error) {
	switch v.Source {
	case "payload":
		return extractFromPayload(req.Payload, v.Key)
	case "header":
		return req.Headers.Get(v.Key), nil
	case "query":
		return req.Query[v.Key], nil
	case "env":
		return os.Getenv(v.Value), nil
	case "literal":
		return v.Value, nil
	default:
		return "", fmt.Errorf("unknown source %q", v.Source)
	}
}
