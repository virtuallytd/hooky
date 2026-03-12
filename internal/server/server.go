// Package server implements the HTTP webhook server.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hooky/internal/config"
	"hooky/internal/hook"
)

const maxBodySize = 10 << 20 // 10 MB

// Options configures the server.
type Options struct {
	Addr        string
	URLPrefix   string
	CertFile    string
	KeyFile     string
	ProxyHeader string // e.g. "X-Forwarded-For" when behind a reverse proxy
	HotReload   bool
	ConfigFile  string
}

// Server is the HTTP webhook server.
type Server struct {
	opts    Options
	httpSrv *http.Server

	mu        sync.RWMutex
	executors map[string]*hook.Executor
	cfg       *config.Config
}

// New creates a Server with the provided options.
func New(opts Options) *Server {
	return &Server{
		opts:      opts,
		executors: make(map[string]*hook.Executor),
	}
}

// SetConfig atomically replaces the active hook configuration.
func (s *Server) SetConfig(cfg *config.Config) error {
	executors := make(map[string]*hook.Executor, len(cfg.Hooks))
	for _, h := range cfg.Hooks {
		executors[h.ID] = hook.NewExecutor(h)
	}
	s.mu.Lock()
	s.cfg = cfg
	s.executors = executors
	s.mu.Unlock()
	return nil
}

// Handler returns the HTTP handler for the server.
// This is exposed primarily for testing with httptest.NewServer.
func (s *Server) Handler() http.Handler {
	prefix := strings.Trim(s.opts.URLPrefix, "/")
	mux := http.NewServeMux()
	mux.HandleFunc("/"+prefix+"/", s.handleHook)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/healthz", s.handleHealth)
	return mux
}

// Run starts the HTTP server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	s.httpSrv = &http.Server{
		Addr:         s.opts.Addr,
		Handler:      s.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 10 * time.Minute, // generous for synchronous, long-running commands
		IdleTimeout:  120 * time.Second,
	}

	if s.opts.HotReload {
		go s.watchConfig(ctx)
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.httpSrv.Shutdown(shutCtx); err != nil {
			slog.Error("graceful shutdown error", "error", err)
		}
	}()

	urlPrefix := strings.Trim(s.opts.URLPrefix, "/")
	var err error
	if s.opts.CertFile != "" && s.opts.KeyFile != "" {
		slog.Info("starting HTTPS server", "addr", s.opts.Addr, "prefix", urlPrefix)
		err = s.httpSrv.ListenAndServeTLS(s.opts.CertFile, s.opts.KeyFile)
	} else {
		slog.Info("starting HTTP server", "addr", s.opts.Addr, "prefix", urlPrefix)
		err = s.httpSrv.ListenAndServe()
	}
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// handleHealth returns a simple JSON status payload.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	hookCount := 0
	if s.cfg != nil {
		hookCount = len(s.cfg.Hooks)
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status": "ok",
		"hooks":  hookCount,
	})
}

// handleHook routes requests to the correct hook executor.
func (s *Server) handleHook(w http.ResponseWriter, r *http.Request) {
	prefix := strings.Trim(s.opts.URLPrefix, "/")
	trimmed := strings.TrimPrefix(r.URL.Path, "/"+prefix+"/")
	hookID, _, _ := strings.Cut(trimmed, "/")

	if hookID == "" {
		http.NotFound(w, r)
		return
	}

	s.mu.RLock()
	executor, ok := s.executors[hookID]
	s.mu.RUnlock()

	if !ok {
		http.NotFound(w, r)
		return
	}

	h := executor.Hook()

	// --- Method check ---
	if !methodAllowed(r.Method, h.HTTPMethods) {
		w.Header().Set("Allow", strings.Join(h.HTTPMethods, ", "))
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// --- Read body ---
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		slog.Warn("reading request body", "hook", hookID, "error", err)
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// --- Build RequestData ---
	req := &hook.RequestData{
		Headers:  r.Header,
		RawBody:  body,
		Query:    extractQuery(r),
		RemoteIP: realIP(r, s.opts.ProxyHeader),
	}
	if isJSON(r) && len(body) > 0 {
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err == nil {
			req.Payload = payload
		}
	}

	// --- Request ID for log correlation ---
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	logger := slog.With("hook", hookID, "request_id", reqID, "remote_ip", req.RemoteIP)
	logger.Info("incoming request", "method", r.Method)

	// --- Apply hook-level response headers ---
	for k, v := range h.Response.Headers {
		w.Header().Set(k, v)
	}

	// --- Rate limit ---
	if err := executor.CheckRateLimit(); err != nil {
		logger.Warn("rate limit exceeded")
		http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
		return
	}

	// --- Secret validation ---
	if h.Secret != nil {
		valid, err := hook.ValidateSecret(*h.Secret, req)
		if err != nil {
			logger.Error("secret validation error", "error", err)
			writeText(w, h.Response.ErrorCode, "secret validation error\n")
			return
		}
		if !valid {
			logger.Warn("secret mismatch")
			writeText(w, h.Response.MismatchCode, "unauthorized\n")
			return
		}
	}

	// --- Trigger rule evaluation ---
	if h.TriggerRule != nil {
		match, err := hook.EvaluateRule(*h.TriggerRule, req)
		if err != nil {
			logger.Error("trigger rule error", "error", err)
			writeText(w, h.Response.ErrorCode, fmt.Sprintf("trigger rule error: %v\n", err))
			return
		}
		if !match {
			logger.Info("trigger rules not matched")
			writeText(w, h.Response.MismatchCode, "trigger conditions not met\n")
			return
		}
	}

	// --- Execute ---
	result, err := executor.Execute(r.Context(), req)
	if err != nil {
		logger.Error("execution error", "error", err)
		writeText(w, h.Response.ErrorCode, fmt.Sprintf("execution error: %v\n", err))
		return
	}

	if result.Err != nil {
		logger.Warn("command failed", "exit_code", result.ExitCode)
		if h.Response.IncludeOutput {
			writeText(w, h.Response.ErrorCode, string(result.Output))
		} else {
			msg := h.Response.Message
			if msg == "" {
				msg = "command failed\n"
			}
			writeText(w, h.Response.ErrorCode, msg)
		}
		return
	}

	logger.Info("hook executed successfully")
	if h.Response.IncludeOutput {
		writeText(w, h.Response.SuccessCode, string(result.Output))
	} else {
		msg := h.Response.Message
		if msg == "" {
			msg = "ok\n"
		}
		writeText(w, h.Response.SuccessCode, msg)
	}
}

func writeText(w http.ResponseWriter, code int, body string) {
	w.WriteHeader(code)
	_, _ = fmt.Fprint(w, body)
}

func methodAllowed(method string, allowed []string) bool {
	for _, m := range allowed {
		if strings.EqualFold(m, method) {
			return true
		}
	}
	return false
}

func extractQuery(r *http.Request) map[string]string {
	q := make(map[string]string, len(r.URL.Query()))
	for k, vs := range r.URL.Query() {
		if len(vs) > 0 {
			q[k] = vs[0]
		}
	}
	return q
}

// realIP extracts the true client IP, optionally from a proxy header.
func realIP(r *http.Request, proxyHeader string) string {
	if proxyHeader != "" {
		if v := r.Header.Get(proxyHeader); v != "" {
			// Take the leftmost (originating) IP from a comma-separated list.
			ip := strings.TrimSpace(strings.SplitN(v, ",", 2)[0])
			if net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isJSON(r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	return strings.Contains(strings.ToLower(ct), "application/json")
}

// watchConfig polls the config file every 5 seconds and hot-reloads on change.
func (s *Server) watchConfig(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	absPath, _ := filepath.Abs(s.opts.ConfigFile)
	var lastMod time.Time
	if info, err := os.Stat(absPath); err == nil {
		lastMod = info.ModTime()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(absPath)
			if err != nil {
				continue
			}
			if !info.ModTime().After(lastMod) {
				continue
			}
			lastMod = info.ModTime()
			cfg, err := config.Load(absPath)
			if err != nil {
				slog.Error("hot reload: config parse error", "error", err)
				continue
			}
			if err := s.SetConfig(cfg); err != nil {
				slog.Error("hot reload: apply error", "error", err)
				continue
			}
			slog.Info("hot reload: config reloaded", "hooks", len(cfg.Hooks))
		}
	}
}
