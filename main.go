package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"hooky/internal/config"
	"hooky/internal/server"
)

var version = "dev"

func main() {
	var (
		configFile  = flag.String("hooks", "hooks.yaml", "path to hooks config file (JSON or YAML)")
		addr        = flag.String("addr", ":9000", "address to listen on (e.g. :9000 or 0.0.0.0:8080)")
		urlPrefix   = flag.String("prefix", "hooks", "URL prefix for hook endpoints")
		certFile    = flag.String("cert", "", "TLS certificate file — enables HTTPS when set")
		keyFile     = flag.String("key", "", "TLS private key file")
		hotReload   = flag.Bool("hotreload", false, "watch config file and reload on change (polls every 5s)")
		logFormat   = flag.String("log-format", "text", "log format: text | json")
		logLevel    = flag.String("log-level", "info", "log level: debug | info | warn | error")
		proxyHeader = flag.String("proxy-header", "", "header to use for the real client IP (e.g. X-Forwarded-For)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("hooky %s\n", version)
		os.Exit(0)
	}

	slog.SetDefault(slog.New(buildHandler(*logFormat, *logLevel)))

	absConfig, err := filepath.Abs(*configFile)
	if err != nil {
		slog.Error("resolving config path", "error", err)
		os.Exit(1)
	}

	cfg, err := config.Load(absConfig)
	if err != nil {
		slog.Error("loading config", "error", err, "file", absConfig)
		os.Exit(1)
	}
	slog.Info("config loaded", "file", absConfig, "hooks", len(cfg.Hooks))

	srv := server.New(server.Options{
		Addr:        *addr,
		URLPrefix:   *urlPrefix,
		CertFile:    *certFile,
		KeyFile:     *keyFile,
		ProxyHeader: *proxyHeader,
		HotReload:   *hotReload,
		ConfigFile:  absConfig,
	})
	if err := srv.SetConfig(cfg); err != nil {
		slog.Error("applying config", "error", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				slog.Info("SIGHUP received, reloading config")
				newCfg, err := config.Load(absConfig)
				if err != nil {
					slog.Error("reload failed", "error", err)
					continue
				}
				if err := srv.SetConfig(newCfg); err != nil {
					slog.Error("reload apply failed", "error", err)
					continue
				}
				slog.Info("config reloaded", "hooks", len(newCfg.Hooks))
			default:
				slog.Info("shutting down", "signal", sig)
				cancel()
			}
		}
	}()

	if err := srv.Run(ctx); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

func buildHandler(format, level string) slog.Handler {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	if format == "json" {
		return slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.NewTextHandler(os.Stdout, opts)
}
