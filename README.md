# Hooky

[![Test](https://github.com/virtuallytd/hooky/actions/workflows/test.yml/badge.svg)](https://github.com/virtuallytd/hooky/actions/workflows/test.yml)

A lightweight HTTP webhook server written in Go. Trigger shell scripts from HTTP requests with built-in secret validation, rate limiting, and configurable execution controls. Runs standalone or in Docker.

## Features

- **Secret validation** — HMAC-SHA256/SHA1/SHA512 signatures or bearer tokens
- **Trigger rules** — composable `and`/`or`/`not` conditions on payload fields, headers, query params, or IP ranges
- **Rate limiting** — sliding window per hook
- **Concurrency control** — limit simultaneous executions per hook
- **Command timeouts** — kill long-running commands automatically
- **Fire-and-forget** — return a response immediately and run the script in the background
- **Hot reload** — edit your config without restarting (`-hotreload` or `SIGHUP`)
- **Proxy-aware** — correct client IP resolution behind reverse proxies
- **Structured logging** — JSON or text output via `log/slog`
- **Health endpoint** — `/health` and `/healthz`
- **No secret in config** — use `env:VAR` or `file:/path` to keep secrets out of config files

## Installation

**From source:**
```bash
go install hooky@latest
```

**Docker:**
```bash
docker compose up --build
```

**Binary:**
Download from the [releases page](https://github.com/virtuallytd/hooky/releases).

## Quick Start

1. Create a `hooks.yaml`:

```yaml
hooks:
  - id: deploy
    command: /scripts/deploy.sh
    secret:
      type: hmac-sha256
      header: X-Hub-Signature-256
      value: env:DEPLOY_SECRET
```

2. Run:

```bash
DEPLOY_SECRET=mysecret hooky -hooks hooks.yaml
```

3. Trigger it:

```bash
BODY='{"ref":"main"}'
SIG=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "mysecret" | awk '{print $2}')

curl -X POST http://localhost:9000/hooks/deploy \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=$SIG" \
  -d "$BODY"
```

## Configuration

Hooks are defined in a YAML or JSON file. Pass the path with `-hooks`.

```yaml
hooks:
  - id: string                  # URL endpoint: /hooks/{id}
    command: string             # Executable to run
    working-dir: string         # Working directory for the command
    timeout: duration           # e.g. 30s, 5m (default: 30s)
    http-methods: [POST]        # Allowed HTTP methods (default: [POST])
    fire-and-forget: false      # Return 200 immediately, run script in background
    max-concurrent: 0           # Max simultaneous executions (0 = unlimited)

    secret:                     # Validate the incoming request
      type: hmac-sha256         # hmac-sha1 | hmac-sha256 | hmac-sha512 | token
      header: X-Hub-Signature-256
      query: token              # Alternative: read token from query parameter
      value: env:MY_SECRET      # env:VAR, file:/path, or a literal string

    trigger-rule:               # Additional conditions (optional)
      and:
        - match:
            type: value         # value | regex | ip-whitelist | payload-hmac-sha256 | ...
            parameter:
              source: payload   # payload | header | query | request | raw-body
              name: event       # dot-notation for nested fields: repository.full_name
            value: push

    args:                       # Positional arguments passed to the command
      - source: payload
        name: ref

    env:                        # Environment variables for the command
      - name: GIT_REF
        source: payload         # payload | header | query | env | literal
        key: ref

    response:
      success-code: 200
      error-code: 500
      mismatch-code: 403        # Returned when secret or trigger rules fail
      message: "Triggered."
      include-output: false     # Stream stdout/stderr back to the caller
      headers:
        X-Custom: value

    rate-limit:
      requests: 10
      window: 1m
```

### Parameter Sources

| Source | Description |
|--------|-------------|
| `payload` | JSON body field. Supports dot-notation: `repository.full_name` |
| `header` | HTTP request header |
| `query` | URL query parameter |
| `request` | Request metadata. Supported names: `remote-addr` |
| `raw-body` | The raw, unparsed request body |
| `literal` | A hard-coded string value (use `name` as the value) |
| `entire-payload` | The full JSON body as a string |
| `entire-headers` | All headers serialised as JSON |
| `entire-query` | All query parameters serialised as JSON |

### Secret Resolution

The `value` field in `secret` and trigger rule `secret` fields supports three formats:

| Format | Description |
|--------|-------------|
| `env:MY_VAR` | Read from the `$MY_VAR` environment variable |
| `file:/run/secrets/token` | Read from a file (whitespace trimmed) |
| `literal-value` | Used as-is |

### Trigger Rules

Rules can be nested with `and`, `or`, and `not`:

```yaml
trigger-rule:
  and:
    - match:
        type: value
        parameter: {source: payload, name: event}
        value: push
    - or:
        - match:
            type: regex
            parameter: {source: payload, name: ref}
            value: ^refs/heads/main$
        - match:
            type: ip-whitelist
            ip-range: 10.0.0.0/8
```

**Match types:**

| Type | Description |
|------|-------------|
| `value` | Exact string match |
| `regex` | Go regular expression match |
| `ip-whitelist` | CIDR range check (uses `ip-range` field) |
| `payload-hmac-sha1` | HMAC-SHA1 signature of the raw body |
| `payload-hmac-sha256` | HMAC-SHA256 signature of the raw body |
| `payload-hmac-sha512` | HMAC-SHA512 signature of the raw body |

## CLI Options

```
-hooks string        Path to hooks config file, JSON or YAML (default: hooks.yaml)
-addr string         Address to listen on (default: :9000)
-prefix string       URL prefix for hook endpoints (default: hooks)
-cert string         TLS certificate file — enables HTTPS when set
-key string          TLS private key file
-hotreload           Watch config file and reload on change
-log-format string   Log format: text | json (default: text)
-log-level string    Log level: debug | info | warn | error (default: info)
-proxy-header string Header to use for the real client IP (e.g. X-Forwarded-For)
-version             Print version and exit
```

## Docker

A `docker-compose.yml` is included. Mount your config and scripts, and optionally the Docker socket if your scripts need to control other containers:

```yaml
services:
  hooky:
    build: .
    ports:
      - "9000:9000"
    volumes:
      - ./hooks.yaml:/app/hooks.yaml:ro
      - ./scripts:/app/scripts:ro
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - DEPLOY_SECRET=changeme
```

> **Warning:** Mounting the Docker socket gives the container full control over the host's Docker daemon. Ensure the server is not publicly accessible without authentication.

## Testing

```bash
# Run all tests
go test ./...

# Run a specific package
go test ./internal/hook/...

# Run a single test
go test ./internal/server/... -run TestHook_HMAC_Valid

# Run with verbose output
go test ./... -v

# Run with the race detector
go test -race ./...
```

### What the tests cover

| Package | Coverage |
|---------|----------|
| `internal/config` | YAML and JSON loading, default values, validation (missing ID/command, duplicate IDs), `env:` and `file:` secret resolution |
| `internal/hook` | Parameter extraction from all sources (payload with dot-notation, header, query, raw-body), HMAC-SHA1/256/512 validation, token auth with Bearer prefix stripping, all trigger rule types (`value`, `regex`, `ip-whitelist`, `payload-hmac-*`), boolean rule composition (`and`/`or`/`not`), rate limiting (allow, block, window reset), command execution (success, failure, exit codes, timeout, working directory, env var passing, concurrency limits, fire-and-forget) |
| `internal/server` | Full HTTP request lifecycle — routing, method enforcement, secret validation, trigger rules, rate limiting, custom response headers, proxy IP resolution, hot reload via `SetConfig`, graceful shutdown, end-to-end test from config file on disk through to command output |

Tests run in CI on every push and pull request via GitHub Actions.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT
