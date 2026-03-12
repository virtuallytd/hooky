# Contributing

## Getting Started

Ensure you have Go 1.22 or later installed, then clone the repo and verify everything works:

```bash
git clone git@github.com:virtuallytd/hooky.git
cd hooky
go test ./...
```

## Making Changes

- **Bug fixes and small improvements** — open a pull request directly.
- **New features or significant changes** — open an issue first to discuss the approach before writing code.

All pull requests must pass the test suite. If you're adding new behaviour, add tests that cover it.

## Running Tests

```bash
# Full test suite
go test ./...

# With race detector (recommended before submitting a PR)
go test -race ./...

# Single package
go test ./internal/hook/...

# Single test
go test ./internal/server/... -run TestHook_HMAC_Valid
```

### Package structure

| Package | Responsibility |
|---------|---------------|
| `internal/config` | Config structs, YAML/JSON loading, secret value resolution |
| `internal/hook` | Request parsing, rule evaluation, command execution |
| `internal/server` | HTTP server, request routing, hot reload |

## Code Style

Follow standard Go conventions. Run `go vet ./...` before submitting — the CI pipeline does the same.

## Commit Messages

Use short, descriptive commit messages in the imperative mood:

```
Add SHA512 support to HMAC validation
Fix rate limiter window not resetting after expiry
```

## Reporting Issues

Open an issue on [GitHub](https://github.com/virtuallytd/hooky/issues) with enough detail to reproduce the problem — the hook config (with secrets removed), the request you're sending, and the response or log output you're seeing.
