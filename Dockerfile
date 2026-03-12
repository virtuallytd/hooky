# syntax=docker/dockerfile:1

# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

WORKDIR /build

# Cache dependency downloads separately from source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o hooky .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.19

# bash and curl are useful for hook scripts; docker-cli allows controlling
# the host Docker daemon when /var/run/docker.sock is mounted.
RUN apk add --no-cache bash curl docker-cli ca-certificates

WORKDIR /app

COPY --from=builder /build/hooky /usr/local/bin/hooky

EXPOSE 9000

ENTRYPOINT ["hooky"]
CMD ["-hooks", "/app/hooks.yaml"]
