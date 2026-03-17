#!/bin/bash
# deploy.sh — pulls the latest image and restarts a Docker Compose service.
#
# Place this script at /opt/hooky/scripts/deploy.sh on the target server.
# Configure the variables below to match your application.
#
# Expected environment variables (set via hooks.yaml env: block):
#   GIT_REF  — the git ref that triggered the deployment (e.g. refs/heads/main)
#   REPO     — the repository name (e.g. myorg/myapp)

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
COMPOSE_DIR="/opt/myapp"
SERVICE="myapp"

# ── Deploy ────────────────────────────────────────────────────────────────────
echo "Starting deployment"
echo "  Repository : ${REPO:-unknown}"
echo "  Ref        : ${GIT_REF:-unknown}"
echo "  Directory  : $COMPOSE_DIR"
echo "  Service    : $SERVICE"

cd "$COMPOSE_DIR"

echo "Pulling latest image..."
docker compose pull "$SERVICE"

echo "Restarting service..."
docker compose up -d --no-deps "$SERVICE"

echo "Deployment complete"
