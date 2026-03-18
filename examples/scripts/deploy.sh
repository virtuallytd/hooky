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
LOG_FILE="/var/log/hooky/deploy.log"

# ── Logging ───────────────────────────────────────────────────────────────────
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

# ── Deploy ────────────────────────────────────────────────────────────────────
log "Starting deployment"
log "  Repository : ${REPO:-unknown}"
log "  Ref        : ${GIT_REF:-unknown}"
log "  Directory  : $COMPOSE_DIR"
log "  Service    : $SERVICE"

cd "$COMPOSE_DIR"

log "Pulling latest image..."
docker compose pull "$SERVICE" 2>&1 | tee -a "$LOG_FILE"

log "Restarting service..."
docker compose up -d --no-deps "$SERVICE" 2>&1 | tee -a "$LOG_FILE"

log "Deployment complete"
