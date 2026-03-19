# Examples

End-to-end example showing how to trigger a hooky deployment from a GitHub Actions workflow.

## Overview

```
GitHub push to main
  → GitHub Actions runs trigger-deploy.yml
    → Sends signed POST request to hooky
      → hooky validates HMAC signature and trigger rule
        → deploy.sh pulls latest image and restarts the service
```

## Files

| File | Purpose |
|------|---------|
| [`hooks.yaml`](hooks.yaml) | Hooky configuration for the deploy hook |
| [`scripts/deploy.sh`](scripts/deploy.sh) | Deployment script run on the server |
| [`github/trigger-deploy.yml`](github/trigger-deploy.yml) | GitHub Actions workflow that triggers the hook |

## Setup

### 1. Server — install the script

Copy the deploy script to the server and make it executable:

```bash
sudo cp examples/scripts/deploy.sh /opt/hooky/scripts/deploy.sh
sudo chown root:hooky /opt/hooky/scripts/deploy.sh
sudo chmod 750 /opt/hooky/scripts/deploy.sh
```

Edit the `COMPOSE_DIR` and `SERVICE` variables at the top of the script to match your application.

### 2. Server — configure hooky

Copy the example hooks config:

```bash
sudo cp examples/hooks.yaml /etc/hooky/hooks.yaml
```

### 3. Server — configure credentials

If your application image is hosted in a private registry (e.g. a private GitHub Container Registry repository), add registry credentials to `/etc/hooky/.env` so the deploy script can authenticate before pulling:

```bash
# /etc/hooky/.env
DEPLOY_SECRET=your-secret-here

# Registry auth — omit these if your image is public
REGISTRY=ghcr.io
REGISTRY_USER=myorg
REGISTRY_TOKEN=ghp_xxxxxxxxxxxx   # GitHub PAT with read:packages scope
```

The deploy script checks for `REGISTRY_TOKEN` at runtime and skips the login step if it is not set, so this is safe to leave out for public images.

Restart the service after editing `.env`:

```bash
sudo systemctl restart hooky
```

### 4. GitHub — add repository secrets and variables

In your application repository go to **Settings → Secrets and variables → Actions** and add:

| Secret | Value |
|--------|-------|
| `DEPLOY_SECRET` | The same secret set in `/etc/hooky/.env` |
| `HOOKY_URL` | The public URL of your hooky server, e.g. `https://hooks.example.com` |

### 5. GitHub — add the workflow

Copy the example workflow into your application repository:

```bash
mkdir -p .github/workflows
cp examples/github/trigger-deploy.yml .github/workflows/deploy.yml
```

Commit and push. The next push to `main` will trigger the deployment.

## How the signature works

The GitHub Actions workflow computes an HMAC-SHA256 signature of the request payload using the shared `DEPLOY_SECRET`:

```bash
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$DEPLOY_SECRET" | awk '{print $2}')
```

Hooky validates this signature before executing the script. If the signature does not match — or the `ref` in the payload is not `refs/heads/main` — the request is rejected with a `403` and the script is never run.
