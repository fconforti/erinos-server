#!/usr/bin/env bash
set -euo pipefail

echo "Waiting for headscale to be ready..."

for i in $(seq 1 30); do
  if docker compose exec headscale headscale apikeys list >/dev/null 2>&1; then
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "Error: headscale not ready after 30 attempts" >&2
    exit 1
  fi
  sleep 2
done

echo "Headscale is ready. Creating API key..."

KEY=$(docker compose exec headscale headscale apikeys create --expiration 9999d)

echo ""
echo "Add this to your .env file:"
echo ""
echo "  HEADSCALE_API_KEY=${KEY}"
echo ""
