#!/usr/bin/env bash
# Daily health check: curl through the residential SOCKS proxy and verify
# the returned public IP matches IPROYAL_EXPECTED_IP. Post to Slack on
# mismatch or curl failure.
#
# Run via cron, e.g. 0 9 * * * /home/ubuntu/codex-reauth/deploy/health-check.sh
#
# Env vars required (sourced from ~/.openclaw/residential-proxy.env):
#   IPROYAL_EXPECTED_IP — the IP we should see
#   SLACK_BOT_TOKEN, SLACK_CHANNEL_ID — for alerts

set -euo pipefail

ENV_FILE="${HOME}/.openclaw/residential-proxy.env"
if [[ -f "$ENV_FILE" ]]; then
  # Use `set -a` so sourced vars are exported to subprocesses (slack-alert.sh)
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERT="${SCRIPT_DIR}/slack-alert.sh"

EXPECTED="${IPROYAL_EXPECTED_IP:-}"
if [[ -z "$EXPECTED" ]]; then
  echo "health-check: IPROYAL_EXPECTED_IP not set in $ENV_FILE" >&2
  exit 2
fi

# 10s total timeout; SOCKS handshake + IP echo should be fast
OBSERVED=$(curl -sS --max-time 10 --socks5 127.0.0.1:1080 https://api.ipify.org || true)

if [[ -z "$OBSERVED" ]]; then
  bash "$ALERT" residential-proxy "health check failed: could not reach api.ipify.org through SOCKS tunnel. Tunnel may be down." || true
  exit 3
fi

if [[ "$OBSERVED" != "$EXPECTED" ]]; then
  bash "$ALERT" residential-proxy "health check IP mismatch: expected ${EXPECTED}, got ${OBSERVED}. IPRoyal may have rotated our IP." || true
  exit 4
fi

echo "$(date -Iseconds) health-check OK (${OBSERVED})"
