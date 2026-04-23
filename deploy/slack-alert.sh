#!/usr/bin/env bash
# Post a Slack message via chat.postMessage using a bot token.
#
# Usage: slack-alert.sh <component> <message>
#
# Env vars required (loaded from EnvironmentFile in the calling systemd unit):
#   SLACK_BOT_TOKEN  — xoxb-... with chat:write scope
#   SLACK_CHANNEL_ID — e.g., C09FLJDCAJD (aaa-ops)
#
# Exits non-zero if the post fails, so systemd logs the failure.

set -euo pipefail

COMPONENT="${1:-unknown}"
MESSAGE="${2:-no message}"
HOSTNAME_TAG=$(hostname -s)
TS=$(date -Iseconds)

if [[ -z "${SLACK_BOT_TOKEN:-}" || -z "${SLACK_CHANNEL_ID:-}" ]]; then
  echo "slack-alert: SLACK_BOT_TOKEN or SLACK_CHANNEL_ID unset; cannot alert" >&2
  exit 2
fi

TEXT=":rotating_light: *[${HOSTNAME_TAG}] ${COMPONENT} alert* — ${TS}
${MESSAGE}"

PAYLOAD=$(python3 -c "
import json, sys
print(json.dumps({'channel': sys.argv[1], 'text': sys.argv[2]}))
" "$SLACK_CHANNEL_ID" "$TEXT")

RESP=$(curl -sS -X POST \
  -H "Authorization: Bearer ${SLACK_BOT_TOKEN}" \
  -H "Content-Type: application/json; charset=utf-8" \
  --data-binary "$PAYLOAD" \
  https://slack.com/api/chat.postMessage)

OK=$(printf '%s' "$RESP" | python3 -c "import json,sys; print(json.load(sys.stdin).get('ok', False))")
if [[ "$OK" != "True" ]]; then
  echo "slack-alert: post failed: $RESP" >&2
  exit 3
fi
