#!/usr/bin/env python3
"""Codex token watchdog — the scheduled entry point.

This is what cron runs. Reactive only: never refreshes proactively. Waits
for the access token to actually expire, then performs the cheap refresh
on the next tick. Worst-case downtime between expiry and detection is one
cron interval (15min by default).

Logic:
  1. Read the current openai-codex:codex-cli profile from auth-profiles.json.
  2. If it still has positive life left (hours_left > REFRESH_BUFFER_HOURS,
     where REFRESH_BUFFER_HOURS=0 means "wait for actual expiry"), do
     nothing. Exit 0.
  3. Otherwise call OpenAI's token endpoint with the current refresh_token.
     a. Success → write the new tokens, done. Exit 0.
     b. invalid_grant / refresh_token_reused → the chain is broken.
        Escalate: run codex_reauth_server.py. Exit with whatever it returns.
     c. 5xx / timeout → transient. Don't escalate. Exit 2 so cron logs it.

Install as a 15-minute cron job on each server:

  */15 * * * * /home/ubuntu/codex-reauth/venv/bin/python \\
               /home/ubuntu/codex-reauth/codex_watchdog.py \\
               >> /home/ubuntu/.openclaw-oauth/watchdog.log 2>&1
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time

from auth_profiles import (
    discover_paths,
    read_current,
    write_token_cache,
    write_tokens,
)
from codex_oauth import CodexTokens, refresh_access_token

REFRESH_BUFFER_HOURS = 0  # reactive: refresh only after the token has actually expired
DEFAULT_GLOBS = [
    "~/.openclaw/auth-profiles.json",
    "~/.openclaw/agents/*/agent/auth-profiles.json",
]
OAUTH_CACHE = "~/.openclaw/oauth-token-cache.json"
ESCALATION_STATE_FILE = os.path.expanduser("~/.openclaw-oauth/watchdog-escalation-state.json")
ESCALATION_ALERT_THRESHOLD = 2
SLACK_ALERT_SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy", "slack-alert.sh")
PROXY_ENV_FILE = os.path.expanduser("~/.openclaw/residential-proxy.env")
SERVER_REAUTH_SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "codex_reauth_server.py"
)
LOG_DIR = os.path.expanduser("~/.openclaw-oauth")
os.makedirs(LOG_DIR, exist_ok=True)

log = logging.getLogger("codex-watchdog")
log.setLevel(logging.INFO)
log.handlers.clear()
fmt = logging.Formatter("%(asctime)s watchdog %(levelname)s %(message)s")
fh = logging.FileHandler(os.path.join(LOG_DIR, "watchdog.log"))
fh.setFormatter(fmt); log.addHandler(fh)
sh = logging.StreamHandler(sys.stdout)
sh.setFormatter(fmt); log.addHandler(sh)


def _is_invalid_grant(err: Exception) -> bool:
    msg = str(err).lower()
    return (
        "invalid_grant" in msg
        or "refresh_token_reused" in msg
        or "refresh token" in msg
        or "400" in msg
    )


def main() -> int:
    paths = discover_paths(DEFAULT_GLOBS)
    current = read_current(paths)
    if not current:
        log.error("no existing openai-codex profile found in any auth-profiles.json — escalating")
        return _escalate()

    expires_ms = int(current.get("expires", 0))
    now_ms = int(time.time() * 1000)
    hours_left = (expires_ms - now_ms) / 3_600_000

    if hours_left > REFRESH_BUFFER_HOURS:
        log.info("token healthy, %.1fh remaining — no action", hours_left)
        return 0

    refresh_tok = current.get("refresh")
    if not refresh_tok:
        log.error("profile has no refresh token — escalating")
        return _escalate()

    log.info("token expired (%.1fh past expiry), attempting reactive refresh", -hours_left)
    try:
        tokens: CodexTokens = refresh_access_token(refresh_tok)
    except Exception as e:
        if _is_invalid_grant(e):
            log.error("refresh returned invalid_grant — escalating: %s", e)
            return _escalate()
        log.warning("refresh failed transiently: %s", e)
        return 2

    write_tokens(paths, tokens)
    write_token_cache(OAUTH_CACHE, tokens)
    new_hours = (tokens.expires_ms - now_ms) / 3_600_000
    log.info("API refresh OK, new token expires in %.1fh", new_hours)
    return 0


def _load_escalation_state() -> dict:
    try:
        with open(ESCALATION_STATE_FILE) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {"consecutive_failures": 0}


def _save_escalation_state(state: dict) -> None:
    os.makedirs(os.path.dirname(ESCALATION_STATE_FILE), exist_ok=True)
    with open(ESCALATION_STATE_FILE, "w") as f:
        json.dump(state, f)


def _alert_slack(message: str) -> None:
    """Post a Slack alert via the shared slack-alert.sh script. Non-fatal on
    failure — we never want the watchdog to crash because Slack is down."""
    if not os.path.exists(SLACK_ALERT_SCRIPT):
        log.error("slack-alert.sh not found at %s; cannot send alert", SLACK_ALERT_SCRIPT)
        return
    cmd = [
        "bash", "-c",
        f'set -a; [ -f "{PROXY_ENV_FILE}" ] && source "{PROXY_ENV_FILE}"; set +a; '
        f'bash "{SLACK_ALERT_SCRIPT}" codex-watchdog "$1"',
        "_",
        message,
    ]
    try:
        subprocess.run(cmd, check=False, timeout=15)
    except Exception as e:
        log.error("failed to invoke slack-alert.sh: %s", e)


def _escalate() -> int:
    if not os.path.exists(SERVER_REAUTH_SCRIPT):
        log.error("escalation target not found: %s", SERVER_REAUTH_SCRIPT)
        return 3
    log.info("escalating to codex_reauth_server.py")
    result = subprocess.run(
        [sys.executable, SERVER_REAUTH_SCRIPT],
        capture_output=False,
    )
    log.info("codex_reauth_server.py exited %d", result.returncode)

    state = _load_escalation_state()
    if result.returncode == 0:
        if state.get("consecutive_failures", 0) > 0:
            log.info("escalation recovered after %d failure(s)", state["consecutive_failures"])
        state["consecutive_failures"] = 0
    else:
        state["consecutive_failures"] = state.get("consecutive_failures", 0) + 1
        log.warning(
            "escalation failed (exit %d); consecutive failures: %d",
            result.returncode, state["consecutive_failures"],
        )
        if state["consecutive_failures"] >= ESCALATION_ALERT_THRESHOLD:
            _alert_slack(
                f"codex reauth escalation has failed {state['consecutive_failures']} times in a row "
                f"(last exit code: {result.returncode}). Likely causes: residential proxy down, "
                f"IPRoyal IP rotated, or OpenAI rejecting even the residential IP. "
                f"Manual intervention: verify `systemctl --user status residential-proxy.service` "
                f"and/or fall back to Mac tunnel."
            )
    _save_escalation_state(state)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
