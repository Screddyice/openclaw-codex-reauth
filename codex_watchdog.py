#!/usr/bin/env python3
"""Codex token watchdog — the scheduled entry point.

This is what cron runs. It does the cheap thing on every tick and only
escalates to the expensive browser-driven re-auth when the cheap thing
can't save the token.

Logic:
  1. Read the current openai-codex:codex-cli profile from auth-profiles.json.
  2. If it has > REFRESH_BUFFER_HOURS of life left, do nothing. Exit 0.
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

REFRESH_BUFFER_HOURS = 4
DEFAULT_GLOBS = [
    "~/.openclaw/auth-profiles.json",
    "~/.openclaw/agents/*/agent/auth-profiles.json",
]
OAUTH_CACHE = "~/.openclaw/oauth-token-cache.json"
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

    log.info("token has %.1fh left, attempting API refresh", hours_left)
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
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
