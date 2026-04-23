"""Read/write openai-codex tokens into openclaw's auth-profiles.json files.

Scope: only the `openai-codex:codex-cli` slot. Does not touch other providers.
"""
from __future__ import annotations

import glob
import json
import os

from codex_oauth import CodexTokens

PROFILE_KEY = "openai-codex:codex-cli"
PROVIDER_NAME = "openai-codex"
DEFAULT_GLOBS = [
    "~/.openclaw/auth-profiles.json",
    "~/.openclaw/agents/*/agent/auth-profiles.json",
]


def discover_paths(globs: list[str] | None = None) -> list[str]:
    out: list[str] = []
    for g in globs or DEFAULT_GLOBS:
        out.extend(glob.glob(os.path.expanduser(g)))
    return out


def read_current(paths: list[str]) -> dict | None:
    """Return the freshest (longest-expiring) existing codex profile, or None."""
    best: dict | None = None
    best_expires = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
        except Exception:
            continue
        prof = d.get("profiles", {}).get(PROFILE_KEY)
        if not prof:
            continue
        exp = int(prof.get("expires", 0))
        if exp > best_expires:
            best_expires = exp
            best = prof
    return best


def write_tokens(paths: list[str], tokens: CodexTokens) -> int:
    """Overwrite the codex profile slot in all given auth-profiles.json files.

    Returns the number of files successfully updated.
    """
    new_profile = tokens.to_openclaw_profile()
    updated = 0
    for p in paths:
        try:
            with open(p) as f:
                d = json.load(f)
        except Exception:
            continue
        d.setdefault("profiles", {})[PROFILE_KEY] = new_profile
        d.get("profiles", {}).pop(f"{PROVIDER_NAME}:api_key", None)
        d.setdefault("lastGood", {})[PROVIDER_NAME] = PROFILE_KEY
        try:
            with open(p, "w") as f:
                json.dump(d, f)
            updated += 1
        except Exception:
            pass
    return updated


def write_token_cache(cache_path: str, tokens: CodexTokens) -> None:
    """Update ~/.openclaw/oauth-token-cache.json (used by legacy refresh cron)."""
    cache_path = os.path.expanduser(cache_path)
    try:
        with open(cache_path) as f:
            c = json.load(f)
    except Exception:
        c = {}
    c["access"] = tokens.access
    c["refresh"] = tokens.refresh
    c["expires"] = tokens.expires_ms
    with open(cache_path, "w") as f:
        json.dump(c, f)
