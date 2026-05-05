"""Verify read/write contract for Codex CLI 0.128.0+'s native ~/.codex/auth.json.

Locks in:
  - read returns openclaw-shaped profile when the file is valid
  - read returns None when missing or malformed
  - write merges into existing file preserving non-token fields
  - write no-ops on missing file unless create_if_missing=True
  - id_token is preserved across refresh-style writes that omit it
"""
from __future__ import annotations

import base64
import json
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _jwt(exp_seconds: int) -> str:
    """Build a fake JWT with given exp claim. Header/signature are placeholders."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(
        json.dumps({"exp": exp_seconds, "https://api.openai.com/auth": {"chatgpt_account_id": "acct_xyz"}}).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{payload}.sig"


def test_read_returns_none_when_missing(tmp_path):
    from auth_profiles import read_codex_cli_native
    assert read_codex_cli_native(str(tmp_path / "nope.json")) is None


def test_read_returns_profile_shape_when_valid(tmp_path):
    from auth_profiles import read_codex_cli_native
    f = tmp_path / "auth.json"
    exp_s = int(time.time()) + 3600
    f.write_text(json.dumps({
        "OPENAI_API_KEY": None,
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": _jwt(exp_s),
            "refresh_token": "rt_abc",
            "id_token": "idt_abc",
            "account_id": "acct_xyz",
        },
        "last_refresh": "2026-05-04T00:00:00Z",
    }))
    p = read_codex_cli_native(str(f))
    assert p is not None
    assert p["provider"] == "openai-codex"
    assert p["mode"] == "oauth"
    assert p["access"].startswith("ey")
    assert p["refresh"] == "rt_abc"
    assert p["accountId"] == "acct_xyz"
    assert p["expires"] == exp_s * 1000


def test_write_no_op_when_missing(tmp_path):
    from auth_profiles import write_codex_cli_native
    from codex_oauth import CodexTokens
    target = tmp_path / "auth.json"
    tokens = CodexTokens(access="a", refresh="r", expires_ms=1, account_id=None)
    assert write_codex_cli_native(tokens, str(target)) is False
    assert not target.exists()


def test_write_merges_preserving_non_token_fields(tmp_path):
    from auth_profiles import write_codex_cli_native
    from codex_oauth import CodexTokens
    target = tmp_path / "auth.json"
    target.write_text(json.dumps({
        "OPENAI_API_KEY": None,
        "auth_mode": "chatgpt",
        "tokens": {
            "access_token": "old_at",
            "refresh_token": "old_rt",
            "id_token": "old_idt",
            "account_id": "acct_old",
        },
        "last_refresh": "old",
    }))
    tokens = CodexTokens(
        access="new_at", refresh="new_rt",
        expires_ms=int(time.time() * 1000) + 3600_000,
        account_id="acct_new",
        id_token=None,  # simulate refresh response that omitted id_token
    )
    assert write_codex_cli_native(tokens, str(target)) is True
    d = json.loads(target.read_text())
    assert d["OPENAI_API_KEY"] is None
    assert d["auth_mode"] == "chatgpt"
    assert d["tokens"]["access_token"] == "new_at"
    assert d["tokens"]["refresh_token"] == "new_rt"
    assert d["tokens"]["id_token"] == "old_idt", "id_token must be preserved when refresh omits it"
    assert d["tokens"]["account_id"] == "acct_new"
    assert d["last_refresh"] != "old"


def test_write_creates_when_missing_and_flag_set(tmp_path):
    from auth_profiles import write_codex_cli_native
    from codex_oauth import CodexTokens
    target = tmp_path / "subdir" / "auth.json"
    tokens = CodexTokens(
        access="at", refresh="rt",
        expires_ms=int(time.time() * 1000) + 3600_000,
        account_id="acct", id_token="idt",
    )
    assert write_codex_cli_native(tokens, str(target), create_if_missing=True) is True
    assert target.exists()
    d = json.loads(target.read_text())
    assert d["auth_mode"] == "chatgpt"
    assert d["tokens"]["access_token"] == "at"
    assert d["tokens"]["id_token"] == "idt"
    # Permissions should be 0600 since this file holds secrets
    import stat
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"


def test_to_codex_cli_tokens_shape():
    from codex_oauth import CodexTokens
    tokens = CodexTokens(
        access="at", refresh="rt", expires_ms=0,
        account_id="acct", id_token="idt",
    )
    block = tokens.to_codex_cli_tokens()
    assert block == {
        "access_token": "at",
        "refresh_token": "rt",
        "id_token": "idt",
        "account_id": "acct",
    }


def test_to_codex_cli_tokens_omits_optional_fields():
    from codex_oauth import CodexTokens
    tokens = CodexTokens(access="at", refresh="rt", expires_ms=0, account_id=None)
    block = tokens.to_codex_cli_tokens()
    assert block == {"access_token": "at", "refresh_token": "rt"}
