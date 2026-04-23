"""Gmail API helper for OpenAI Codex re-auth.

Scope: read-only access to a single inbox (defaults to you@example.com)
for the sole purpose of catching an email from OpenAI during a Codex login
flow and extracting the magic link or verification code it contains.

Nothing in this module knows about OAuth flows, browsers, or auth profiles.
"""
from __future__ import annotations

import base64
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass


GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
GMAIL_API_BASE = "https://gmail.googleapis.com/gmail/v1/users/me"


@dataclass
class Message:
    id: str
    thread_id: str
    from_addr: str
    subject: str
    date_header: str
    internal_date_ms: int
    body_text: str
    body_html: str

    def text_or_html(self) -> str:
        return self.body_text or self.body_html or ""


class GmailReader:
    """Single-inbox Gmail reader using a stored OAuth refresh token.

    credentials_path points at a JSON file with:
      { client_id, client_secret, refresh_token, token_uri, email }
    """

    def __init__(self, credentials_path: str):
        self.credentials_path = os.path.expanduser(credentials_path)
        with open(self.credentials_path) as f:
            self._creds = json.load(f)
        self._access_token: str | None = None
        self._access_expiry_ts: float = 0.0

    # ------------------------------------------------------------------ auth
    def _refresh_access_token(self) -> None:
        data = urllib.parse.urlencode({
            "client_id": self._creds["client_id"],
            "client_secret": self._creds["client_secret"],
            "refresh_token": self._creds["refresh_token"],
            "grant_type": "refresh_token",
        }).encode()
        req = urllib.request.Request(
            self._creds.get("token_uri", GOOGLE_TOKEN_URI),
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            resp = urllib.request.urlopen(req, timeout=15)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode()
            except Exception:
                pass
            raise RuntimeError(f"Gmail token refresh failed: HTTP {e.code} {body[:200]}")
        payload = json.loads(resp.read())
        self._access_token = payload["access_token"]
        self._access_expiry_ts = time.time() + payload.get("expires_in", 3600) - 60

    def _token(self) -> str:
        if not self._access_token or time.time() >= self._access_expiry_ts:
            self._refresh_access_token()
        assert self._access_token
        return self._access_token

    # --------------------------------------------------------------- fetching
    def _api_get(self, path: str, params: dict | None = None) -> dict:
        url = f"{GMAIL_API_BASE}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url, headers={"Authorization": f"Bearer {self._token()}"}
        )
        resp = urllib.request.urlopen(req, timeout=15)
        return json.loads(resp.read())

    def search(self, query: str, max_results: int = 10) -> list[str]:
        """Return message IDs matching the Gmail search query."""
        out = self._api_get(
            "/messages",
            {"q": query, "maxResults": str(max_results)},
        )
        return [m["id"] for m in out.get("messages", [])]

    def fetch(self, message_id: str) -> Message:
        raw = self._api_get(f"/messages/{message_id}", {"format": "full"})
        headers = {
            h["name"].lower(): h["value"]
            for h in raw.get("payload", {}).get("headers", [])
        }
        body_text, body_html = _extract_bodies(raw.get("payload", {}))
        return Message(
            id=raw["id"],
            thread_id=raw.get("threadId", ""),
            from_addr=headers.get("from", ""),
            subject=headers.get("subject", ""),
            date_header=headers.get("date", ""),
            internal_date_ms=int(raw.get("internalDate", "0")),
            body_text=body_text,
            body_html=body_html,
        )

    # ------------------------------------------------------------------ wait
    def wait_for_matching(
        self,
        query: str,
        since_ts_ms: int,
        timeout_s: int = 120,
        poll_interval_s: float = 4.0,
        predicate=None,
    ) -> Message | None:
        """Poll Gmail until a message matches query AND predicate, or timeout.

        since_ts_ms filters out pre-existing messages locally (Gmail search
        granularity is ~1 minute, so we do our own comparison against
        internalDate in ms).
        """
        deadline = time.time() + timeout_s
        seen: set[str] = set()
        while time.time() < deadline:
            try:
                ids = self.search(query, max_results=10)
            except Exception:
                ids = []
            for mid in ids:
                if mid in seen:
                    continue
                seen.add(mid)
                try:
                    msg = self.fetch(mid)
                except Exception:
                    continue
                if msg.internal_date_ms < since_ts_ms:
                    continue
                if predicate is None or predicate(msg):
                    return msg
            time.sleep(poll_interval_s)
        return None


# ---------------------------------------------------------------- body parse
def _decode_b64url(data: str) -> str:
    padded = data + "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")


def _extract_bodies(payload: dict) -> tuple[str, str]:
    """Recursively pull out text/plain and text/html bodies from a Gmail payload."""
    text = ""
    html = ""

    def walk(part: dict) -> None:
        nonlocal text, html
        mime = part.get("mimeType", "")
        body = part.get("body", {})
        data = body.get("data")
        if data:
            decoded = _decode_b64url(data)
            if mime == "text/plain" and not text:
                text = decoded
            elif mime == "text/html" and not html:
                html = decoded
        for sub in part.get("parts", []) or []:
            walk(sub)

    walk(payload)
    return text, html


# ---------------------------------------------------------------- extractors
LINK_RE = re.compile(r'https?://[^\s"\'<>]+', re.IGNORECASE)
CODE_RE = re.compile(r"(?<!\d)(\d{6})(?!\d)")


def extract_links(body: str, host_allowlist: list[str] | None = None) -> list[str]:
    """Return URLs from body. If host_allowlist is given, only URLs whose host
    (or a parent domain) is in the list are returned."""
    links = LINK_RE.findall(body)
    if not host_allowlist:
        return links
    allowed = [h.lower().lstrip(".") for h in host_allowlist]
    out: list[str] = []
    for link in links:
        try:
            host = urllib.parse.urlparse(link).hostname or ""
        except Exception:
            continue
        host = host.lower()
        if any(host == h or host.endswith("." + h) for h in allowed):
            out.append(link)
    return out


def extract_first_code(body: str) -> str | None:
    """Return first 6-digit numeric code found, or None."""
    m = CODE_RE.search(body)
    return m.group(1) if m else None
