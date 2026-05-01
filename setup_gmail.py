#!/usr/bin/env python3
"""One-time helper to refresh the Gmail OAuth refresh token.

Runs on the operator's Mac. Reads the existing
~/.openclaw/gmail-oauth-credentials.json (or a copy thereof) for the
registered OAuth client_id/client_secret, walks the Google OAuth code +
PKCE flow with a localhost callback, and writes the new refresh_token
back into the credentials file. Optionally SCPs the fresh credential to
neb-server and openclaw via SSH aliases.

Usage:
  python3 setup_gmail.py --creds /path/to/gmail-oauth-credentials.json
  python3 setup_gmail.py --creds ./creds.json --push neb-server,openclaw

If --creds is omitted and ./gmail-oauth-credentials.json exists, that's used.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
DEFAULT_SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
CALLBACK_PORT = 8765
CALLBACK_PATH = "/callback"


_callback_state: dict = {"code": None, "state": None, "hit": False}


def _pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _start_callback_server(expected_state: str) -> HTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != CALLBACK_PATH:
                self.send_response(404); self.end_headers(); return
            params = urllib.parse.parse_qs(parsed.query)
            state = (params.get("state") or [None])[0]
            code = (params.get("code") or [None])[0]
            err = (params.get("error") or [None])[0]
            if err:
                self.send_response(400); self.end_headers()
                self.wfile.write(f"OAuth error: {err}".encode())
                _callback_state["hit"] = True
                return
            if state != expected_state:
                self.send_response(400); self.end_headers()
                self.wfile.write(b"state mismatch"); return
            _callback_state["code"] = code
            _callback_state["state"] = state
            _callback_state["hit"] = True
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<h1>Done</h1><p>You can close this tab and return to the terminal.</p>"
            )

        def log_message(self, *_):  # silence
            pass

    # If the port is already taken, fail fast with a clear message
    try:
        srv = HTTPServer(("127.0.0.1", CALLBACK_PORT), Handler)
    except OSError as e:
        print(f"Could not bind 127.0.0.1:{CALLBACK_PORT}: {e}", file=sys.stderr)
        print("Another process is using the port. Stop it and retry.", file=sys.stderr)
        sys.exit(2)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh Gmail OAuth refresh token")
    parser.add_argument(
        "--creds",
        default="./gmail-oauth-credentials.json",
        help="Path to existing credentials JSON (read for client_id/client_secret/scopes/email; written back with new refresh_token).",
    )
    parser.add_argument(
        "--push",
        default="",
        help="Comma-separated SSH aliases to scp the credentials to (e.g., neb-server,openclaw).",
    )
    parser.add_argument(
        "--remote-path",
        default="~/.openclaw/gmail-oauth-credentials.json",
        help="Remote destination path on each --push host.",
    )
    args = parser.parse_args()

    creds_path = os.path.expanduser(args.creds)
    if not os.path.exists(creds_path):
        print(f"ERROR: {creds_path} does not exist. Pass --creds with the path to your existing gmail-oauth-credentials.json.", file=sys.stderr)
        return 1

    with open(creds_path) as f:
        creds = json.load(f)

    client_id = creds.get("client_id")
    client_secret = creds.get("client_secret")
    scopes = creds.get("scopes") or DEFAULT_SCOPES
    expected_email = creds.get("email")

    if not client_id or not client_secret:
        print("ERROR: existing credentials missing client_id or client_secret", file=sys.stderr)
        return 1

    redirect_uri = f"http://127.0.0.1:{CALLBACK_PORT}{CALLBACK_PATH}"
    state = secrets.token_urlsafe(16)
    verifier, challenge = _pkce_pair()

    auth_params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(scopes),
        "access_type": "offline",
        "prompt": "consent",  # forces refresh_token issuance
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "include_granted_scopes": "true",
    }
    if expected_email:
        auth_params["login_hint"] = expected_email

    auth_url = f"{AUTHORIZE_URL}?{urllib.parse.urlencode(auth_params)}"

    srv = _start_callback_server(state)
    print()
    print("Opening Google consent in your browser...")
    print(f"If it doesn't open automatically, paste this URL:\n  {auth_url}\n")
    print(f"Sign in as {expected_email or '(your Gmail account)'} and click Allow.")
    print(f"The redirect will land on {redirect_uri} (this terminal will detect it).")
    print()

    try:
        webbrowser.open(auth_url, new=1, autoraise=True)
    except Exception as e:
        print(f"(browser open failed: {e}; paste the URL manually)")

    # Wait up to 5 minutes for the callback
    import time
    deadline = time.time() + 300
    while not _callback_state["hit"] and time.time() < deadline:
        time.sleep(0.25)

    srv.shutdown()

    if not _callback_state["hit"]:
        print("Timed out waiting for OAuth callback.", file=sys.stderr)
        return 3

    code = _callback_state["code"]
    if not code:
        print("OAuth callback did not include a code (user denied or error).", file=sys.stderr)
        return 4

    # Exchange code for tokens
    body = urllib.parse.urlencode({
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": verifier,
    }).encode()

    req = urllib.request.Request(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=15)
    except urllib.error.HTTPError as e:
        print(f"Token exchange failed: HTTP {e.code} {e.read().decode()[:300]}", file=sys.stderr)
        return 5

    payload = json.loads(resp.read())
    new_refresh = payload.get("refresh_token")
    if not new_refresh:
        print("Token response did not include a refresh_token (Google sometimes withholds it on subsequent grants — this script forces prompt=consent which should always return one). Response:", file=sys.stderr)
        print(json.dumps(payload, indent=2), file=sys.stderr)
        return 6

    creds["refresh_token"] = new_refresh
    creds.setdefault("token_uri", TOKEN_URL)
    if not creds.get("scopes"):
        creds["scopes"] = scopes

    with open(creds_path, "w") as f:
        json.dump(creds, f, indent=2)
    os.chmod(creds_path, 0o600)
    print(f"\n✓ wrote new refresh_token to {creds_path}")

    pushes = [h.strip() for h in args.push.split(",") if h.strip()]
    for host in pushes:
        # Ensure remote dir exists then scp
        subprocess.run(
            ["ssh", host, "mkdir -p ~/.openclaw && chmod 700 ~/.openclaw"],
            check=True,
        )
        rc = subprocess.run(
            ["scp", "-q", creds_path, f"{host}:{args.remote_path}"],
        ).returncode
        if rc == 0:
            subprocess.run(
                ["ssh", host, f"chmod 600 {args.remote_path}"],
                check=False,
            )
            print(f"✓ pushed to {host}:{args.remote_path}")
        else:
            print(f"✗ scp to {host} failed (exit {rc})", file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
