"""Run the Gmail OAuth installed-app grant once and write credentials.

Reads client_secret JSON, opens browser to Google's auth URL, listens on
localhost for the redirect, exchanges code for tokens, then writes the
credentials file in the format that gmail_reader.GmailReader expects:

  { client_id, client_secret, refresh_token, token_uri, email, scopes }

Run interactively. Sign in as the email passed via --user.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import socket
import sys
import threading
import urllib.parse
import urllib.request
import webbrowser

GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


_state: dict = {"code": None, "error": None}


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a, **kw):
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if "code" in params:
            _state["code"] = params["code"][0]
            body = b"<h2>OK. You can close this tab.</h2>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        if "error" in params:
            _state["error"] = params["error"][0]
            body = f"<h2>Error: {_state['error']}</h2>".encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)
            return
        # Anything else (favicon, prefetch, etc.) — ignore silently
        self.send_response(204)
        self.end_headers()


def _pick_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--client-secret", required=True)
    ap.add_argument("--user", required=True, help="Gmail address to grant as")
    ap.add_argument("--out", required=True, help="Output credentials path")
    args = ap.parse_args()

    cs = json.load(open(os.path.expanduser(args.client_secret)))
    inner = cs.get("installed") or cs.get("web") or cs
    client_id = inner["client_id"]
    client_secret = inner["client_secret"]

    port = _pick_port()
    redirect_uri = f"http://localhost:{port}"

    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()

    auth_url = GOOGLE_AUTH + "?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": SCOPE,
        "access_type": "offline",
        "prompt": "consent",
        "login_hint": args.user,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })

    server = http.server.HTTPServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()

    print(f"Opening browser; sign in as {args.user}")
    print(f"If browser doesn't open, paste this URL:\n{auth_url}\n")
    webbrowser.open(auth_url)

    while _state["code"] is None and _state["error"] is None:
        threading.Event().wait(0.5)
    server.shutdown()

    if _state["error"]:
        print(f"OAuth error: {_state['error']}", file=sys.stderr)
        return 1

    body = urllib.parse.urlencode({
        "code": _state["code"],
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code_verifier": verifier,
    }).encode()
    req = urllib.request.Request(
        GOOGLE_TOKEN, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        resp = urllib.request.urlopen(req, timeout=20)
    except urllib.error.HTTPError as e:
        print(f"Token exchange failed: {e.code} {e.read().decode()[:300]}", file=sys.stderr)
        return 2
    tokens = json.loads(resp.read())
    if "refresh_token" not in tokens:
        print("No refresh_token in response — Google may have suppressed it.", file=sys.stderr)
        print("Revoke prior grants at https://myaccount.google.com/permissions and retry.", file=sys.stderr)
        return 3

    out = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": tokens["refresh_token"],
        "token_uri": GOOGLE_TOKEN,
        "email": args.user,
        "scopes": [SCOPE],
    }
    out_path = os.path.expanduser(args.out)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    os.chmod(out_path, 0o600)
    print(f"Wrote {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
