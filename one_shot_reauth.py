#!/usr/bin/env python3
"""One-shot interactive OAuth reauth. Prints a URL, waits for callback on
127.0.0.1:1455 (expected to be SSH-tunneled to the operator Mac), writes
fresh tokens to auth-profiles.json + oauth-token-cache.json, then exits."""
from __future__ import annotations
import datetime, json, os, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.expanduser("~/codex-reauth"))
from codex_oauth import build_authorize_url, exchange_code
from auth_profiles import DEFAULT_GLOBS, discover_paths, write_tokens, write_token_cache

url, verifier, state = build_authorize_url()
print("="*78, flush=True)
print("OPEN THIS URL IN YOUR MAC BROWSER:", flush=True)
print(url, flush=True)
print("="*78, flush=True)
print("Waiting for callback on 127.0.0.1:1455 ...", flush=True)

cb = {"code": None, "state": None, "done": False}
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if not self.path.startswith("/auth/callback"):
            self.send_response(404); self.end_headers(); return
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        cb["code"]  = (qs.get("code")  or [None])[0]
        cb["state"] = (qs.get("state") or [None])[0]
        cb["done"]  = True
        self.send_response(200)
        self.send_header("Content-Type","text/html; charset=utf-8"); self.end_headers()
        self.wfile.write(b"<h1>Authorized. You can close this tab.</h1>")

srv = HTTPServer(("127.0.0.1", 1455), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

deadline = time.time() + 600
while not cb["done"] and time.time() < deadline:
    time.sleep(0.25)
srv.shutdown()

if not cb["done"]:
    print("TIMEOUT: no callback within 600s", flush=True); sys.exit(13)
if cb["state"] != state:
    print(f"STATE MISMATCH: expected {state} got {cb["state"]}", flush=True); sys.exit(14)

print("got code, exchanging for tokens ...", flush=True)
tokens = exchange_code(cb["code"], verifier)
paths = discover_paths(DEFAULT_GLOBS)
n = write_tokens(paths, tokens)
write_token_cache(os.path.expanduser("~/.openclaw/oauth-token-cache.json"), tokens)
print(f"wrote {n} auth-profiles.json files + oauth-token-cache.json", flush=True)

with open(paths[0]) as f:
    prof = json.load(f)["profiles"]["openai-codex:codex-cli"]
exp_ms = int(prof["expires"])
print(f"new expires: {datetime.datetime.fromtimestamp(exp_ms/1000, datetime.UTC).isoformat()}", flush=True)
print("OK", flush=True)
