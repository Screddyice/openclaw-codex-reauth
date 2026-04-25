"""Verify that when the residential proxy is NOT reachable, codex_reauth_server
logs a WARNING (not INFO), so proxy outages surface in the reauth log."""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def test_missing_proxy_logs_warning(caplog):
    """When 127.0.0.1:1080 refuses the connection, we should log a WARNING
    with text indicating the proxy is expected but unreachable."""
    import codex_reauth_server as mod

    cfg = {
        "codex": {
            "chrome_path": "/bin/true",
            "chrome_profile_dir": "/tmp/test-chrome-profile",
            "cdp_port": 19333,
            "callback_host": "127.0.0.1",
            "callback_port": 11455,
            "callback_path": "/auth/callback",
            "use_xvfb": False,
            "xvfb_screen": "1280x900x24",
            "socks_proxy_port": 65530,  # unused port, connect will fail
            "socks_proxy_auto": True,
        },
    }
    log = logging.getLogger("test-codex-reauth")
    caplog.set_level(logging.DEBUG, logger="test-codex-reauth")

    # launch_chrome calls subprocess.Popen; patch it so we don't actually spawn
    with patch.object(mod.subprocess, "Popen") as popen, \
         patch.object(mod.subprocess, "run"), \
         patch.object(mod.time, "sleep"):
        popen.return_value.poll.return_value = None
        try:
            mod.launch_chrome(cfg, log)
        except Exception:
            pass  # we don't care if Chrome "launched" fake — only about the log

    msgs = [r for r in caplog.records if "no SOCKS proxy" in r.getMessage()
                                       or "residential proxy" in r.getMessage()
                                       or "proxy not reachable" in r.getMessage()]
    assert msgs, f"expected a proxy-related log record, got: {[r.getMessage() for r in caplog.records]}"
    assert any(r.levelno >= logging.WARNING for r in msgs), (
        f"expected WARNING-level log for missing proxy, "
        f"got levels: {[(r.levelname, r.getMessage()) for r in msgs]}"
    )
