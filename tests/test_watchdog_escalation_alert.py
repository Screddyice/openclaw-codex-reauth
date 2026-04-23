"""Verify the watchdog alerts Slack after 2 consecutive escalation failures
and resets the counter on success."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def _make_script(tmp_path: Path, name: str, exit_code: int) -> str:
    """Write a tiny Python script that exits with the given code. The watchdog
    invokes SERVER_REAUTH_SCRIPT via `sys.executable <path>`, so it must be
    a Python file, not a shell binary like /bin/false."""
    p = tmp_path / name
    p.write_text(f"import sys\nsys.exit({exit_code})\n")
    return str(p)


@pytest.fixture
def watchdog(tmp_path, monkeypatch):
    import codex_watchdog as mod
    state_file = tmp_path / "state.json"
    monkeypatch.setattr(mod, "ESCALATION_STATE_FILE", str(state_file))
    return mod, state_file


def test_single_failure_does_not_alert(watchdog, monkeypatch, tmp_path):
    mod, state_file = watchdog
    alerts = []
    monkeypatch.setattr(mod, "_alert_slack", lambda msg: alerts.append(msg))
    # Point SERVER_REAUTH_SCRIPT at a stub Python script that always fails.
    monkeypatch.setattr(mod, "SERVER_REAUTH_SCRIPT", _make_script(tmp_path, "fail.py", 1))

    rc = mod._escalate()
    assert rc != 0
    assert alerts == []  # first failure does not alert
    state = json.loads(state_file.read_text())
    assert state["consecutive_failures"] == 1


def test_two_consecutive_failures_alert(watchdog, monkeypatch, tmp_path):
    mod, state_file = watchdog
    alerts = []
    monkeypatch.setattr(mod, "_alert_slack", lambda msg: alerts.append(msg))
    monkeypatch.setattr(mod, "SERVER_REAUTH_SCRIPT", _make_script(tmp_path, "fail.py", 1))

    mod._escalate()  # failure 1
    mod._escalate()  # failure 2 → alert

    assert len(alerts) == 1
    assert "2" in alerts[0]
    state = json.loads(state_file.read_text())
    assert state["consecutive_failures"] == 2


def test_success_resets_counter(watchdog, monkeypatch, tmp_path):
    mod, state_file = watchdog
    alerts = []
    monkeypatch.setattr(mod, "_alert_slack", lambda msg: alerts.append(msg))

    # First, rack up a failure
    monkeypatch.setattr(mod, "SERVER_REAUTH_SCRIPT", _make_script(tmp_path, "fail.py", 1))
    mod._escalate()
    assert json.loads(state_file.read_text())["consecutive_failures"] == 1

    # Then a success resets
    monkeypatch.setattr(mod, "SERVER_REAUTH_SCRIPT", _make_script(tmp_path, "ok.py", 0))
    rc = mod._escalate()
    assert rc == 0
    assert json.loads(state_file.read_text())["consecutive_failures"] == 0
