"""Pointers to the Web UI Certificate name where it really is (#3045).

Since #404 it is an entry in Appliance -> Fleet's side list, not an Appliance
tab. Stored certificate notes and the expiry alert text are written by this
code, so a stale pointer here reaches the operator verbatim.
"""

from __future__ import annotations

from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
REAL = "Appliance → Fleet → Web UI Certificate"


def test_no_backend_text_points_at_a_web_ui_certificate_tab() -> None:
    offenders = []
    for path in APP.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for bad in ("Appliance → Web UI Certificate", "Web UI Certificate tab"):
            if bad in text:
                offenders.append(f"{path.relative_to(APP)}: {bad!r}")
    assert not offenders, "name the real path:\n  " + "\n  ".join(offenders)


def test_the_real_path_is_what_the_notes_and_alert_say() -> None:
    for rel in ("services/appliance/bootstrap.py", "services/alerts.py"):
        assert REAL in (APP / rel).read_text(encoding="utf-8")
