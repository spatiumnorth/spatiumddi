"""#4800 — the apt hook that stamps update attempts/successes, and the runner
marker that tells the supervisor the periodic update is off on purpose.

    python3 -m pytest appliance/tests/test_apt_update_stamps_4800.py -v
"""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HOOK = REPO / "appliance/mkosi.extra/etc/apt/apt.conf.d/30spatium-update-stamps"
RELOAD = REPO / "appliance/mkosi.extra/usr/local/bin/spatiumddi-apt-reload"


def test_hook_stamps_attempt_and_success_and_never_fails_apt() -> None:
    lines = [ln for ln in HOOK.read_text().splitlines() if ln and not ln.startswith("//")]
    assert len(lines) == 2
    assert lines[0].startswith("APT::Update::Pre-Invoke ")
    assert lines[1].startswith("APT::Update::Post-Invoke-Success ")
    for ln in lines:
        assert "|| true" in ln  # a hook error must not fail apt-get update
        assert "/var/lib/spatiumddi/release-state/apt-update-" in ln


def test_runner_marks_periodic_update_off() -> None:
    text = RELOAD.read_text()
    assert "apt-periodic-off" in text
    assert 'Update-Package-Lists "0"' in text
