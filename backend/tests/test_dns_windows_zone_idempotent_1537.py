"""#1537 — Windows DNS zone create / delete script is idempotent but strict.

The PowerShell is the contract (no WinRM in unit tests): an absent zone is
detected from Win32 9601 specifically, so access-denied and other probe
failures rethrow instead of reading as "already gone".
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.drivers.dns.windows import _ps_apply_zone

_ZONE = SimpleNamespace(name="Example.Com.")


def test_probe_is_strict_and_only_9601_means_absent() -> None:
    for op in ("create", "delete"):
        script = _ps_apply_zone(_ZONE, op)
        assert "Get-DnsServerZone -Name 'Example.Com' -ErrorAction Stop" in script
        assert "SilentlyContinue" not in script
        assert "-notmatch 'WIN32 9601'" in script
        # Anything that is not 9601 is rethrown.
        assert "throw" in script


def test_create_treats_existing_zone_as_done() -> None:
    script = _ps_apply_zone(_ZONE, "create")
    assert "already exists on server" in script
    # A lost create race (DNS_ERROR_ZONE_ALREADY_EXISTS) converges too.
    assert "WIN32 9609" in script
    assert "Add-DnsServerPrimaryZone" in script


def test_delete_treats_missing_zone_as_done() -> None:
    script = _ps_apply_zone(_ZONE, "delete")
    assert "was not present on server" in script
    assert "Remove-DnsServerZone -Name 'Example.Com' -Force -ErrorAction Stop" in script
    # Zone vanishing between probe and remove is also done.
    assert "WIN32 9601" in script


def test_script_fits_the_winrm_command_budget_for_a_maximal_zone_name() -> None:
    """The strict probe repeats the zone name; a 253-char name must still
    encode under ``MAX_ENCODED_COMMAND`` or the push dies before sending."""
    from app.drivers._winrm import MAX_ENCODED_COMMAND, encoded_command_len

    longest = ".".join(["a" * 63] * 3 + ["b" * 61]) + "."
    for op in ("create", "delete"):
        script = _ps_apply_zone(SimpleNamespace(name=longest), op)
        assert encoded_command_len(script) < MAX_ENCODED_COMMAND


def test_noop_markers_match_what_the_script_writes() -> None:
    """``apply_zone_change`` reads "no change" off these strings, so a
    reworded ``Write-Output`` would silently turn every converged answer
    back into a change (and its compensation back into a teardown)."""
    from app.drivers.dns.windows import _ZONE_NOOP_MARKERS

    create = _ps_apply_zone(_ZONE, "create")
    delete = _ps_apply_zone(_ZONE, "delete")
    assert f"zone 'Example.Com' {_ZONE_NOOP_MARKERS[0]}" in create
    assert f"zone 'Example.Com' {_ZONE_NOOP_MARKERS[1]}" in delete
    # The change paths must not carry a marker.
    assert not any(m in "zone 'Example.Com' created" for m in _ZONE_NOOP_MARKERS)
    assert not any(m in "zone 'Example.Com' deleted" for m in _ZONE_NOOP_MARKERS)


async def test_apply_zone_change_reports_no_change_from_the_script_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.drivers.dns import windows

    outputs = iter(
        [
            "zone 'example.com' created\r\n",
            "zone 'example.com' already exists on server\r\n",
            "zone 'example.com' deleted\r\n",
            "zone 'example.com' was not present on server\r\n",
        ]
    )
    monkeypatch.setattr(windows, "_load_credentials", lambda server: {})
    monkeypatch.setattr(windows, "_run_ps", lambda server, creds, script: next(outputs))
    driver = windows.WindowsDNSDriver()
    server = SimpleNamespace(id="s", host="dc1", credentials_encrypted=b"x")
    zone = SimpleNamespace(name="example.com.")
    assert await driver.apply_zone_change(server, zone, "create") is True
    assert await driver.apply_zone_change(server, zone, "create") is False
    assert await driver.apply_zone_change(server, zone, "delete") is True
    assert await driver.apply_zone_change(server, zone, "delete") is False
