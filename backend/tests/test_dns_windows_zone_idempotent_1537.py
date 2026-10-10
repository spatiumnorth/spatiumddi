"""#1537 — Windows DNS zone create / delete script is idempotent but strict.

The PowerShell is the contract (no WinRM in unit tests): an absent zone is
detected from Win32 9601 specifically, so access-denied and other probe
failures rethrow instead of reading as "already gone".
"""

from __future__ import annotations

from types import SimpleNamespace

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
