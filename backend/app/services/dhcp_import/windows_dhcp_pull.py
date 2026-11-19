"""Windows DHCP live-pull importer (issue #129 Phase 2).

Reuses the existing :class:`WindowsDHCPReadOnlyDriver` Path A read
methods — the driver already speaks ``Get-DhcpServerv4Scope`` +
``Get-DhcpServerv4OptionValue`` + ``Get-DhcpServerv4ExclusionRange`` +
``Get-DhcpServerv4Reservation`` for the Logs surface and lease sync, so
the importer just iterates ``get_scopes()`` and reshapes the neutral
dicts into the canonical IR.

Windows DHCP is IPv4-only in our driver, so every imported scope is
``ipv4``. Option names already arrive in SpatiumDDI's canonical
vocabulary (the driver's ``_translate_options`` did the option-id →
name mapping), so there's no per-option translation here.
"""

from __future__ import annotations

from typing import Any

from app.drivers.dhcp.windows import WindowsDHCPReadOnlyDriver

from .canonical import (
    ImportedPool,
    ImportedReservation,
    ImportedScope,
    ImportPreview,
)
from .options import normalise_mac


class WindowsDHCPImportError(RuntimeError):
    """Raised when the live pull from the Windows DHCP server fails
    (WinRM transport, auth, or PowerShell error)."""


def _scope_from_dict(raw: dict[str, Any]) -> ImportedScope | None:
    cidr = raw.get("subnet_cidr")
    if not cidr:
        return None
    pools: list[ImportedPool] = []
    parse_warnings: list[str] = []
    for p in raw.get("pools") or []:
        if p.get("start_ip") and p.get("end_ip"):
            pools.append(
                ImportedPool(
                    start_ip=str(p["start_ip"]),
                    end_ip=str(p["end_ip"]),
                    pool_type=str(p.get("pool_type") or "dynamic"),
                )
            )
        else:
            # Name a dropped range rather than leave it silently missing (#3097).
            parse_warnings.append(
                f"Range {p.get('start_ip')!r}-{p.get('end_ip')!r} not imported: "
                "the server reported no start or end address."
            )
    reservations: list[ImportedReservation] = []
    for s in raw.get("statics") or []:
        mac = normalise_mac(s.get("mac_address"))
        if mac is None or not s.get("ip_address"):
            continue
        reservations.append(
            ImportedReservation(
                ip_address=str(s["ip_address"]),
                mac_address=mac,
                hostname=str(s.get("hostname") or ""),
                client_id=s.get("client_id"),
            )
        )
    return ImportedScope(
        subnet_cidr=str(cidr),
        address_family="ipv4",
        name=str(raw.get("name") or ""),
        description=str(raw.get("description") or ""),
        lease_time=int(raw.get("lease_time") or 86400),
        is_active=bool(raw.get("is_active", True)),
        options=dict(raw.get("options") or {}),
        pools=pools,
        reservations=reservations,
        parse_warnings=parse_warnings,
    )


async def parse_windows_dhcp_server(server: Any) -> ImportPreview:
    """Live-pull every IPv4 scope from a Windows DHCP server and reshape
    into the canonical import preview.

    ``server`` is a ``DHCPServer`` row with ``driver == "windows_dhcp"``
    and WinRM credentials configured. The pull blocks until every scope
    has been walked.
    """
    driver = WindowsDHCPReadOnlyDriver()
    try:
        raw_scopes = await driver.get_scopes(server)
    except Exception as exc:  # noqa: BLE001 — surface any WinRM/PS error
        raise WindowsDHCPImportError(f"Windows DHCP pull failed: {exc}") from exc

    scopes: list[ImportedScope] = []
    warnings: list[str] = []
    for raw in raw_scopes:
        scope = _scope_from_dict(raw)
        if scope is not None:
            scopes.append(scope)

    # Surface raw / unmapped option ids (the driver keeps them as
    # ``opt-<id>``) so the operator knows they came across opaque.
    raw_option_scopes = sum(1 for s in scopes if any(k.startswith("opt-") for k in s.options))
    if raw_option_scopes:
        warnings.append(
            f"{raw_option_scopes} scope(s) carry non-standard DHCP options preserved as "
            "raw 'opt-<id>' values — review them after import."
        )

    af_hist = {"ipv4": len(scopes)} if scopes else {}
    return ImportPreview(
        source="windows_dhcp",
        scopes=scopes,
        client_classes=[],  # Windows DHCP classes aren't pulled by Path A
        conflicts=[],
        warnings=warnings,
        unsupported=[],
        total_pools=sum(len(s.pools) for s in scopes),
        total_reservations=sum(len(s.reservations) for s in scopes),
        address_family_histogram=af_hist,
    )
