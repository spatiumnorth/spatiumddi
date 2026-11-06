"""Hold an imported SOA RNAME to the rule Add Zone applies (#3673, #2916).

Add Zone and Edit Zone refuse an Admin Email BIND cannot serve or a zone
file cannot carry (``admin_email_error``). An importer reading a source
server's RNAME used to store it as written, so the agent later dropped it
and served ``admin.{zone}`` with nothing said. Now a value that fails the
rule is not stored (the zone's Admin Email stays empty, which the renderer
serves as ``admin.{zone}``), and the preview says so, per zone.
"""

from __future__ import annotations

from app.core.dns_names import admin_email_error
from app.services.dns_import.canonical import ImportPreview


def importable_admin_email(raw: str | None) -> tuple[str, str | None]:
    """``(value to store, reason it was not kept or None)`` for a source RNAME."""
    value = (raw or "").rstrip(".")
    if not value:
        return "", None
    err = admin_email_error(value)
    if err is None:
        return value, None
    return "", err


def admin_email_warning(zone_name: str, raw: str, reason: str) -> str:
    return (
        f"Zone {zone_name!r}: SOA mailbox (RNAME) {raw!r} was not imported: Admin Email "
        f"{reason}. The zone's Admin Email is left empty and the zone is served "
        f"with admin.{zone_name.rstrip('.')} instead."
    )


def is_admin_email_warning(warning: str, zone_name: str) -> bool:
    return warning.startswith(f"Zone {zone_name!r}: SOA mailbox (RNAME) ")


def annotate_admin_email(preview: ImportPreview) -> None:
    """Add one preview warning per zone whose RNAME will not be stored."""
    for z in preview.zones:
        if z.soa is None:
            continue
        _, reason = importable_admin_email(z.soa.admin_email)
        if reason is not None:
            preview.warnings.append(admin_email_warning(z.name, z.soa.admin_email, reason))
