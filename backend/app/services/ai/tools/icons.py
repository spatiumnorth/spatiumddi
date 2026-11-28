"""Operator Copilot tools for built-in icons (#5022).

* ``find_icons``: read-only keyword search of the built-in icon catalog, so the
  copilot can pick a valid name before proposing one. Default-enabled: no
  secrets, no off-prem call.
* ``propose_set_icon``: stages setting or clearing the explicit icon on one IP
  address or DNS record. The ``set_ip_address_icon`` / ``set_dns_record_icon``
  operations (``services/ai/operations_icons.py``) run only when the operator
  applies the proposal, under the same write permission as the REST edit.
  Default-enabled: cosmetic, one row at a time.

The existing ``find_ip`` / ``find_ip_addresses`` / ``query_dns_records`` reads
carry ``icon`` and ``effective_icon`` too.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import User
from app.services import icons as icon_svc
from app.services.ai.operations_icons import SetDNSRecordIconArgs, SetIPAddressIconArgs
from app.services.ai.tools.base import register_tool
from app.services.ai.tools.proposals import _propose_via


class FindIconsArgs(BaseModel):
    q: str | None = Field(
        default=None,
        description="Keywords, matched against icon names, aliases and tags ('printer', 'wifi router').",
    )
    limit: int = Field(default=25, ge=1, le=100, description="Max icons to return (1-100).")


@register_tool(
    name="find_icons",
    permission="authenticated",
    description=(
        "Search the built-in icon catalog by keyword and return icon names like "
        "'mdi:printer' with a label. Use it before propose_set_icon, which only "
        "accepts names from this catalog. Read-only."
    ),
    args_model=FindIconsArgs,
    category="ipam",
)
async def find_icons(db: AsyncSession, user: User, args: FindIconsArgs) -> dict[str, Any]:
    hits = icon_svc.search_catalog(args.q)
    return {
        "icons": [{"name": e.name, "label": e.label} for e in hits[: args.limit]],
        "total": len(hits),
        "returned": min(len(hits), args.limit),
    }


class ProposeSetIconArgs(BaseModel):
    target: Literal["ip_address", "dns_record"] = Field(
        description="What to set the icon on: an IP address row or a DNS record."
    )
    id: str = Field(description="UUID of that IP address or DNS record.")
    icon: str | None = Field(
        default=None,
        description=(
            "Built-in icon name from find_icons, like 'mdi:printer'. Omit or null "
            "to clear the explicit choice and return to the automatic icon."
        ),
    )


@register_tool(
    name="propose_set_icon",
    # The operations declare the finer gates (write on the subnet / address set,
    # or on dns_record); this is the catalog-level floor for either target.
    permission=("write", ("subnet", "dns_record")),
    description=(
        "Prepare a proposal to set or clear the built-in icon on one IP address "
        "or DNS record. The operator must click Apply; the change is cosmetic "
        "(no DNS change). Get a valid name from find_icons first. Returns a "
        "kind='proposal' card; never call twice for the same change."
    ),
    args_model=ProposeSetIconArgs,
    writes=False,
    category="ipam",
    default_enabled=True,
)
async def propose_set_icon(
    db: AsyncSession, user: User, args: ProposeSetIconArgs
) -> dict[str, Any]:
    from pydantic import ValidationError  # noqa: PLC0415

    try:
        if args.target == "ip_address":
            return await _propose_via(
                db=db,
                user=user,
                operation_name="set_ip_address_icon",
                args=SetIPAddressIconArgs(address_id=args.id, icon=args.icon),
            )
        return await _propose_via(
            db=db,
            user=user,
            operation_name="set_dns_record_icon",
            args=SetDNSRecordIconArgs(record_id=args.id, icon=args.icon),
        )
    except ValidationError as exc:
        return {"error": "; ".join(e["msg"] for e in exc.errors())}
