"""Per-row narrowing for copilot tools that list rows (GHSA-4wrc-78rq-vgcg).

The coarse gate is each tool's ``permission`` declaration, enforced by
``ToolRegistry.call``. A resource-scoped API token (#374) clears that gate
when it is bound to *one* instance of the type, so a tool that lists rows
must also narrow them to the bound instances — exactly what the REST list
routes do (``_zone_token_id_filter`` in the DNS router,
``_token_subnet_scope_uuids`` in the IPAM router). Both are thin wrappers
over :func:`app.core.permissions.token_scoped_resource_ids`, and so are
these, so the copilot answers with the same semantics:

* ``None`` — no narrowing (session, plain token, or a wildcard grant).
* a (possibly empty) set — only these instances are visible.
"""

from __future__ import annotations

import uuid

from app.models.auth import User

# ``app.core.permissions`` is imported inside each helper: it pulls in the
# auth dependencies, which must stay off the tool-registry import path (the
# same reason the IPAM tools import it lazily).


def _uuid_set(ids: set[str] | None) -> set[uuid.UUID] | None:
    if ids is None:
        return None
    out: set[uuid.UUID] = set()
    for rid in ids:
        try:
            out.add(uuid.UUID(str(rid)))
        except (ValueError, TypeError):
            continue
    return out


def token_zone_ids(user: User) -> set[uuid.UUID] | None:
    """DNS zones a zone-bound token may see (REST ``_zone_token_id_filter``)."""
    from app.core.permissions import token_scoped_resource_ids  # noqa: PLC0415

    return _uuid_set(token_scoped_resource_ids(user, "dns_zone"))


def token_subnet_ids(user: User) -> set[uuid.UUID] | None:
    """Subnets a subnet-bound token may see (REST ``_token_subnet_scope_uuids``)."""
    from app.core.permissions import token_scoped_resource_ids  # noqa: PLC0415

    return _uuid_set(token_scoped_resource_ids(user, "subnet"))


def token_allows_zone(user: User, zone_id: object) -> bool:
    from app.core.permissions import token_scope_allows  # noqa: PLC0415

    return token_scope_allows(user, "dns_zone", str(zone_id) if zone_id is not None else None)


def token_allows_subnet(user: User, subnet_id: object) -> bool:
    from app.core.permissions import token_scope_allows  # noqa: PLC0415

    return token_scope_allows(user, "subnet", str(subnet_id) if subnet_id is not None else None)
