"""Pick a free ``Router.name`` for a router an automated path creates (#2140).

``router.name`` is UNIQUE (``uq_router_name``) and operators name routers
freely — usually after the gateway, which is exactly the name an
integration or importer would choose for its own router too. Creating
under a taken name raises on flush, which poisons the session and
rolls back the whole pass; on a beat-driven reconcile that means the
target fails identically on every sweep and nothing is ever mirrored.

Adopting the existing row is not an option either: an integration
reconciler renames and deletes the VLANs on the Router it owns, so
taking over an operator's Router would destroy the operator's VLANs.
So the automated path keeps its own row and takes the first free name
in ``"<base>"``, ``"<base> (<tag>)"``, ``"<base> (<tag> 2)"``, … — checked
by query, never by catching the flush error.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vlans import Router

# ``router.name`` is String(255).
_NAME_MAX = 255
# A pathological estate could hold every suffix; stop somewhere finite.
_MAX_SUFFIX = 200


def _fit(base: str, suffix: str) -> str:
    return base[: _NAME_MAX - len(suffix)] + suffix


async def pick_unique_router_name(db: AsyncSession, base: str, *, tag: str) -> str:
    """The first of ``base``, ``base (tag)``, ``base (tag 2)``, … no Router
    holds. ``tag`` names the creator (``"UniFi"``, ``"NetBox"``) so an
    operator reading the router list can tell whose row the suffixed one is.
    """
    base = base.strip() or tag
    candidates = [_fit(base, ""), _fit(base, f" ({tag})")]
    candidates += [_fit(base, f" ({tag} {n})") for n in range(2, _MAX_SUFFIX)]
    taken = set(
        (await db.execute(select(Router.name).where(Router.name.in_(candidates)))).scalars().all()
    )
    for name in candidates:
        if name not in taken:
            return name
    raise ValueError(f"no free router name derived from {base!r}")


__all__ = ["pick_unique_router_name"]
