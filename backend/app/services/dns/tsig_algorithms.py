"""TSIG algorithms a DNS driver cannot use (#1858).

SpatiumDDI accepts hmac-sha1 / sha224 / sha256 / sha384 / sha512 on a group
TSIG key. Technitium cannot sign or verify with HMAC-SHA224: its
``DnsDatagram.GetTsigMacSize`` (TechnitiumLibrary,
``TechnitiumLibrary.Net/Dns/DnsDatagram.cs``) handles hmac-md5, -sha1,
-sha256, -sha256-128, -sha384, -sha384-192, -sha512 and -sha512-256 and
returns 0 for anything else, so a request signed with a sha224 key answers
TSIG error BADKEY even though ``TsigKey`` names the algorithm and the
settings API stores the key. The key looks installed, is pinned on every zone,
and no transfer signed with it ever succeeds.

Other drivers have no gap in our five: BIND9 (``named`` accepts all of them),
PowerDNS (``hmac-md5``, ``-sha1``, ``-sha224``, ``-sha256``, ``-sha384``,
``-sha512``). Windows DNS and the cloud drivers do not use group TSIG keys at
all (Windows authenticates dynamic updates with GSS-TSIG, the clouds with a
provider API), so there is nothing to refuse there.

The refusal is made where a Technitium driver and a key can first meet: key
create / update, a server joining a group (create, driver change, move,
Fleet role assignment, copilot) and a zone moving into a group.
"""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.dns import DNSTSIGKey

#: driver -> TSIG algorithms the driver cannot use. Absent = no gap.
UNSUPPORTED_TSIG_ALGORITHMS: dict[str, frozenset[str]] = {
    "technitium": frozenset({"hmac-sha224"}),
    "technitium_api": frozenset({"hmac-sha224"}),
}

_VENDOR = {"technitium": "Technitium", "technitium_api": "Technitium"}


def unsupported_drivers(algorithm: str | None, drivers: list[str] | set[str]) -> list[str]:
    """The drivers among ``drivers`` that cannot use ``algorithm``."""
    algo = (algorithm or "hmac-sha256").strip().lower()
    return sorted(d for d in set(drivers) if algo in UNSUPPORTED_TSIG_ALGORITHMS.get(d, ()))


def key_refusal(
    algorithm: str | None, drivers: list[str] | set[str], *, key: str = ""
) -> str | None:
    """A 422 message when a ``driver`` in the group cannot use the algorithm."""
    bad = unsupported_drivers(algorithm, drivers)
    if not bad:
        return None
    algo = (algorithm or "hmac-sha256").strip().lower()
    vendor = " / ".join(sorted({_VENDOR.get(d, d) for d in bad}))
    what = f"TSIG key {key!r} uses" if key else "TSIG algorithm"
    return (
        f"{what} {algo}, which {vendor} does not support (driver {', '.join(bad)}): it has no "
        f"{algo.upper()}, so every transfer signed with the key fails with BADKEY. Use one of "
        "hmac-sha1, hmac-sha256, hmac-sha384 or hmac-sha512."
    )


async def group_key_refusal(
    db: AsyncSession, group_id: uuid.UUID, drivers: list[str] | set[str]
) -> str | None:
    """A 422 message when a key already in ``group_id`` is unusable by ``drivers``."""
    rows = (
        await db.execute(
            select(DNSTSIGKey.name, DNSTSIGKey.algorithm)
            .where(DNSTSIGKey.group_id == group_id)
            .order_by(DNSTSIGKey.name)
        )
    ).all()
    for name, algorithm in rows:
        msg = key_refusal(algorithm, drivers, key=name)
        if msg:
            return msg + " Change or delete the key first."
    return None
