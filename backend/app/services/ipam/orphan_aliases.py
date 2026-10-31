"""Which trashed DNS records are an orphan's withdrawn aliases (#2604, #3189).

Mark as Orphan withdraws an address's aliases (soft-deletes them) so the
address's own Restore can bring them back, and an orphan has no time limit.
While the address is still an orphan those rows belong to it: the Trash does
not offer them alone, the retention sweep leaves them, and deleting the
address for good deletes them with it.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, exists

from app.models.dns import DNSRecord
from app.models.ipam import IPAddress


def withdrawn_for_an_orphan() -> Any:
    """SQL predicate: the record is an alias of an address that is still an orphan."""
    return and_(
        DNSRecord.ip_alias.is_(True),
        exists().where(
            IPAddress.id == DNSRecord.ip_address_id,
            IPAddress.status == "orphan",
        ),
    )


def refusal_reason() -> str:
    return (
        "it is an alias withdrawn with an orphaned IP address — restore the address "
        "(or delete it permanently) and the alias follows it"
    )
