"""Nudge DNS agents when the cert their DoT/DoH listener serves changes (#50).

A DoT / DoH listener serves an ``ApplianceCertificate`` row, which the
config bundle carries to the agent as PEM (see
``app.services.dns.agent_config``). Both renewal paths rewrite ``cert_pem``
**in place** on the existing row — the ACME orchestrator on auto-renewal,
and the operator pasting a re-signed cert back into a CSR-pending row — so
the pointer stays valid and only the material changes.

That material is inside the hashed bundle body, so the etag shifts and
agents converge on their own. This module only makes it *prompt*: without a
wake the change lands on the next safety tick instead of within a second.
Per cross-cutting pattern #2 the wake stays advisory — never the sole
delivery path — and ``publish_wake`` swallows its own errors, so a Redis
outage can never break the caller.
"""

from __future__ import annotations

import uuid

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_wake import appliance_channel, dns_group_channel, publish_wake
from app.models.dns import DNSServerOptions


async def _group_ids_serving_cert(db: AsyncSession, cert_id: uuid.UUID) -> list[uuid.UUID]:
    """DNS groups with a LIVE listener on ``cert_id``.

    Groups that reference the cert but have both listeners off are skipped —
    their bundle carries no cert material, so there is nothing to converge.
    """
    return list(
        (
            await db.execute(
                select(DNSServerOptions.group_id).where(
                    DNSServerOptions.tls_certificate_id == cert_id,
                    or_(
                        DNSServerOptions.dot_enabled.is_(True),
                        DNSServerOptions.doh_enabled.is_(True),
                        # #3061 — DoQ serves the same cert (Technitium, #741)
                        DNSServerOptions.doq_enabled.is_(True),
                    ),
                )
            )
        )
        .scalars()
        .all()
    )


async def wake_dns_groups_serving_cert(db: AsyncSession, cert_id: uuid.UUID) -> None:
    """Publish one wake covering every DNS group with a live listener on this cert.

    Call AFTER the commit that changed the certificate.
    """
    group_ids = await _group_ids_serving_cert(db, cert_id)
    if group_ids:
        # One connect/publish/close round-trip for the whole set —
        # publish_wake takes varargs and dedups internally.
        await publish_wake(*[dns_group_channel(g) for g in group_ids])


async def wake_for_cert_deletion(db: AsyncSession, cert_id: uuid.UUID) -> None:
    """Wake both the DNS agents AND the appliances serving this cert.

    Deleting a certificate is different from rotating one: the FK is
    ``ON DELETE SET NULL``, so the listener loses its cert entirely and the
    agent degrades to Do53. That ALSO empties ``dns_encrypted_tcp_ports`` on
    the supervisor's role assignment, so the firewall should close the port
    rather than keep advertising a service that no longer answers.

    Must be called BEFORE the delete commits — afterwards the FK is already
    NULL and the owning groups can no longer be found.
    """
    group_ids = await _group_ids_serving_cert(db, cert_id)
    if not group_ids:
        return

    from app.models.appliance import Appliance  # noqa: PLC0415 — avoids an import cycle

    appliance_ids = (
        (
            await db.execute(
                select(Appliance.id).where(Appliance.assigned_dns_group_id.in_(group_ids))
            )
        )
        .scalars()
        .all()
    )
    await publish_wake(
        *[dns_group_channel(g) for g in group_ids],
        *[appliance_channel(a) for a in appliance_ids],
    )
