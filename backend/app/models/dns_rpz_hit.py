"""RPZ policy-hit attribution (issue #699).

SpatiumDDI serves curated blocklists as RPZ zones and, until this
existed, threw every hit away. That made the most operationally useful
question the blocklists can answer — *which machine keeps reaching for
blocked domains* — unanswerable. A blocked lookup is not a problem; a
host generating thousands of them is an infected host announcing
itself.

One row per policy rewrite, written by the query-log ingest when the
line came from named's ``rpz`` logging category. Deliberately a
separate table from ``dns_query_log_entry`` rather than a flag on it:

* RPZ hits are worth keeping far longer than raw queries. The query log
  is 24 h operator triage; "this host has hit the malware feed every
  day this week" needs to outlive that, exactly like the threat rollup
  does.
* The columns genuinely differ — a hit carries a policy action, a
  trigger type and the feed that matched, none of which a query has.
* Mixing them would make the query log's own retention sweep either
  drop the hits early or keep the queries too long.

``rpz_zone`` records which RPZ zone matched. Note the resolution limit:
``dns/agent_config.py`` merges every enabled blocklist into ONE rendered
zone per view, so for SpatiumDDI-managed lists this distinguishes
*views*, not individual feeds — "which of my 14 lists fired" needs
either per-list zones or a qname join back to ``DNSBlockListEntry``, and
is follow-up work on #699. It does separate our zone from any
hand-rolled ``response-policy`` zone an operator runs alongside.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import INET, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class DNSRPZHit(Base):
    """One RPZ policy rewrite — a blocked (or passed-through) lookup."""

    __tablename__ = "dns_rpz_hit"
    __table_args__ = (
        # "Who has been hitting the blocklist recently" — the query
        # behind the attribution report and the Threat tab's RPZ panel.
        Index("ix_dns_rpz_hit_client_ts", "client_ip", "ts"),
        # Retention sweep + the "what got blocked lately" ordering.
        Index("ix_dns_rpz_hit_ts", "ts"),
        # "Which feed is doing the work" rollup.
        Index("ix_dns_rpz_hit_zone_ts", "rpz_zone", "ts"),
        # Time-partitioned like the other agent-shipped logs (#2185): retention
        # is a partition drop, and ``ts`` is part of the primary key.
        {"postgresql_partition_by": "RANGE (ts)"},
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dns_server.id", ondelete="CASCADE"), nullable=False
    )
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), primary_key=True)

    # Nullable because a hit whose log head didn't parse is still worth
    # counting — it proves the blocklist fired — even though it cannot
    # be pinned to a host. Every attribution surface filters these out;
    # the totals keep them.
    client_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    qname: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # QNAME / CLIENT-IP / IP / NSDNAME / NSIP — which part of the
    # transaction matched the policy.
    trigger: Mapped[str] = mapped_column(String(16), nullable=False)
    # NXDOMAIN / NODATA / PASSTHRU / DROP / TCP-ONLY / CNAME /
    # Local-Data. PASSTHRU is an explicit allow, so it is NOT a block —
    # the surfaces separate them rather than counting every row as a
    # block.
    policy: Mapped[str] = mapped_column(String(16), nullable=False)
    # The blocklist zone that matched, recovered from named's ``via``
    # clause. Nullable: DROP logs no ``via``.
    rpz_zone: Mapped[str | None] = mapped_column(String(255), nullable=True)

    raw: Mapped[str] = mapped_column(Text, nullable=False, default="")
