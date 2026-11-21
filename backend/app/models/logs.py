"""Per-server query/activity log entries shipped from agents.

Each row is one parsed log line. Agents tail their daemon's log file
(BIND9 query log, Kea ``kea-dhcp4.log``), batch new lines, and POST
to the control plane every few seconds. The control plane parses
lines into structured columns and stores them here for the Logs UI.

This is **operator triage**, not analytics. We keep a short rolling
window (default 24 h) so the UI stays responsive and the table size
is bounded; longer retention belongs in Loki / a SIEM.

Deleting a server keeps its entries: the FK is ``ON DELETE SET NULL``
(#4173) and the retention prune ages them out as usual.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import INET, MACADDR, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class DNSQueryLogEntry(Base):
    """One parsed BIND9 query log line.

    Example raw line:

        ``client @0x... 192.0.2.5#54321 (example.com): query: example.com IN A +E(0)K (10.0.0.1)``

    We extract the client IP / port, qname, qclass, qtype, and the
    flags string into structured columns; the full original line is
    kept in ``raw`` for cases the parser doesn't fully understand.

    ``rcode`` / ``answer_count`` come from a *second* line — BIND's
    ``responses`` category — stamped onto this row at ingest when the
    operator has opted into response logging (issue #914).
    """

    __tablename__ = "dns_query_log_entry"
    __table_args__ = (
        Index("ix_dns_query_log_server_ts", "server_id", "ts"),
        Index("ix_dns_query_log_ts", "ts"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # SET NULL, not CASCADE (#4173): the row records what a client asked, not
    # anything about the server, so retiring a server must not erase it (and
    # the cascade made the delete minutes long on a big table). ``server_name``
    # keeps the row attributable once the id is gone; NULL ``server_id`` means
    # "the server was deleted", never "unknown server".
    server_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server.id", ondelete="SET NULL"),
        nullable=True,
    )
    server_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    client_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    client_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    qname: Mapped[str | None] = mapped_column(String(512), nullable=True)
    qclass: Mapped[str | None] = mapped_column(String(8), nullable=True)
    qtype: Mapped[str | None] = mapped_column(String(16), nullable=True)
    flags: Mapped[str | None] = mapped_column(String(64), nullable=True)
    view: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # ── What the client actually got back (issue #914) ────────────────
    #
    # BIND's ``queries`` category is request-side by design: it logs the
    # question on arrival and says nothing about the answer. So until
    # #914 the log could prove a query reached the server and could not
    # distinguish the five outcomes an operator is actually triaging —
    # NOERROR, NOERROR-with-no-answers (NODATA), NXDOMAIN, REFUSED,
    # SERVFAIL — which is the difference between "it is not DNS" and
    # "an ACL is rejecting this client".
    #
    # These are filled from BIND's separate ``responses`` category
    # (``responselog yes;``, BIND 9.20+), correlated back onto the query
    # row at ingest. They are NULL whenever that is off or the driver
    # has no equivalent, and **NULL means UNKNOWN, never NOERROR** —
    # rendering an unrecorded outcome as "fine" is the one failure mode
    # this column exists to prevent.
    rcode: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: RRs in the answer section. NOERROR with ``answer_count == 0`` is a
    #: NODATA response — the name exists but carries no record of that
    #: type — which is a different fault from NXDOMAIN and reads
    #: identically without this.
    answer_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # ── How the server produced the answer (issue #4251) ──────────────
    #
    # ``authoritative`` / ``cache`` / ``forwarded`` / ``recursion`` —
    # filled only when the daemon's own log says so (PowerDNS
    # Authoritative's per-query verdict today). BIND9's ``queries`` /
    # ``responses`` categories carry nothing of the kind, so BIND rows
    # stay NULL until a dnstap pipeline exists (#3580). **NULL means
    # UNKNOWN, never "authoritative"**: nothing is inferred from zone
    # membership or the rcode.
    answer_source: Mapped[str | None] = mapped_column(String(16), nullable=True)
    #: Upstream resolver address for ``forwarded`` / ``recursion``, when the
    #: reporting flavor names one. No flavor populates it yet.
    answer_upstream: Mapped[str | None] = mapped_column(String(64), nullable=True)


class DHCPLogEntry(Base):
    """One parsed Kea ``kea-dhcp4.log`` line.

    Kea's stock log format:

        ``2026-04-25 16:30:01.123 INFO  [kea-dhcp4.leases/12345.139...] DHCP4_LEASE_ALLOC [hwtype=1 aa:bb:cc:dd:ee:ff], cid=[no info], tid=0x12345678: lease 192.0.2.10 has been allocated for 3600 seconds``

    Structured columns capture the most-filterable bits (severity,
    log code, MAC, IP, transaction ID); the full original line stays
    in ``raw``.
    """

    __tablename__ = "dhcp_log_entry"
    __table_args__ = (
        Index("ix_dhcp_log_server_ts", "server_id", "ts"),
        Index("ix_dhcp_log_ts", "ts"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    # SET NULL, not CASCADE (#4173): the row records what a client asked, not
    # anything about the server, so retiring a server must not erase it (and
    # the cascade made the delete minutes long on a big table). ``server_name``
    # keeps the row attributable once the id is gone; NULL ``server_id`` means
    # "the server was deleted", never "unknown server".
    server_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="SET NULL"),
        nullable=True,
    )
    server_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(MACADDR, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    transaction_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    raw: Mapped[str] = mapped_column(Text, nullable=False, default="")


__all__ = ["DNSQueryLogEntry", "DHCPLogEntry"]
