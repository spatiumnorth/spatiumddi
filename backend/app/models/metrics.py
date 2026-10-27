"""Per-server metric sample models (agent-reported deltas).

Each row is one fixed-width time bucket of counter deltas, reported
by the agent after it polls its local daemon (BIND9 statistics-
channels for DNS, Kea ``statistic-get-all`` for DHCP). Storing deltas
rather than raw counters means retention pruning doesn't require a
running-sum recompute, and counter resets on daemon restart don't
back-propagate into the time series. The FK cascade drops a server's
samples when the server row is removed.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, PrimaryKeyConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class DNSMetricSample(Base):
    __tablename__ = "dns_metric_sample"
    __table_args__ = (PrimaryKeyConstraint("server_id", "bucket_at", name="pk_dns_metric_sample"),)

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dns_server.id", ondelete="CASCADE"),
        nullable=False,
    )
    bucket_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    queries_total: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    noerror: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    nxdomain: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    servfail: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    recursion: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    # Response Rate Limiting drops (#146 Phase 3). rate_dropped = responses
    # dropped, rate_slipped = responses truncated (TC=1). 0 unless RRL is on.
    rate_dropped: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    rate_slipped: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class DHCPMetricSample(Base):
    __tablename__ = "dhcp_metric_sample"
    __table_args__ = (PrimaryKeyConstraint("server_id", "bucket_at", name="pk_dhcp_metric_sample"),)

    server_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("dhcp_server.id", ondelete="CASCADE"),
        nullable=False,
    )
    bucket_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    discover: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    offer: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    request: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    ack: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    nak: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    decline: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    release: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    inform: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    # #980 — the two loss counters, and the reason they are NULLABLE where
    # every column above is NOT NULL DEFAULT 0.
    #
    # ``receive_drop`` is Kea's own ``pkt4/6-receive-drop``: packets it read
    # and then discarded. ``socket_drop`` is the kernel's per-socket
    # ``sk_drops`` on UDP/67 + UDP/547 — packets Kea never saw because its
    # receive buffer was full. They are not interchangeable, and the second
    # is the one that moves when a node is short of CPU: measured against
    # kea-dhcp4 3.0.3, a run that lost 9,700 datagrams to buffer overflow
    # left ``pkt4-receive-drop`` at 0 for its whole duration.
    #
    # NULL means UNMEASURED, and only NULL can mean that. An agent older
    # than #980 reports neither field, and 0 from such an agent would read
    # as "this server has dropped nothing" — the precise false reassurance
    # the issue was filed about. Every reader must render NULL as unknown
    # rather than folding it to zero.
    receive_drop: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    socket_drop: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # #2889 — DHCPv4 requests Kea read and then evicted from its
    # multi-threading packet queue when a burst outran its worker. Kea keeps
    # no statistic for it, and neither counter above moves: ``socket_drop``
    # is before Kea reads, ``receive_drop`` is the worker, after the queue.
    # The agent derives it — kernel-counted arrivals at Kea's intake, less
    # the DHCPv4 share of ``socket_drop``, less ``pkt4-received``. Loss
    # exactly like ``socket_drop``, and NULL means unmeasured exactly like
    # it: an agent without ``CAP_NET_RAW``, a v6-only server, a bucket that
    # straddled a Kea restart, or an agent older than this change.
    queue_evicted: Mapped[int | None] = mapped_column(BigInteger, nullable=True)


__all__ = ["DNSMetricSample", "DHCPMetricSample"]
