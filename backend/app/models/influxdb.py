"""InfluxDB push-export target (issue #889).

One row per InfluxDB destination. SpatiumDDI is the *writer* — a Celery
beat task formats line protocol from the existing metric tables and
POSTs it. Nothing reads back.

``version`` picks the wire dialect:

* ``v1`` — legacy ``/write?db=…`` endpoint, HTTP basic auth.
* ``v2`` — ``/api/v2/write?org=…&bucket=…``, ``Authorization: Token``.
* ``v3`` — InfluxDB 3 (Core / Enterprise / Cloud Dedicated / Cloud
  Serverless). Reuses the **v2 endpoint and code path**: a v3 database
  is a v2 bucket, ``org`` is accepted-and-ignored, and auth is
  ``Authorization: Bearer``. No separate client — see
  ``app/services/influxdb/client.py``.

Secrets follow the ``audit_forward`` convention: Fernet-encrypted
``LargeBinary`` columns, never returned by the API (the response shape
carries ``password_set`` / ``token_set`` booleans instead).

The two ``last_*_bucket_at`` columns are per-source high-water marks so
a worker restart doesn't re-push the whole retention window. They are
an optimisation, not a correctness guarantee — line protocol is
idempotent for identical measurement + tags + timestamp, so the pusher
deliberately re-sends a small overlap window to catch late-arriving
agent samples (see ``app/services/influxdb/push.py``).
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, LargeBinary, String, Text
from sqlalchemy import text as sa_text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

# Wire dialects. ``v3`` is not a third client — it reuses the v2 write
# endpoint with bearer auth and bucket=database naming.
INFLUXDB_VERSIONS = ("v1", "v2", "v3")

DEFAULT_MEASUREMENT_PREFIX = "spatiumddi_"
# The beat tick is 30 s (see ``celery_app.beat_schedule``), so a shorter
# interval than that can't be honoured. The real data floor is the 60 s
# agent metric bucket regardless.
MIN_PUSH_INTERVAL_SECONDS = 30
DEFAULT_PUSH_INTERVAL_SECONDS = 60


class InfluxDBTarget(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "influxdb_target"

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)

    # version: v1 | v2 | v3
    version: Mapped[str] = mapped_column(String(4), nullable=False, default="v2")
    # Base URL only — the writer appends the version-appropriate path.
    url: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    verify_tls: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)

    # ── v1 fields ──────────────────────────────────────────────────
    database: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    username: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # Fernet-encrypted at rest. On InfluxDB 3's v1 endpoint the API token
    # rides here and the username is ignored — that is the documented
    # compatibility shim, not a misuse of the column.
    password_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    # ── v2 / v3 fields ─────────────────────────────────────────────
    org: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    # v2 bucket; on v3 this is the database name.
    bucket: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    token_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)

    measurement_prefix: Mapped[str] = mapped_column(
        String(64), nullable=False, default=DEFAULT_MEASUREMENT_PREFIX
    )
    push_interval_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=DEFAULT_PUSH_INTERVAL_SECONDS
    )

    # ── what this target carries ───────────────────────────────────
    # Per-target so an operator can point a small Grafana Cloud bucket at
    # the DNS series only without paying for the IPAM gauges.
    push_dns_metrics: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    push_dhcp_metrics: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    push_subnet_utilization: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )
    push_dhcp_scope_leases: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=sa_text("true")
    )

    # ── push state ─────────────────────────────────────────────────
    last_dns_bucket_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_dhcp_bucket_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_push_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # The last push the destination ACCEPTED (#1990). ``last_push_at`` is the
    # last attempt and moves on failure; this one does not. NULL = never.
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Point count of that successful push (only written on success).
    last_push_points: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # NULL means "no failure recorded"; it is cleared on the next success
    # so the UI never shows a stale error next to a healthy target.
    last_push_error: Mapped[str | None] = mapped_column(Text, nullable=True)


__all__ = [
    "DEFAULT_MEASUREMENT_PREFIX",
    "DEFAULT_PUSH_INTERVAL_SECONDS",
    "INFLUXDB_VERSIONS",
    "MIN_PUSH_INTERVAL_SECONDS",
    "InfluxDBTarget",
]
