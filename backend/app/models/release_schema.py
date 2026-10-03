"""Which database schema each release ran at (#1227).

PostgreSQL lives on ``/var``, which an A/B slot swap does not touch. So a
rollback, an auto-revert or a per-box downgrade puts an older release's code
on a database a newer release has already migrated forward. The older
release's migrate step then fails with Alembic's ``Can't locate revision``,
its api / worker / beat never start, and nothing retries.

Deciding whether that will happen needs one fact the database does not
otherwise keep: the Alembic head the target release was built with. This
table records it. Every release writes its own row on startup, once the
schema is at its head (``services.upgrades.schema_rollback``), so the
release an appliance upgrades FROM has always recorded itself before the
upgrade starts. Releases older than this table are covered by the bundled
``app/data/release_schema_heads.json``.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base


class ReleaseSchemaHead(Base):
    __tablename__ = "release_schema_head"

    # The release string as the operator sees it: ``2026.09.04-1``, a
    # nightly's appliance version, or ``1.0.0``. On an appliance both the
    # image version and the slot's APPLIANCE_VERSION are recorded when they
    # differ, because a rollback looks the slot up by the latter.
    version: Mapped[str] = mapped_column(String(64), primary_key=True)
    alembic_head: Mapped[str] = mapped_column(String(64), nullable=False)
    # Last time a process of this release confirmed it, not first seen.
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
