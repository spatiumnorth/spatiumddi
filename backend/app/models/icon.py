"""Operator overrides of the shipped default-icon mapping (#5022).

The shipped mapping (device class, IP role -> icon) lives
in code (``app.services.icons``). A row here exists only when an operator
changed one entry or added their own, so a fresh install has an empty table and
a shipped-mapping change reaches every install that never touched the entry.
"""

from __future__ import annotations

from sqlalchemy import String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class IconDefault(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "icon_default"
    __table_args__ = (UniqueConstraint("kind", "match_value", name="uq_icon_default_kind_match"),)

    # device_class | ip_role
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    # Normalised (trimmed, lower-cased) value the kind is matched against.
    match_value: Mapped[str] = mapped_column(String(100), nullable=False)
    # Namespaced icon name, ``mdi:<name>``.
    icon: Mapped[str] = mapped_column(String(80), nullable=False)
