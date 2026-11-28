"""Factory-reset service (issue #116).

Per-section "wipe back to defaults" surface for superadmins. Hard
guardrails: superadmin-only permission gate, password re-validation,
type-to-confirm phrase per section, mutex against concurrent
sync/reconciler/backup operations, 6-hour cooldown, audit anchor
that survives the wipe, notification fan-out.
"""

from app.services.factory_reset.runner import (
    FactoryResetError,
    FactoryResetMutexError,
    FactoryResetOutcome,
    apply_factory_reset,
    preview_factory_reset,
)
from app.services.factory_reset.sections import (
    FACTORY_SECTIONS,
    FACTORY_SECTIONS_BY_KEY,
    FactorySection,
    section_description,
)

__all__ = [
    "FACTORY_SECTIONS",
    "FACTORY_SECTIONS_BY_KEY",
    "FactorySection",
    "FactoryResetError",
    "FactoryResetMutexError",
    "FactoryResetOutcome",
    "apply_factory_reset",
    "preview_factory_reset",
    "section_description",
]
