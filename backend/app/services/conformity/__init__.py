"""Conformity evaluations service (issue #106).

Companion to the compliance-change alerts in #105: where alerts fire
*reactively* on individual mutations, conformity evaluations run
*proactively* on a schedule and produce auditor-acceptable artifacts.

Public surface:

* ``engine.evaluate_policy`` / ``evaluate_due_policies`` — the
  orchestrator the API + Celery beat call.
* ``checks.CHECK_REGISTRY`` — name → evaluator function. Looked up
  by ``ConformityPolicy.check_kind``.
* ``seeder.seed_builtin_conformity_policies`` — first-boot seed of
  the curated PCI / HIPAA / internet-facing starter library.
* ``pdf.generate_conformity_pdf`` — auditor-facing PDF export.
"""

from __future__ import annotations

from app.services.conformity.engine import (
    evaluate_due_policies,
    evaluate_policy,
    resolve_orphaned_policy_alerts,
    resolve_policy_alerts,
)
from app.services.conformity.seeder import seed_builtin_conformity_policies

__all__ = [
    "evaluate_due_policies",
    "evaluate_policy",
    "resolve_orphaned_policy_alerts",
    "resolve_policy_alerts",
    "seed_builtin_conformity_policies",
]
