"""Server-group names an appliance supervisor will accept (#1468).

The supervisor writes the assigned DNS / DHCP group's NAME into the role env
(``AGENT_GROUP`` / ``DHCP_AGENT_GROUP``) and from there into the agent's chart
values. It only accepts names matching ``_GROUP_NAME_RE`` in
``agent/supervisor/spatium_supervisor/role_orchestrator.py`` (defense in depth
against env-file injection, #237) and silently DROPS anything else: the agent
then registers with no group, and a freshly registered server lands in the
default group instead of the one the operator assigned.

Group names are otherwise free text — a compose or plain-Kubernetes install
never goes through a supervisor — so the rule is enforced only where a name
reaches one: assigning a group to an appliance role, and renaming a group
that an appliance already has assigned.

``SUPERVISOR_GROUP_NAME_RE`` must stay identical to the supervisor's pattern;
``tests/test_appliance_group_names.py`` reads it out of the supervisor source
and fails when the two drift.
"""

from __future__ import annotations

import re
import uuid
from typing import Literal

from sqlalchemy import exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import Appliance

SUPERVISOR_GROUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

GroupKind = Literal["dns", "dhcp"]

_UMLAUTS = str.maketrans(
    {"ä": "ae", "ö": "oe", "ü": "ue", "Ä": "Ae", "Ö": "Oe", "Ü": "Ue", "ß": "ss"}
)


def suggest_group_name(name: str) -> str:
    """A name the supervisor accepts, derived from ``name`` — only a hint
    in the error message, never applied on the operator's behalf."""
    s = name.translate(_UMLAUTS).lower()
    s = re.sub(r"[^a-z0-9._-]+", "-", s).strip("-._")
    return s[:128] or "group"


def group_name_problem(kind: GroupKind, name: str) -> str | None:
    """None when an appliance supervisor accepts ``name``, else why not."""
    if SUPERVISOR_GROUP_NAME_RE.match(name):
        return None
    label = "DNS" if kind == "dns" else "DHCP"
    return (
        f"{label} server group name {name!r} cannot be used on an appliance: "
        "the supervisor accepts only letters, digits, '.', '_' and '-' "
        "(starting with a letter or digit, at most 128 characters) and would "
        "drop it, so the agent would register without its group. Rename the "
        f"group first, e.g. to {suggest_group_name(name)!r}."
    )


async def group_assigned_to_appliance(
    db: AsyncSession, kind: GroupKind, group_id: uuid.UUID
) -> bool:
    column = Appliance.assigned_dns_group_id if kind == "dns" else Appliance.assigned_dhcp_group_id
    return bool(await db.scalar(select(exists().where(column == group_id))))
