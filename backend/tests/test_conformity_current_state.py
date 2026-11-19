"""#2278: the conformity summary, the PDF and the Copilot rollup report the
CURRENT state — each enabled policy's most recent pass — not every result
ever written.

Before the fix they kept the newest row per (policy, resource) across the
whole append-only history, so a target deleted or moved out of scope was
never evaluated again and its last ``fail`` stayed "current" forever; a
disabled policy's results kept counting; and a framework filter matching no
policy pulled every framework's results into the PDF.

Driven through the real engine and the real endpoints, asserting on the
numbers and the rendered PDF text an operator / auditor sees.
"""

from __future__ import annotations

import base64
import re
import uuid
import zlib
from datetime import UTC, datetime, timedelta

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.conformity import ConformityPolicy, ConformityResult
from app.models.ipam import IPBlock, IPSpace, Subnet
from app.services.ai.operations_writes import (
    UpdateConformityPolicyArgs,
    _apply_update_conformity_policy,
)
from app.services.ai.tools.conformity import GetConformitySummaryArgs, get_conformity_summary
from app.services.conformity import evaluate_policy

T1 = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)
T2 = T1 + timedelta(days=1)


async def _superadmin(db: AsyncSession) -> tuple[User, dict[str, str]]:
    user = User(
        username=f"su-{uuid.uuid4().hex[:8]}",
        email=f"su-{uuid.uuid4().hex[:8]}@t.io",
        display_name="su",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    user.groups = []
    db.add(user)
    await db.flush()
    return user, {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _pci_subnets(db: AsyncSession, n: int) -> list[Subnet]:
    space = IPSpace(name=f"c2278-{uuid.uuid4().hex[:8]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.78.0.0/16", name="b")
    db.add(block)
    await db.flush()
    subnets = []
    for i in range(n):
        s = Subnet(
            space_id=space.id,
            block_id=block.id,
            name=f"s{i}",
            network=f"10.78.{i}.0/24",
            pci_scope=True,
        )
        db.add(s)
        subnets.append(s)
    await db.flush()
    return subnets


async def _failing_policy(db: AsyncSession, *, framework: str = "PCI-DSS 4.0") -> ConformityPolicy:
    """A PCI-subnet policy every test subnet fails (no ``customer_id``)."""
    p = ConformityPolicy(
        name=f"pol-{uuid.uuid4().hex[:8]}",
        framework=framework,
        severity="warning",
        target_kind="subnet",
        target_filter={"classification": "pci_scope"},
        check_kind="has_field",
        check_args={"field": "customer_id"},
        eval_interval_hours=24,
    )
    db.add(p)
    await db.flush()
    return p


async def _summary(client: AsyncClient, h: dict[str, str]) -> dict:
    r = await client.get("/api/v1/conformity/summary", headers=h)
    assert r.status_code == 200, r.text
    return r.json()


def _pdf_text(data: bytes) -> str:
    """The text a reportlab PDF draws, wrapped lines re-joined by spaces.

    reportlab encodes content streams ASCII85 then Flate, and draws each
    wrapped line as its own ``(...) Tj`` string.
    """
    assert data.startswith(b"%PDF-")
    shown: list[str] = []
    for raw in re.findall(rb"stream\r?\n(.*?)endstream", data, re.S):
        try:
            content = zlib.decompress(base64.a85decode(raw.strip().removesuffix(b"~>")))
        except (ValueError, zlib.error):
            continue
        for lit in re.findall(rb"\(((?:\\.|[^\\()])*)\)\s*Tj", content):
            shown.append(re.sub(rb"\\(.)", rb"\1", lit).decode("latin-1"))
    return " ".join(" ".join(shown).split())


async def _pdf(client: AsyncClient, h: dict[str, str], **params: str) -> str:
    r = await client.get("/api/v1/conformity/export.pdf", params=params, headers=h)
    assert r.status_code == 200, r.text
    return _pdf_text(r.content)


async def test_descoped_target_leaves_summary_and_pdf(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _superadmin(db_session)
    keep, gone = await _pci_subnets(db_session, 2)
    policy = await _failing_policy(db_session)
    await evaluate_policy(db_session, policy, now=T1)
    await db_session.commit()
    assert (await _summary(client, h))["overall_fail"] == 2

    gone.pci_scope = False
    await evaluate_policy(db_session, policy, now=T2)
    await db_session.commit()

    s = await _summary(client, h)
    assert s["overall_fail"] == 1
    text = await _pdf(client, h)
    assert "1 current results" in text
    assert f"{keep.network}" in text
    assert f"{gone.network}" not in text


async def test_deleted_target_leaves_summary(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _superadmin(db_session)
    _, gone = await _pci_subnets(db_session, 2)
    policy = await _failing_policy(db_session)
    await evaluate_policy(db_session, policy, now=T1)
    await db_session.commit()

    await db_session.delete(gone)
    await db_session.flush()
    await evaluate_policy(db_session, policy, now=T2)
    await db_session.commit()

    assert (await _summary(client, h))["overall_fail"] == 1


async def test_disabled_policy_contributes_no_results(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _superadmin(db_session)
    await _pci_subnets(db_session, 2)
    policy = await _failing_policy(db_session)
    await evaluate_policy(db_session, policy, now=T1)
    policy.enabled = False
    await db_session.commit()

    s = await _summary(client, h)
    assert s["overall_fail"] == 0
    pci = next(f for f in s["frameworks"] if f["framework"] == "PCI-DSS 4.0")
    assert pci["policies_total"] == 1 and pci["policies_enabled"] == 0
    assert pci["fail_count"] == 0

    text = await _pdf(client, h)
    assert policy.name not in text
    assert "0 current results" in text
    assert "1 disabled policies are excluded" in text


async def test_pdf_states_scope_and_as_of(client: AsyncClient, db_session: AsyncSession) -> None:
    _, h = await _superadmin(db_session)
    await _pci_subnets(db_session, 1)
    policy = await _failing_policy(db_session)
    await evaluate_policy(db_session, policy, now=T1)
    await db_session.commit()

    text = await _pdf(client, h)
    assert "most recent evaluation pass" in text
    assert f"Results as of: {T1.isoformat()}" in text


async def test_framework_filter_matching_nothing_is_empty(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _superadmin(db_session)
    await _pci_subnets(db_session, 2)
    policy = await _failing_policy(db_session)
    await evaluate_policy(db_session, policy, now=T1)
    await db_session.commit()

    text = await _pdf(client, h, framework="no-such-framework")
    assert "0 current results" in text
    assert policy.name not in text


async def test_rescoping_a_policy_retires_its_last_pass(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, h = await _superadmin(db_session)
    await _pci_subnets(db_session, 2)
    policy = await _failing_policy(db_session)
    await evaluate_policy(db_session, policy, now=T1)
    await db_session.commit()

    r = await client.patch(
        f"/api/v1/conformity/policies/{policy.id}",
        json={"target_filter": {"classification": "hipaa_scope"}},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["last_evaluated_at"] is None
    assert (await _summary(client, h))["overall_fail"] == 0

    # A field that does not change what is checked keeps the pass.
    await evaluate_policy(db_session, policy, now=T2)
    await db_session.commit()
    r = await client.patch(
        f"/api/v1/conformity/policies/{policy.id}",
        json={"severity": "critical"},
        headers=h,
    )
    assert r.json()["last_evaluated_at"] is not None


async def test_copilot_rollup_counts_current_state_once(db_session: AsyncSession) -> None:
    user, _ = await _superadmin(db_session)
    await _pci_subnets(db_session, 1)
    policy = await _failing_policy(db_session)
    for when in (T1, T2, T2 + timedelta(days=1)):
        await evaluate_policy(db_session, policy, now=when)
    await db_session.commit()

    rows = await get_conformity_summary(db_session, user, GetConformitySummaryArgs())
    pci = next(r for r in rows if r["framework"] == "PCI-DSS 4.0")
    assert pci["fail_count"] == 1


async def test_copilot_rescope_retires_its_last_pass(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The Copilot's ``update_conformity_policy`` operation is a second
    way to change a policy's scope, and must follow the same rule."""
    user, h = await _superadmin(db_session)
    await _pci_subnets(db_session, 2)
    policy = await _failing_policy(db_session)
    await evaluate_policy(db_session, policy, now=T1)
    await db_session.commit()

    await _apply_update_conformity_policy(
        db_session,
        user,
        UpdateConformityPolicyArgs(policy_id=policy.id, check_args={"field": "vlan_id"}),
    )
    assert policy.last_evaluated_at is None
    assert (await _summary(client, h))["overall_fail"] == 0

    await evaluate_policy(db_session, policy, now=T2)
    await db_session.commit()
    await _apply_update_conformity_policy(
        db_session,
        user,
        UpdateConformityPolicyArgs(policy_id=policy.id, severity="critical"),
    )
    assert policy.last_evaluated_at == T2


async def test_unstamped_pass_never_becomes_current(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Rows from a pass that died before stamping ``last_evaluated_at``
    carry an instant no policy points at, so the previous complete pass
    keeps reporting."""
    _, h = await _superadmin(db_session)
    (subnet,) = await _pci_subnets(db_session, 1)
    policy = await _failing_policy(db_session)
    await evaluate_policy(db_session, policy, now=T1)
    db_session.add(
        ConformityResult(
            policy_id=policy.id,
            resource_kind="subnet",
            resource_id=str(subnet.id),
            resource_display="orphan",
            evaluated_at=T2,
            status="pass",
        )
    )
    await db_session.commit()

    s = await _summary(client, h)
    assert s["overall_fail"] == 1 and s["overall_pass"] == 0
