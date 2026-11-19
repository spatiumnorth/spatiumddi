"""A server group an appliance cannot carry is refused, not silently dropped (#1468).

The supervisor puts the assigned group's NAME into the role env and drops any
name outside ``_GROUP_NAME_RE``, so the agent registers with no group. The
control plane accepted names like ``UniFi DHCP migration`` and the only trace
was a supervisor warning on every heartbeat. Now assigning such a group to an
appliance role, or renaming an assigned group to such a name, is a 422.
"""

from __future__ import annotations

import ast
import hashlib
import os
import uuid
from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.appliance import APPLIANCE_STATE_APPROVED, Appliance
from app.models.auth import User
from app.models.dhcp import DHCPServerGroup
from app.models.dns import DNSServerGroup
from app.services.appliance.group_names import (
    SUPERVISOR_GROUP_NAME_RE,
    group_name_problem,
    suggest_group_name,
)

# ── The rule ─────────────────────────────────────────────────────────


def test_pattern_matches_the_supervisor() -> None:
    """Reads the supervisor source rather than importing it: it is a separate
    distribution, not installed in the backend's environment."""
    src = (
        Path(__file__).resolve().parents[2]
        / "agent"
        / "supervisor"
        / "spatium_supervisor"
        / "role_orchestrator.py"
    )
    if not src.exists():  # pragma: no cover - backend-only checkout
        pytest.skip(f"supervisor source not present at {src}")

    patterns = [
        node.value.args[0].value
        for node in ast.walk(ast.parse(src.read_text()))
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "_GROUP_NAME_RE" for t in node.targets)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.args[0], ast.Constant)
    ]
    assert patterns == [SUPERVISOR_GROUP_NAME_RE.pattern]


@pytest.mark.parametrize("name", ["default", "unifi-dhcp-migration", "dc1.edge_2", "A" * 128])
def test_names_the_supervisor_accepts(name: str) -> None:
    assert group_name_problem("dhcp", name) is None


@pytest.mark.parametrize(
    "name", ["UniFi DHCP migration", "Büro", "-lead", "", "a" * 129, "edge\nX=1"]
)
def test_names_the_supervisor_drops(name: str) -> None:
    problem = group_name_problem("dns", name)
    assert problem is not None
    assert "DNS server group" in problem


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("UniFi DHCP migration", "unifi-dhcp-migration"),
        ("Sonos Büro", "sonos-buero"),
        ("  --  ", "group"),
    ],
)
def test_suggested_name_is_accepted(name: str, expected: str) -> None:
    suggestion = suggest_group_name(name)
    assert suggestion == expected
    assert group_name_problem("dhcp", suggestion) is None


# ── Write paths ──────────────────────────────────────────────────────


async def _superadmin(db: AsyncSession) -> dict[str, str]:
    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(u.id))}"}


async def _approved_appliance(db: AsyncSession) -> Appliance:
    der = os.urandom(32)
    a = Appliance(
        id=uuid.uuid4(),
        hostname=f"n-{uuid.uuid4().hex[:6]}",
        public_key_der=der,
        public_key_fingerprint=hashlib.sha256(der).hexdigest(),
        state=APPLIANCE_STATE_APPROVED,
        deployment_kind="appliance",
        appliance_variant="application",
    )
    db.add(a)
    await db.flush()
    return a


@pytest.mark.asyncio
async def test_assigning_a_dhcp_group_with_a_space_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    a = await _approved_appliance(db_session)
    g = DHCPServerGroup(name="UniFi DHCP migration")
    db_session.add(g)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles", headers=h, json={"dhcp_group_id": str(g.id)}
    )
    assert r.status_code == 422, r.text
    assert "unifi-dhcp-migration" in r.json()["detail"]
    await db_session.refresh(a)
    assert a.assigned_dhcp_group_id is None


@pytest.mark.asyncio
async def test_assigning_valid_groups_still_works(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    a = await _approved_appliance(db_session)
    dhcp = DHCPServerGroup(name="unifi-dhcp-migration")
    dns = DNSServerGroup(name="iwg")
    db_session.add_all([dhcp, dns])
    await db_session.commit()

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles",
        headers=h,
        json={"dhcp_group_id": str(dhcp.id), "dns_group_id": str(dns.id)},
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(a)
    assert (a.assigned_dhcp_group_id, a.assigned_dns_group_id) == (dhcp.id, dns.id)


@pytest.mark.asyncio
async def test_assigning_a_dns_group_with_a_space_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    a = await _approved_appliance(db_session)
    g = DNSServerGroup(name="Internal DNS")
    db_session.add(g)
    await db_session.commit()

    r = await client.put(
        f"/api/v1/appliance/appliances/{a.id}/roles", headers=h, json={"dns_group_id": str(g.id)}
    )
    assert r.status_code == 422, r.text
    await db_session.refresh(a)
    assert a.assigned_dns_group_id is None


@pytest.mark.asyncio
async def test_renaming_an_assigned_dhcp_group_to_a_dropped_name_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    a = await _approved_appliance(db_session)
    g = DHCPServerGroup(name="edge")
    db_session.add(g)
    await db_session.flush()
    a.assigned_dhcp_group_id = g.id
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/server-groups/{g.id}", headers=h, json={"name": "Edge DHCP"}
    )
    assert r.status_code == 422, r.text
    await db_session.refresh(g)
    assert g.name == "edge"

    # A valid rename, and an edit that leaves the name alone, still go through.
    r = await client.put(f"/api/v1/dhcp/server-groups/{g.id}", headers=h, json={"name": "edge-2"})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_renaming_an_assigned_dns_group_to_a_dropped_name_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _superadmin(db_session)
    a = await _approved_appliance(db_session)
    g = DNSServerGroup(name="iwg")
    db_session.add(g)
    await db_session.flush()
    a.assigned_dns_group_id = g.id
    await db_session.commit()

    r = await client.put(f"/api/v1/dns/groups/{g.id}", headers=h, json={"name": "Home DNS"})
    assert r.status_code == 422, r.text
    await db_session.refresh(g)
    assert g.name == "iwg"


@pytest.mark.asyncio
async def test_unassigned_groups_keep_free_text_names(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Compose / plain-k8s installs never go through a supervisor."""
    h = await _superadmin(db_session)
    dhcp = DHCPServerGroup(name="edge")
    dns = DNSServerGroup(name="iwg")
    db_session.add_all([dhcp, dns])
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/server-groups/{dhcp.id}", headers=h, json={"name": "Edge DHCP"}
    )
    assert r.status_code == 200, r.text
    r = await client.put(f"/api/v1/dns/groups/{dns.id}", headers=h, json={"name": "Home DNS"})
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_resaving_a_legacy_name_on_an_assigned_group_is_allowed(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A group assigned before this check keeps working through the edit form,
    which sends the unchanged name along with every other field."""
    h = await _superadmin(db_session)
    a = await _approved_appliance(db_session)
    g = DHCPServerGroup(name="UniFi DHCP migration")
    db_session.add(g)
    await db_session.flush()
    a.assigned_dhcp_group_id = g.id
    await db_session.commit()

    r = await client.put(
        f"/api/v1/dhcp/server-groups/{g.id}",
        headers=h,
        json={"name": "UniFi DHCP migration", "description": "edited"},
    )
    assert r.status_code == 200, r.text


@pytest.mark.asyncio
async def test_copilot_role_assignment_refuses_the_same_names(db_session: AsyncSession) -> None:
    from app.services.ai.operations import (
        AssignApplianceRoleArgs,
        _apply_assign_appliance_role,
        _preview_assign_appliance_role,
    )

    u = User(
        username=f"u-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@x.com",
        display_name="T",
        hashed_password=hash_password("x"),
        is_superadmin=True,
    )
    db_session.add(u)
    a = await _approved_appliance(db_session)
    g = DHCPServerGroup(name="UniFi DHCP migration")
    db_session.add(g)
    await db_session.flush()
    args = AssignApplianceRoleArgs(appliance_id=str(a.id), roles=[], dhcp_group_id=str(g.id))

    preview = await _preview_assign_appliance_role(db_session, u, args)
    assert not preview.ok
    assert "unifi-dhcp-migration" in preview.detail

    with pytest.raises(ValueError, match="cannot be used on an appliance"):
        await _apply_assign_appliance_role(db_session, u, args)
    assert a.assigned_dhcp_group_id is None
