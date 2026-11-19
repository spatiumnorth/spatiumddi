"""#1427 — a control-plane cluster serves one DNS server group.

A formed cluster has ONE ``spatiumddi-appliance`` HelmChart, and so one
``dnsBind9.serverGroupName``: the ``AGENT_GROUP`` of the one dns-bind9
DaemonSet on every node labelled for DNS (the PowerDNS and Technitium blocks
carry the same value). Whichever member that holds a DNS role writes the chart
last sets it, from its own assignment. With two members given different
groups, every DNS agent of the cluster served the group of the last writer,
and nothing refused the assignment.

The contract (mzac, on #1427, for 1.0): assigning a cluster member a DNS group
that differs from the group the cluster's other DNS members are in is refused
with a 422 that names the cluster's group, and changes nothing. Only a change
is refused (a re-save of what is already there never is), a member that drops
DNS never is, and an appliance outside the cluster has its own chart.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.appliance import Appliance
from app.models.dns import DNSServerGroup
from tests.test_dns_server_group_move import (
    _auth,
    _fleet_appliance,
    _group,
    _roles_url,
    _server,
    _superadmin,
)

DNS_CAPS = {"can_run_dns_bind9": True, "can_run_dhcp": True}


async def _member(
    db: AsyncSession, group: DNSServerGroup | None, role: str = "member", **kw: object
) -> Appliance:
    kw.setdefault("capabilities", DNS_CAPS)
    appliance = await _fleet_appliance(db, group or await _group(db, f"g-{uuid.uuid4().hex[:6]}"))
    appliance.cluster_role = role
    for key, value in kw.items():
        setattr(appliance, key, value)
    if group is None:
        appliance.assigned_dns_group_id = None
    await db.flush()
    return appliance


async def _put(client: AsyncClient, token: str, appliance: Appliance, body: dict) -> object:
    return await client.put(_roles_url(appliance.id), json=body, headers=_auth(token))


@pytest.mark.asyncio
async def test_a_member_moved_off_the_clusters_group_is_refused_and_nothing_changes(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1427a")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _member(db_session, default, role="primary")
    member = await _member(db_session, default)
    srv = await _server(db_session, default, "ns2", host=member.hostname, agent_id=uuid.uuid4())
    await db_session.commit()

    resp = await _put(client, token, member, {"dns_group_id": str(branch.id)})

    assert resp.status_code == 422, resp.text
    assert "default" in resp.json()["detail"]
    await db_session.refresh(member)
    await db_session.refresh(srv)
    assert member.assigned_dns_group_id == default.id
    assert srv.group_id == default.id


@pytest.mark.asyncio
async def test_the_seed_is_held_to_the_same_rule(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1427b")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    seed = await _member(db_session, default, role="primary")
    await _member(db_session, default)
    await db_session.commit()

    resp = await _put(client, token, seed, {"dns_group_id": str(branch.id)})

    assert resp.status_code == 422, resp.text
    assert "default" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_the_clusters_group_or_no_other_dns_member_is_fine(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1427c")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    seed = await _member(db_session, branch, role="primary")
    member = await _member(db_session, None, assigned_roles=["dhcp"])
    await db_session.commit()

    # A member given DNS in the group the cluster serves.
    resp = await _put(
        client, token, member, {"roles": ["dns-bind9", "dhcp"], "dns_group_id": str(branch.id)}
    )
    assert resp.status_code == 200, resp.text

    # The seed, once the only DNS member left, moves the cluster's group.
    resp = await _put(client, token, member, {"roles": ["dhcp"]})
    assert resp.status_code == 200, resp.text
    resp = await _put(client, token, seed, {"dns_group_id": str(default.id)})
    assert resp.status_code == 200, resp.text
    await db_session.refresh(seed)
    assert seed.assigned_dns_group_id == default.id


@pytest.mark.asyncio
async def test_a_member_dropping_dns_is_never_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1427d")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _member(db_session, default, role="primary")
    one = await _member(db_session, branch)  # already apart, from before the rule
    two = await _member(db_session, branch)
    await db_session.commit()

    assert (await _put(client, token, one, {"roles": ["dhcp"]})).status_code == 200
    assert (await _put(client, token, two, {"dns_group_id": None})).status_code == 200


@pytest.mark.asyncio
async def test_a_member_gaining_dns_in_another_group_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Gaining the role is a change too: the group pointer it already had
    would become the chart's."""
    token = await _superadmin(db_session, "root1427e")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _member(db_session, default, role="primary")
    member = await _member(db_session, branch, assigned_roles=["dhcp"])
    await db_session.commit()

    resp = await _put(client, token, member, {"roles": ["dns-bind9", "dhcp"]})

    assert resp.status_code == 422, resp.text
    assert "default" in resp.json()["detail"]
    await db_session.refresh(member)
    assert member.assigned_roles == ["dhcp"]


@pytest.mark.asyncio
async def test_a_joining_member_counts_and_an_outside_appliance_does_not(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1427f")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _member(db_session, default, role="primary")
    joiner = await _member(db_session, default, role=None, desired_cluster_role="member")
    outside = await _member(db_session, default, role=None)  # its own k3s, its own chart
    await db_session.commit()

    assert (await _put(client, token, joiner, {"dns_group_id": str(branch.id)})).status_code == 422
    assert (await _put(client, token, outside, {"dns_group_id": str(branch.id)})).status_code == 200


@pytest.mark.asyncio
async def test_re_saving_what_is_already_there_is_never_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A cluster already split across two groups (from before the rule) can
    still save every other field of a member."""
    token = await _superadmin(db_session, "root1427g")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _member(db_session, default, role="primary")
    member = await _member(db_session, branch)
    await db_session.commit()

    resp = await _put(
        client,
        token,
        member,
        {"roles": ["dns-bind9"], "dns_group_id": str(branch.id), "tags": {"site": "b"}},
    )

    assert resp.status_code == 200, resp.text


# ── Every other way a member's DNS group can be set ──────────────────────────


@pytest.mark.asyncio
async def test_a_dns_server_move_cannot_take_a_member_off_the_clusters_group(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """A DNS server move repoints its owning appliance's group (#934), so
    moving a member's server was the same assignment by another door."""
    token = await _superadmin(db_session, "root1427h")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _member(db_session, default, role="primary")
    member = await _member(db_session, default)
    srv = await _server(db_session, default, "ns2", host=member.hostname, agent_id=uuid.uuid4())
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dns/groups/{default.id}/servers/{srv.id}",
        json={"group_id": str(branch.id)},
        headers=_auth(token),
    )

    assert resp.status_code == 422, resp.text
    assert "default" in resp.json()["detail"]
    await db_session.refresh(member)
    await db_session.refresh(srv)
    assert member.assigned_dns_group_id == default.id
    assert srv.group_id == default.id


@pytest.mark.asyncio
async def test_a_server_move_outside_the_cluster_is_unaffected(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1427i")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _member(db_session, default, role="primary")
    outside = await _member(db_session, default, role=None)
    srv = await _server(db_session, default, "ns9", host=outside.hostname, agent_id=uuid.uuid4())
    await db_session.commit()

    resp = await client.put(
        f"/api/v1/dns/groups/{default.id}/servers/{srv.id}",
        json={"group_id": str(branch.id)},
        headers=_auth(token),
    )

    assert resp.status_code == 200, resp.text
    await db_session.refresh(outside)
    assert outside.assigned_dns_group_id == branch.id


@pytest.mark.asyncio
async def test_the_copilot_assignment_is_held_to_the_same_rule(db_session: AsyncSession) -> None:
    from app.models.auth import User
    from app.services.ai.operations import AssignApplianceRoleArgs, get_operation

    user = User(
        username="root1427j",
        email="root1427j@example.com",
        display_name="root1427j",
        hashed_password="x",
        is_superadmin=True,
    )
    db_session.add(user)
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _member(db_session, default, role="primary")
    member = await _member(db_session, default)
    await db_session.commit()
    op = get_operation("assign_appliance_role")
    assert op is not None
    args = AssignApplianceRoleArgs.model_validate(
        {"appliance_id": str(member.id), "roles": ["dns-bind9"], "dns_group_id": str(branch.id)}
    )

    preview = await op.preview(db_session, user, args)
    assert not preview.ok and "default" in preview.detail
    with pytest.raises(ValueError, match="one DNS server group"):
        await op.apply(db_session, user, args)
    await db_session.refresh(member)
    assert member.assigned_dns_group_id == default.id

    # Re-proposing the cluster's own group is fine.
    same = AssignApplianceRoleArgs.model_validate(
        {"appliance_id": str(member.id), "roles": ["dns-bind9"], "dns_group_id": str(default.id)}
    )
    assert (await op.preview(db_session, user, same)).ok


async def _promote_seed(db: AsyncSession, group: DNSServerGroup) -> Appliance:
    from app.core.crypto import encrypt_str

    return await _member(
        db,
        group,
        role="primary",
        appliance_variant="control-plane",
        deployment_kind="appliance",
        node_ip="10.0.0.1",
        k3s_join_token_encrypted=encrypt_str("K10::servertoken"),
    )


@pytest.mark.asyncio
async def test_promoting_a_joiner_that_runs_dns_in_another_group_is_refused(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1427k")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _promote_seed(db_session, default)
    same = await _member(db_session, default, role=None, deployment_kind="appliance")
    other = await _member(db_session, branch, role=None, deployment_kind="appliance")
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(same.id), str(other.id)]},
        headers=_auth(token),
    )

    assert resp.status_code == 422, resp.text
    assert "branch" in resp.json()["detail"] and other.hostname in resp.json()["detail"]
    await db_session.refresh(other)
    assert other.desired_cluster_role is None


@pytest.mark.asyncio
async def test_promoting_joiners_in_the_clusters_group_or_without_dns_is_fine(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    token = await _superadmin(db_session, "root1427l")
    default = await _group(db_session, "default")
    branch = await _group(db_session, "branch")
    await _promote_seed(db_session, default)
    same = await _member(db_session, default, role=None, deployment_kind="appliance")
    no_dns = await _member(
        db_session, branch, role=None, deployment_kind="appliance", assigned_roles=["dhcp"]
    )
    await db_session.commit()

    resp = await client.post(
        "/api/v1/appliance/fleet/control-plane/promote",
        json={"appliance_ids": [str(same.id), str(no_dns.id)]},
        headers=_auth(token),
    )

    assert resp.status_code == 200, resp.text
