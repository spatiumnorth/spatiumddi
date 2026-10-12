"""#1421 — a DDNS template applied to an existing carrier locks in the
template's DDNS, not the carrier's ignored defaults.

``POST /api/v1/ipam/templates/{id}/apply`` without ``force`` fills only the
target's empty columns. A subnet's ``ddns_enabled = False`` and its default
hostname policy are values, not empty columns, so a template that turns DDNS
on never wrote either one. Its DDNS lock still turned the subnet's
``ddns_inherit_settings`` off, and with inheritance off
``resolve_effective_ddns`` reads all four of the subnet's own DDNS columns
together. A subnet that inherited DDNS on from its block was pinned to its own
DDNS, which is off: applying a template that turns DDNS on turned it off.

A carrier that inherits DDNS ignores its own DDNS columns, so they hold no
value for ``force=False`` to keep, and the lock now comes with all four of the
template's DDNS values. A carrier that already has its own DDNS keeps its
non-empty values unless ``force`` is set, as before.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import User
from app.models.ipam import IPAMTemplate, IPBlock, IPSpace, Subnet
from app.services.dns.ddns import resolve_effective_ddns

# The issue's template: it turns DDNS on.
DDNS_ON = {"ddns_enabled": True, "ddns_hostname_policy": "always_generate", "ddns_ttl": 120}
# What a subnet resolves once that template's DDNS is in effect on it:
# (enabled, hostname policy, domain override, TTL).
TEMPLATE_DDNS = (True, "always_generate", None, 120)


async def _admin_headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"ta-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="TA",
        hashed_password=hash_password("x" * 10),
        is_superadmin=True,
    )
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _space_and_ddns_block(db: AsyncSession) -> tuple[IPSpace, IPBlock]:
    """A space and a block whose own DDNS is on: what an inheriting child resolves."""
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(
        space_id=space.id,
        network="10.72.0.0/16",
        name="ddns-on",
        ddns_enabled=True,
        ddns_hostname_policy="client_provided",
        ddns_ttl=300,
        ddns_inherit_settings=False,
    )
    db.add(block)
    await db.flush()
    return space, block


def _template(db: AsyncSession, applies_to: str, **columns: Any) -> IPAMTemplate:
    template = IPAMTemplate(name=f"tpl-{uuid.uuid4().hex[:6]}", applies_to=applies_to, **columns)
    db.add(template)
    return template


async def _apply(
    client: AsyncClient, headers: dict[str, str], template: IPAMTemplate, **body: Any
) -> list[str]:
    resp = await client.post(
        f"/api/v1/ipam/templates/{template.id}/apply",
        headers=headers,
        json={k: str(v) if isinstance(v, uuid.UUID) else v for k, v in body.items()},
    )
    assert resp.status_code == 200, resp.text
    written: list[str] = resp.json()["fields_written"]
    return written


async def _effective(db: AsyncSession, subnet: Subnet, *carriers: IPBlock) -> tuple[Any, ...]:
    """The subnet's effective DDNS as the lease path resolves it, read back
    from the database after the apply."""
    for row in (subnet, *carriers):
        await db.refresh(row)
    eff = await resolve_effective_ddns(db, subnet)
    return (eff.enabled, eff.hostname_policy, eff.domain_override, eff.ttl, eff.source)


@pytest.mark.asyncio
async def test_a_ddns_template_applied_to_an_inheriting_subnet_turns_ddns_on(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # The issue's case: a subnet with the defaults inherits DDNS, on, from
    # its block, and the template it gets turns DDNS on.
    hdr = await _admin_headers(db_session)
    space, block = await _space_and_ddns_block(db_session)
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.72.1.0/24", name="s")
    db_session.add(subnet)
    template = _template(db_session, "subnet", **DDNS_ON)
    await db_session.commit()
    assert (await _effective(db_session, subnet))[0] is True

    written = await _apply(client, hdr, template, subnet_id=subnet.id)

    # DDNS is on, with the template's settings.
    assert await _effective(db_session, subnet) == (*TEMPLATE_DDNS, "subnet")
    # The response names what the apply changed, the lock included.
    assert {"ddns_enabled", "ddns_hostname_policy", "ddns_ttl", "ddns_inherit_settings"} <= set(
        written
    )


@pytest.mark.asyncio
async def test_the_lock_replaces_the_ddns_values_an_inheriting_subnet_ignores(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # A subnet that inherits keeps old DDNS values of its own that nothing
    # reads. The lock must not turn those on in place of the template's.
    hdr = await _admin_headers(db_session)
    space, block = await _space_and_ddns_block(db_session)
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.72.2.0/24",
        name="s",
        ddns_enabled=True,
        ddns_hostname_policy="client_provided",
        ddns_domain_override="old.example.com.",
        ddns_ttl=900,
    )
    db_session.add(subnet)
    template = _template(db_session, "subnet", **DDNS_ON)
    await db_session.commit()
    assert (await _effective(db_session, subnet))[4] == f"block:{block.id}"

    await _apply(client, hdr, template, subnet_id=subnet.id)

    assert await _effective(db_session, subnet) == (*TEMPLATE_DDNS, "subnet")


@pytest.mark.asyncio
async def test_a_ddns_template_applied_to_an_inheriting_block_turns_ddns_on(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _admin_headers(db_session)
    space, parent = await _space_and_ddns_block(db_session)
    child = IPBlock(
        space_id=space.id, parent_block_id=parent.id, network="10.72.16.0/20", name="child"
    )
    db_session.add(child)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=child.id, network="10.72.17.0/24", name="s")
    db_session.add(subnet)
    template = _template(db_session, "block", **DDNS_ON)
    await db_session.commit()
    assert (await _effective(db_session, subnet))[4] == f"block:{parent.id}"

    written = await _apply(client, hdr, template, block_id=child.id, carve_children=False)

    assert await _effective(db_session, subnet, child) == (*TEMPLATE_DDNS, f"block:{child.id}")
    assert "ddns_inherit_settings" in written


@pytest.mark.asyncio
async def test_without_force_a_subnets_own_ddns_keeps_its_values(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    # The operator turned DDNS off on this subnet itself. Without force the
    # apply fills only its empty DDNS columns and leaves the rest alone.
    hdr = await _admin_headers(db_session)
    space, block = await _space_and_ddns_block(db_session)
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.72.3.0/24",
        name="s",
        ddns_enabled=False,
        ddns_inherit_settings=False,
    )
    db_session.add(subnet)
    template = _template(db_session, "subnet", **DDNS_ON)
    await db_session.commit()

    written = await _apply(client, hdr, template, subnet_id=subnet.id)

    assert await _effective(db_session, subnet) == (
        False,
        "client_or_generated",
        None,
        120,
        "subnet",
    )
    assert "ddns_ttl" in written
    assert not {"ddns_enabled", "ddns_hostname_policy", "ddns_inherit_settings"} & set(written)


@pytest.mark.asyncio
async def test_force_locks_the_templates_ddns_in(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _admin_headers(db_session)
    space, block = await _space_and_ddns_block(db_session)
    subnet = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.72.4.0/24",
        name="s",
        ddns_enabled=False,
        ddns_inherit_settings=False,
    )
    db_session.add(subnet)
    template = _template(db_session, "subnet", **DDNS_ON)
    await db_session.commit()

    await _apply(client, hdr, template, subnet_id=subnet.id, force=True)

    assert await _effective(db_session, subnet) == (*TEMPLATE_DDNS, "subnet")


@pytest.mark.asyncio
async def test_a_template_without_ddns_leaves_ddns_inheritance_alone(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    hdr = await _admin_headers(db_session)
    space, block = await _space_and_ddns_block(db_session)
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.72.5.0/24", name="s")
    db_session.add(subnet)
    template = _template(db_session, "subnet", tags={"site": "hq"})
    await db_session.commit()

    written = await _apply(client, hdr, template, subnet_id=subnet.id)

    assert await _effective(db_session, subnet) == (
        True,
        "client_provided",
        None,
        300,
        f"block:{block.id}",
    )
    assert "tags" in written
    assert "ddns_inherit_settings" not in written
