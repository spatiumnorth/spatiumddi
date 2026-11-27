"""Shared builders for the multi-tenancy tests (#4263)."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.models.tenant import Tenant

IPAM_ADMIN = [
    {"action": "admin", "resource_type": rt}
    for rt in ("ip_space", "ip_block", "subnet", "ip_address", "custom_field")
]


@dataclass
class Side:
    tenant: Tenant
    space: IPSpace
    block: IPBlock
    subnet: Subnet
    address: IPAddress
    user: User
    headers: dict[str, str]


def bearer(user: User) -> dict[str, str]:
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def make_user(
    db: AsyncSession,
    *,
    tenant: Tenant | None = None,
    superadmin: bool = False,
    permissions: list[dict] | None = None,
    group_name: str = "Admins",
) -> User:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="T User",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=superadmin,
    )
    user.groups = []
    if not superadmin:
        role = Role(name=f"r-{tag}", permissions=permissions or IPAM_ADMIN)
        group = Group(name=group_name, tenant_id=tenant.id if tenant else None)
        if tenant is None:
            group.name = f"{group_name}-{tag}"
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return user


async def make_side(
    db: AsyncSession, name: str, *, network: str = "10.50.0.0/16", subnet: str = "10.50.1.0/24"
) -> Side:
    """One tenant with a space, block, subnet, address and a tenant user. Both
    sides of a test use the SAME CIDRs and the SAME space name on purpose."""
    tenant = Tenant(name=name)
    db.add(tenant)
    await db.flush()
    space = IPSpace(name="Corporate", description=f"{name} space", tenant_id=tenant.id)
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network=network, name=f"{name}-block")
    db.add(block)
    await db.flush()
    sn = Subnet(space_id=space.id, block_id=block.id, network=subnet, name=f"{name}-subnet")
    db.add(sn)
    await db.flush()
    addr = IPAddress(
        subnet_id=sn.id,
        address=subnet.replace("0/24", "10"),
        hostname=f"{name.lower()}-host",
        status="allocated",
    )
    db.add(addr)
    user = await make_user(db, tenant=tenant)
    await db.commit()
    return Side(tenant, space, block, sn, addr, user, bearer(user))


def reset_scope(db: AsyncSession) -> None:
    """The test client shares ONE session between requests and the test body, so
    a tenant request leaves its scope (and loaded rows) behind; clear both
    before the test queries or acts as someone else."""
    db.sync_session.info.pop("tenant_scope", None)
    db.expunge_all()


async def get(client: AsyncClient, db: AsyncSession, path: str, headers: dict[str, str]):
    db.expunge_all()
    return await client.get(path, headers=headers)


async def send(client: AsyncClient, db: AsyncSession, method: str, path: str, headers: dict, **kw):
    db.expunge_all()
    return await client.request(method, path, headers=headers, **kw)


async def reload_user(db: AsyncSession, user: User) -> User:
    """A fresh copy of ``user`` with its groups (and their roles) loaded."""
    from sqlalchemy import select
    from sqlalchemy.orm import selectinload

    db.expunge_all()
    return (
        await db.execute(select(User).where(User.id == user.id).options(selectinload(User.groups)))
    ).scalar_one()
