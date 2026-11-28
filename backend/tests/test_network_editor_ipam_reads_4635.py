"""The Network Editor can read what its creates anchor to (#4635).

New multicast group and AV reserved range pick an IP space, New Purdue zone a
subnet, New OT descriptor and BACnet device an address. The dialogs fill those
choices from ``GET /ipam/spaces``, ``GET /ipam/subnets`` and ``GET /search``,
which the role was refused, so each offered an empty choice. Matrix: the
built-in Network Editor, a Viewer, a superadmin, and a role holding the
registries' admin grants only (the refusal the dialogs now say in words).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import _BUILTIN_ROLES
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet

pytestmark = pytest.mark.asyncio


async def _headers(
    db: AsyncSession,
    *,
    permissions: list[dict[str, Any]] | None = None,
    superadmin: bool = False,
) -> dict[str, str]:
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"u-{tag}",
        email=f"{tag}@example.test",
        display_name="U",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    if permissions is not None:
        r = Role(name=f"r-{tag}", description="", permissions=permissions)
        g = Group(name=f"g-{tag}", description="")
        g.roles = [r]
        g.users = [user]
        db.add_all([r, g])
    db.add(user)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


async def _ipam(db: AsyncSession) -> tuple[IPSpace, Subnet]:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="198.51.100.0/24", name="b")
    db.add(block)
    await db.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="198.51.100.0/24", name="s")
    db.add(subnet)
    await db.flush()
    db.add(IPAddress(subnet_id=subnet.id, address="198.51.100.7", status="allocated"))
    await db.flush()
    return space, subnet


_EDITOR = list(_BUILTIN_ROLES["Network Editor"][1])
_NO_IPAM = [p for p in _EDITOR if p["resource_type"] not in ("ip_space", "subnet", "ip_address")]


@pytest.mark.parametrize(
    ("who", "allowed"),
    [("editor", True), ("viewer", True), ("superadmin", True), ("no_ipam_read", False)],
)
async def test_picker_reads_the_five_dialogs_use(
    client: AsyncClient, db_session: AsyncSession, who: str, allowed: bool
) -> None:
    space, subnet = await _ipam(db_session)
    headers = await _headers(
        db_session,
        permissions={
            "editor": _EDITOR,
            "viewer": [{"action": "read", "resource_type": "*"}],
            "no_ipam_read": _NO_IPAM,
        }.get(who),
        superadmin=who == "superadmin",
    )

    spaces = await client.get("/api/v1/ipam/spaces", headers=headers)
    subnets = await client.get("/api/v1/ipam/subnets", headers=headers)
    found = await client.get(
        "/api/v1/search",
        params={"q": "198.51.100.7", "types": "ip_address"},
        headers=headers,
    )
    assert found.status_code == 200
    hits = [r for r in found.json()["results"] if r["type"] == "ip_address"]

    if allowed:
        assert spaces.status_code == 200
        assert str(space.id) in {s["id"] for s in spaces.json()}
        assert subnets.status_code == 200
        assert str(subnet.id) in {s["id"] for s in subnets.json()}
        assert hits
        assert "ip_address" in {t["type"] for t in found.json()["searched_types"]}
    else:
        assert spaces.status_code == 403
        assert subnets.status_code == 403
        assert not hits
        assert "ip_address" not in {t["type"] for t in found.json()["searched_types"]}


async def test_network_editor_gets_read_only_on_ipam() -> None:
    perms = {(p["action"], p["resource_type"]) for p in _EDITOR}
    for t in ("ip_space", "subnet", "ip_address"):
        assert ("read", t) in perms
        assert ("admin", t) not in perms and ("write", t) not in perms
