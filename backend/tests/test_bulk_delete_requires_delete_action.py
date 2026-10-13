"""Every multi-row delete POST requires ``delete``, like a single-row DELETE.

``require_resource_permission`` and its siblings map HTTP methods to actions
(POST -> write, DELETE -> delete). A bulk delete is a POST, so the router-level
gates used to authorise it on ``write``: a role holding write but not delete
could not ``DELETE /x/{id}`` yet could remove up to 500 rows in one call.
``MULTI_ROW_DELETE_SUFFIXES`` names those routes for the gates.

The guard walks the live route table: every listed route is checked against a
write-only role, and a POST route named like a delete that is neither listed
nor reviewed fails, so a new one cannot quietly fall back to ``write``.
"""

from __future__ import annotations

import re
import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import MULTI_ROW_DELETE_SUFFIXES
from app.core.security import create_access_token, hash_password
from app.main import create_app
from app.models.auth import Group, Role, User
from app.models.ipam import IPAddress, IPBlock, IPSpace, Subnet
from app.services import feature_modules

# Floor on what discovery must find, so a rename that hides every route from
# the suffix match cannot turn the guard into a vacuous pass.
_KNOWN = {
    "/asns/bulk-delete",
    "/vrfs/bulk-delete",
    "/overlays/bulk-delete",
    "/multicast/groups/bulk-delete",
    "/circuits/bulk-delete",
    "/services/bulk-delete",
    "/customers/bulk-delete",
    "/sites/bulk-delete",
    "/providers/bulk-delete",
    "/domains/bulk-delete",
    "/nmap/scans/bulk-delete",
    "/pcap/captures/bulk-delete",
    "/dns/groups/{group_id}/zones/{zone_id}/records/bulk-delete",
    "/ipam/addresses/bulk-delete",
    "/ipam/subnets/{subnet_id}/orphans/purge",
}

# A POST whose last literal path segment reads like a multi-row delete must be
# either covered by ``MULTI_ROW_DELETE_SUFFIXES`` or listed here, reviewed, with
# the reason it is not one. A new ``.../purge`` or ``.../bulk-remove`` route
# therefore fails until someone decides which it is.
_DELETE_WORD = re.compile(
    r"(delete|purge|prune|clear|remove|wipe|empty|trash|evict|flush|cleanup|"
    r"drop|destroy|erase)",
    re.IGNORECASE,
)
_REVIEWED_NOT_MULTI_ROW_DELETE: dict[str, str] = {
    "/appliance/appliances/{appliance_id}/clear-upgrade": (
        "clears a pending upgrade request on one appliance row; admin on appliance"
    ),
    "/appliance/appliances/{appliance_id}/permanent-delete": (
        "one row, gated on admin:appliance plus superadmin and password"
    ),
    "/appliance/fleet/control-plane/{appliance_id}/clear-cluster-state": (
        "resets one node's cluster bookkeeping, deletes no resource rows"
    ),
    "/ipam/aggregation-snoozes/clear": (
        "removes one key from a UI suggestion snooze map, not a resource row"
    ),
}


def _post_paths() -> list[str]:
    """Full paths of every POST route, from the published document.

    ``app.routes`` holds deferred ``include_router`` wrappers whose children
    carry only their sub-path, so reading it directly finds almost nothing.
    The OpenAPI document has every route at its full path.
    """
    paths = create_app().openapi()["paths"]
    return sorted(p.removeprefix("/api/v1") for p, ops in paths.items() if "post" in ops)


def _is_multi_row_delete(path: str) -> bool:
    return path.rstrip("/").endswith(MULTI_ROW_DELETE_SUFFIXES)


def _bulk_delete_paths() -> list[str]:
    return [p for p in _post_paths() if _is_multi_row_delete(p)]


def _last_literal_segments(path: str) -> str:
    """The trailing literal segments, after the last path parameter."""
    tail: list[str] = []
    for part in reversed(path.strip("/").split("/")):
        if part.startswith("{"):
            break
        tail.append(part)
    return "/".join(reversed(tail))


def _concrete(path: str) -> str:
    out = path
    for part in path.split("/"):
        if part.startswith("{") and part.endswith("}"):
            out = out.replace(part, str(uuid.uuid4()))
    return out


async def _headers(db: AsyncSession, actions: list[str]) -> dict[str, str]:
    """A non-superadmin holding ``actions`` on EVERY resource type.

    The ``*`` resource type makes one role fit every route, whatever type or
    ``manage_*`` scope it names, while the action list is the only variable.
    """
    tag = uuid.uuid4().hex[:8]
    user = User(
        username=f"bd-{tag}",
        email=f"{tag}@example.test",
        display_name="Bulk Delete",
        hashed_password=hash_password("x"),
        is_superadmin=False,
    )
    role = Role(
        name=f"r-{tag}",
        description="",
        permissions=[{"action": a, "resource_type": "*"} for a in actions],
    )
    group = Group(name=f"g-{tag}", description="")
    group.roles = [role]
    group.users = [user]
    db.add_all([role, group, user])
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


@pytest.fixture(autouse=True)
def _all_modules_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _on(*_a: object, **_k: object) -> bool:
        return True

    monkeypatch.setattr(feature_modules, "is_module_enabled", _on)


def test_the_walk_finds_the_known_bulk_delete_routes() -> None:
    found = set(_bulk_delete_paths())
    missing = _KNOWN - found
    assert not missing, f"multi-row delete routes no longer discovered: {sorted(missing)}"


def test_every_post_named_like_a_delete_is_classified() -> None:
    """A POST that reads like a multi-row delete is on the list or reviewed.

    Without this, a new ``POST .../purge`` would be gated on ``write`` and the
    guard above would never see it, because it only checks what the list names.
    """
    posts = _post_paths()
    unclassified = sorted(
        p
        for p in posts
        if _DELETE_WORD.search(_last_literal_segments(p))
        and not _is_multi_row_delete(p)
        and p not in _REVIEWED_NOT_MULTI_ROW_DELETE
    )
    assert not unclassified, (
        "POST routes named like a delete that are neither in "
        "MULTI_ROW_DELETE_SUFFIXES nor reviewed in _REVIEWED_NOT_MULTI_ROW_DELETE: "
        f"{unclassified}"
    )
    stale = sorted(set(_REVIEWED_NOT_MULTI_ROW_DELETE) - set(posts))
    assert not stale, f"reviewed routes that no longer exist: {stale}"


def test_suffix_match_is_on_whole_segments() -> None:
    """``/x/bulk-delete-y`` or a parameter merely containing the word is not one."""
    assert _is_multi_row_delete("/vrfs/bulk-delete")
    assert _is_multi_row_delete("/vrfs/bulk-delete/")
    assert not _is_multi_row_delete("/vrfs/bulk-delete-preview")
    assert not _is_multi_row_delete("/vrfs/not-bulk-delete-x")
    assert not _is_multi_row_delete("/ipam/subnets/{subnet_id}/orphans/purge/preview")


@pytest.mark.asyncio
async def test_write_only_role_is_denied_on_every_bulk_delete_route(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session, ["read", "write"])
    leaked: list[str] = []
    for path in _bulk_delete_paths():
        for body in (
            {"ids": [], "record_ids": [], "ip_ids": []},
            {"ids": [str(uuid.uuid4())], "record_ids": [str(uuid.uuid4())]},
        ):
            url = "/api/v1" + _concrete(path)
            for target in (url, url + "/"):
                resp = await client.post(target, json=body, headers=headers)
                # A trailing slash is answered by a redirect that runs no
                # handler; anything else must be the gate's refusal.
                if resp.status_code != 403 and not (
                    target.endswith("/") and resp.status_code in (307, 308, 404)
                ):
                    leaked.append(f"{target} -> {resp.status_code}")
    assert not leaked, "write-only role was not denied: " + ", ".join(sorted(set(leaked)))


@pytest.mark.asyncio
async def test_delete_role_clears_the_gate_on_every_bulk_delete_route(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session, ["read", "write", "delete"])
    denied: list[str] = []
    for path in _bulk_delete_paths():
        resp = await client.post(
            "/api/v1" + _concrete(path),
            json={"ids": [], "record_ids": [], "ip_ids": []},
            headers=headers,
        )
        if resp.status_code in (401, 403):
            denied.append(f"{path} -> {resp.status_code}")
    assert not denied, "write+delete role was refused: " + ", ".join(denied)


@pytest.mark.asyncio
async def test_vrf_write_only_cannot_bulk_delete_but_delete_can(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Focused case over a real row: the row survives a refused call."""
    writer = await _headers(db_session, ["write"])
    deleter = await _headers(db_session, ["write", "delete"])
    created = await client.post(
        "/api/v1/vrfs",
        json={"name": f"v-{uuid.uuid4().hex[:6]}"},
        headers=writer,
    )
    assert created.status_code in (200, 201), created.text
    vid = created.json()["id"]

    denied = await client.post("/api/v1/vrfs/bulk-delete", json={"ids": [vid]}, headers=writer)
    assert denied.status_code == 403
    single = await client.delete(f"/api/v1/vrfs/{vid}", headers=writer)
    assert single.status_code == 403

    ok = await client.post("/api/v1/vrfs/bulk-delete", json={"ids": [vid]}, headers=deleter)
    assert ok.status_code == 200, ok.text
    assert ok.json()["deleted"] == 1


@pytest.mark.asyncio
async def test_dns_record_bulk_delete_needs_delete(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    writer = await _headers(db_session, ["write"])
    deleter = await _headers(db_session, ["write", "delete"])
    url = f"/api/v1/dns/groups/{uuid.uuid4()}/zones/{uuid.uuid4()}/records/bulk-delete"
    body = {"record_ids": [str(uuid.uuid4())]}
    assert (await client.post(url, json=body, headers=writer)).status_code == 403
    # Past the gate: the zone does not exist, which is a 404, not a refusal.
    assert (await client.post(url, json=body, headers=deleter)).status_code == 404


@pytest.mark.asyncio
async def test_orphan_purge_needs_delete(client: AsyncClient, db_session: AsyncSession) -> None:
    """Clean Orphans permanently deletes addresses, so it needs ``delete``.

    The same role is refused a permanent single-row delete of that address.
    """
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.77.0.0/16", name="b")
    db_session.add(block)
    await db_session.flush()
    subnet = Subnet(space_id=space.id, block_id=block.id, network="10.77.1.0/24", name="s")
    db_session.add(subnet)
    await db_session.flush()
    ip = IPAddress(subnet_id=subnet.id, address="10.77.1.20", status="orphan")
    db_session.add(ip)
    await db_session.flush()

    writer = await _headers(db_session, ["read", "write"])
    deleter = await _headers(db_session, ["read", "write", "delete"])
    url = f"/api/v1/ipam/subnets/{subnet.id}/orphans/purge"
    body = {"ip_ids": [str(ip.id)]}

    assert (await client.post(url, json=body, headers=writer)).status_code == 403
    single = await client.delete(
        f"/api/v1/ipam/addresses/{ip.id}", params={"permanent": "true"}, headers=writer
    )
    assert single.status_code == 403
    still = await db_session.execute(select(IPAddress.id).where(IPAddress.id == ip.id))
    assert still.scalar_one_or_none() == ip.id

    ok = await client.post(url, json=body, headers=deleter)
    assert ok.status_code == 200, ok.text
    assert ok.json() == {"purged": 1}
