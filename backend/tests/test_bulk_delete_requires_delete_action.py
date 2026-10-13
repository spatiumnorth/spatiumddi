"""Every ``POST .../bulk-delete`` requires ``delete``, like a single-row DELETE.

``require_resource_permission`` and its siblings map HTTP methods to actions
(POST -> write, DELETE -> delete). A bulk delete is a POST, so the router-level
gates used to authorise it on ``write``: a role holding write but not delete
could not ``DELETE /x/{id}`` yet could remove up to 500 rows in one call.

The guard walks the live route table, so a bulk-delete route added later
without a delete check fails here without anyone remembering to list it.
"""

from __future__ import annotations

import uuid

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.main import create_app
from app.models.auth import Group, Role, User
from app.services import feature_modules

# A route that is not named ``bulk-delete`` but deletes many rows by POST can
# be added here; the walk below finds the conventional name on its own.
_EXTRA_BULK_DELETE_PATHS: set[str] = set()

# Floor on what the walk must discover, so a rename that hides every route from
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
    "/dns/groups/{group_id}/zones/{zone_id}/records/bulk-delete",
    "/ipam/addresses/bulk-delete",
}


def _bulk_delete_paths() -> list[str]:
    """Full paths of every bulk-delete POST, from the published document.

    ``app.routes`` holds deferred ``include_router`` wrappers whose children
    carry only their sub-path, so reading it directly finds almost nothing.
    The OpenAPI document has every route at its full path.
    """
    paths = create_app().openapi()["paths"]
    return sorted(
        p
        for p, ops in paths.items()
        if "post" in ops and (p.endswith("/bulk-delete") or p in _EXTRA_BULK_DELETE_PATHS)
    )


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
    found = {p.removeprefix("/api/v1") for p in _bulk_delete_paths()}
    missing = _KNOWN - found
    assert not missing, f"bulk-delete routes no longer discovered: {sorted(missing)}"


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
            resp = await client.post(_concrete(path), json=body, headers=headers)
            if resp.status_code != 403:
                leaked.append(f"{path} -> {resp.status_code}")
    assert not leaked, "write-only role was not denied: " + ", ".join(sorted(set(leaked)))


@pytest.mark.asyncio
async def test_delete_role_clears_the_gate_on_every_bulk_delete_route(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    headers = await _headers(db_session, ["read", "write", "delete"])
    denied: list[str] = []
    for path in _bulk_delete_paths():
        resp = await client.post(
            _concrete(path),
            json={"ids": [], "record_ids": [], "ip_ids": []},
            headers=headers,
        )
        if resp.status_code in (401, 403):
            denied.append(f"{path} -> {resp.status_code}")
    assert not denied, "write+delete role was refused: " + ", ".join(denied)


@pytest.mark.asyncio
async def test_circuits_write_only_cannot_bulk_delete_but_delete_can(
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
    assert (await client.delete(f"/api/v1/vrfs/{vid}", headers=writer)).status_code == 403

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
