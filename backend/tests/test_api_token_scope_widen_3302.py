"""Write-scope prefixes cover the plainly-domain routes, and approve-and-provision
checks the operation's own family at apply time (#3302, S2-e).

Token SCOPE only: RBAC is untouched, so every HTTP case uses a superadmin owner
and the assertion is about the scope gate / the apply-time scope check.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, generate_api_token, hash_password
from app.models.ai import AIOperationProposal
from app.models.auth import Group, Role, User
from app.models.change_request import ChangeRequest
from app.models.feature_module import FeatureModule
from app.models.ipam import IPBlock, IPSpace
from app.services import feature_modules
from app.services.ai import operations
from app.services.api_token_scopes import scope_matches_request

# ── Unit: the widened routes ──────────────────────────────────────────────

_WIDENED = [
    ("ipam:write", "POST", "/api/v1/address-sets"),
    ("ipam:write", "PUT", "/api/v1/address-sets/abc"),
    ("ipam:write", "POST", "/api/v1/multicast/groups"),
    ("ipam:write", "DELETE", "/api/v1/multicast/groups/abc"),
    ("ipam:write", "PUT", "/api/v1/av/flows/abc"),
    ("ipam:write", "POST", "/api/v1/av/reserved-ranges"),
    ("ipam:write", "POST", "/api/v1/custom-fields"),
    ("ipam:write", "POST", "/api/v1/nmap/scans/abc/stamp-discovered"),
    ("dns:write", "POST", "/api/v1/acme/register"),
    ("dns:write", "DELETE", "/api/v1/acme/accounts/abc"),
    ("dns:write", "POST", "/api/v1/domains"),
    ("dns:write", "DELETE", "/api/v1/domains/abc"),
    ("dhcp:write", "POST", "/api/v1/new-devices/block"),
]


@pytest.mark.parametrize(("scope", "method", "path"), _WIDENED)
def test_widened_route_admits_its_scope_and_only_its_scope(
    scope: str, method: str, path: str
) -> None:
    assert scope_matches_request([scope], method, path) is True
    for other in {"ipam:write", "dns:write", "dhcp:write", "read"} - {scope}:
        assert scope_matches_request([other], method, path) is False, other


@pytest.mark.parametrize(
    ("scope", "method", "path"),
    [
        # Scan creation is an active probe; only the stamp is IPAM's.
        ("ipam:write", "POST", "/api/v1/nmap/scans"),
        ("ipam:write", "POST", "/api/v1/nmap/scans/abc/stamp-discovered/x"),
        ("ipam:write", "DELETE", "/api/v1/nmap/scans/abc/stamp-discovered"),
        # The acme-dns client surface authenticates itself; not an operator.
        ("dns:write", "POST", "/api/v1/acme/update"),
        ("dns:write", "DELETE", "/api/v1/acme/update"),
        ("dns:write", "POST", "/api/v1/acme/registerx"),
        ("dhcp:write", "POST", "/api/v1/new-devices/baseline"),
        ("dhcp:write", "POST", "/api/v1/new-devices/allowlist"),
        ("dns:write", "POST", "/api/v1/domainsx"),
        ("ipam:write", "POST", "/api/v1/custom-fieldsx"),
        ("ipam:write", "POST", "/api/v1/av/other"),
        # The synchronous RDAP refresh is an off-prem lookup (unrestricted only).
        ("dns:write", "POST", "/api/v1/domains/abc/refresh-whois"),
        # Matched whole: no trailing slash, newline or extra segment.
        ("dhcp:write", "POST", "/api/v1/new-devices/block/"),
        ("dns:write", "POST", "/api/v1/acme/register\n"),
        ("ipam:write", "POST", "/api/v1/requests/abc/approve/x"),
    ],
)
def test_siblings_of_a_widened_route_stay_refused(scope: str, method: str, path: str) -> None:
    assert scope_matches_request([scope], method, path) is False


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/migration/cutover/plans",
        "/api/v1/migration/cutover/plans/abc/items/def/switch",
        "/api/v1/admin/trash/subnet/abc/restore",
        "/api/v1/change-requests/policies",
    ],
)
def test_cross_domain_routes_stay_unrestricted_only(path: str) -> None:
    for scopes in (["ipam:write"], ["dns:write"], ["dhcp:write"]):
        assert scope_matches_request(scopes, "POST", path) is False
        assert scope_matches_request(scopes, "DELETE", path) is False
    assert scope_matches_request([], "POST", path) is True


# ── HTTP ──────────────────────────────────────────────────────────────────


async def _user(db: AsyncSession, name: str, perms: list[dict] | None, *, sa: bool = False):
    user = User(
        username=f"{name}-{uuid.uuid4().hex[:8]}",
        email=f"{name}-{uuid.uuid4().hex[:8]}@t.io",
        display_name=name,
        hashed_password=hash_password("password123"),
        is_superadmin=sa,
    )
    user.groups = []
    if perms:
        role = Role(name=f"role-{uuid.uuid4().hex[:8]}", permissions=perms)
        group = Group(name=f"grp-{uuid.uuid4().hex[:8]}")
        group.roles = [role]
        user.groups = [group]
        db.add_all([role, group])
    db.add(user)
    await db.flush()
    return user


async def _api_token(db: AsyncSession, owner: User, scopes: list[str]) -> dict[str, str]:
    from app.models.auth import APIToken  # noqa: PLC0415

    raw, _prefix, token_hash = generate_api_token()
    db.add(
        APIToken(
            name=f"t-{uuid.uuid4().hex[:6]}",
            token_hash=token_hash,
            prefix=raw[:10],
            scope="user",
            scopes=scopes,
            user_id=owner.id,
            created_by_user_id=owner.id,
            is_active=True,
        )
    )
    await db.flush()
    return {"Authorization": f"Bearer {raw}"}


async def _enable(db: AsyncSession, *modules: str) -> None:
    for m in modules:
        db.add(FeatureModule(id=m, enabled=True))
    await db.flush()
    feature_modules.invalidate_cache()


@pytest.mark.asyncio
async def test_widened_routes_pass_the_gate_for_the_right_scope(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable(db_session, "ipam.address_sets", "network.domains")
    owner = await _user(db_session, "own", None, sa=True)
    ipam = await _api_token(db_session, owner, ["ipam:write"])
    dns = await _api_token(db_session, owner, ["dns:write"])
    await db_session.commit()

    r = await client.post(
        "/api/v1/address-sets", json={"name": f"s-{uuid.uuid4().hex[:6]}"}, headers=ipam
    )
    assert r.status_code != 403, r.text
    r = await client.post("/api/v1/address-sets", json={"name": "x"}, headers=dns)
    assert r.status_code == 403 and "scope" in r.text.lower()

    r = await client.post("/api/v1/domains", json={"name": "example.test"}, headers=dns)
    assert r.status_code != 403, r.text
    r = await client.post("/api/v1/domains", json={"name": "example.test"}, headers=ipam)
    assert r.status_code == 403 and "scope" in r.text.lower()


@pytest.mark.asyncio
async def test_cutover_is_still_refused_to_every_scoped_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable(db_session, "migration.cutover")
    owner = await _user(db_session, "own", None, sa=True)
    hdrs = [
        await _api_token(db_session, owner, [s]) for s in ("ipam:write", "dns:write", "dhcp:write")
    ]
    await db_session.commit()
    for h in hdrs:
        r = await client.post("/api/v1/migration/cutover/plans", json={}, headers=h)
        assert r.status_code == 403 and "scope" in r.text.lower(), r.text


_APPROVER_PERMS = [
    {"action": "approve", "resource_type": "change_request"},
    {"action": "read", "resource_type": "change_request"},
    {"action": "write", "resource_type": "subnet"},
    {"action": "read", "resource_type": "subnet"},
    {"action": "read", "resource_type": "ip_block"},
]
_REQUESTER_PERMS = [
    {"action": "write", "resource_type": "provisioning_request"},
    {"action": "read", "resource_type": "provisioning_request"},
    {"action": "read", "resource_type": "subnet"},
    {"action": "read", "resource_type": "ip_block"},
]


async def _submit(client: AsyncClient, db: AsyncSession, requester: User) -> str:
    space = IPSpace(name=f"sp-{uuid.uuid4().hex[:6]}")
    db.add(space)
    await db.flush()
    block = IPBlock(space_id=space.id, network="10.30.0.0/16", name="b")
    db.add(block)
    await db.flush()
    r = await client.post(
        "/api/v1/requests",
        headers={"Authorization": f"Bearer {create_access_token(str(requester.id))}"},
        json={
            "kind": "subnet",
            "args": {"block_id": str(block.id), "prefix_len": 26, "name": "lab"},
            "justification": "x",
        },
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.mark.asyncio
@pytest.mark.parametrize("verb", ["approve", "reject"])
async def test_portal_decision_checks_the_operations_family(
    client: AsyncClient, db_session: AsyncSession, verb: str
) -> None:
    await _enable(db_session, "governance.requests")
    requester = await _user(db_session, "req", _REQUESTER_PERMS)
    approver = await _user(db_session, "appr", _APPROVER_PERMS)
    wrong = await _api_token(db_session, approver, ["dns:write"])
    read = await _api_token(db_session, approver, ["read"])
    right = await _api_token(db_session, approver, ["ipam:write"])
    req_id = await _submit(client, db_session, requester)
    await db_session.commit()
    url = f"/api/v1/requests/{req_id}/{verb}"

    r = await client.post(url, headers=read, json={})
    assert r.status_code == 403, r.text
    r = await client.post(url, headers=wrong, json={})
    assert r.status_code == 403 and "ipam:write" in r.json()["detail"], r.text
    r = await client.post(url, headers=right, json={})
    assert r.status_code == 200, r.text
    assert r.json()["state"] == ("executed" if verb == "approve" else "rejected")


@pytest.mark.asyncio
async def test_portal_decision_is_unchanged_for_an_unrestricted_token_and_session(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable(db_session, "governance.requests")
    requester = await _user(db_session, "req", _REQUESTER_PERMS)
    approver = await _user(db_session, "appr", _APPROVER_PERMS)
    unrestricted = await _api_token(db_session, approver, [])
    first = await _submit(client, db_session, requester)
    second = await _submit(client, db_session, requester)
    await db_session.commit()
    r = await client.post(f"/api/v1/requests/{first}/approve", headers=unrestricted, json={})
    assert r.status_code == 200 and r.json()["state"] == "executed", r.text
    session = {"Authorization": f"Bearer {create_access_token(str(approver.id))}"}
    r = await client.post(f"/api/v1/requests/{second}/approve", headers=session, json={})
    assert r.status_code == 200 and r.json()["state"] == "executed", r.text


@pytest.mark.asyncio
async def test_portal_submit_and_cancel_check_the_family(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable(db_session, "governance.requests")
    requester = await _user(db_session, "req", _REQUESTER_PERMS)
    wrong = await _api_token(db_session, requester, ["dns:write"])
    right = await _api_token(db_session, requester, ["ipam:write"])
    req_id = await _submit(client, db_session, requester)
    await db_session.commit()

    body = {"kind": "subnet", "args": {}, "justification": "x"}
    r = await client.post("/api/v1/requests", headers=wrong, json=body)
    assert r.status_code == 403 and "ipam:write" in r.json()["detail"], r.text
    r = await client.post("/api/v1/requests", headers=right, json=body)
    assert r.status_code != 403, r.text  # args are invalid; the scope gate passed

    r = await client.post(f"/api/v1/requests/{req_id}/cancel", headers=wrong, json={})
    assert r.status_code == 403 and "ipam:write" in r.json()["detail"], r.text
    r = await client.post(f"/api/v1/requests/{req_id}/cancel", headers=right, json={})
    assert r.status_code == 200 and r.json()["state"] == "cancelled", r.text


@pytest.mark.asyncio
async def test_gate_change_request_decision_checks_the_operations_family(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable(db_session, "governance.approvals")
    requester = await _user(db_session, "req", None, sa=True)
    approver = await _user(db_session, "appr", None, sa=True)
    wrong = await _api_token(db_session, approver, ["ipam:write"])
    cr = ChangeRequest(
        operation="delete_zone",
        resource_type="dns_zone",
        resource_display="z.test",
        risk_reason="delete",
        requested_by_display="req",
        args={"zone_id": str(uuid.uuid4())},
        preview_text="x",
        origin="gate",
        state="pending",
        requested_by_user_id=requester.id,
        expires_at=datetime.now(UTC) + timedelta(hours=1),
    )
    db_session.add(cr)
    await db_session.commit()
    for verb in ("approve", "reject"):
        r = await client.post(f"/api/v1/change-requests/{cr.id}/{verb}", headers=wrong, json={})
        assert r.status_code == 403 and "dns:write" in r.json()["detail"], (verb, r.text)


@pytest.mark.asyncio
async def test_proposal_apply_checks_the_operations_family(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable(db_session, "ai.copilot")
    owner = await _user(db_session, "own", None, sa=True)
    wrong = await _api_token(db_session, owner, ["ipam:write"])
    nofamily = await _api_token(db_session, owner, ["dns:write"])
    unrestricted = await _api_token(db_session, owner, [])
    row = AIOperationProposal(
        session_id=None,
        user_id=owner.id,
        operation="create_dns_record",
        args={},
        preview_text="p",
        expires_at=operations.expires_at_default(),
    )
    db_session.add(row)
    await db_session.commit()
    url = f"/api/v1/ai/proposals/{row.id}/apply"

    r = await client.post(url, headers=wrong, json={})
    assert r.status_code == 403 and "dns:write" in r.json()["detail"], r.text
    for h in (nofamily, unrestricted):
        r = await client.post(url, headers=h, json={})
        assert r.status_code != 403, r.text  # bad args -> ok=False, not a scope refusal

    # An operation no write scope covers needs an unrestricted token.
    row2 = AIOperationProposal(
        session_id=None,
        user_id=owner.id,
        operation="allowlist_mac",
        args={},
        preview_text="p",
        expires_at=operations.expires_at_default(),
    )
    db_session.add(row2)
    await db_session.commit()
    r = await client.post(f"/api/v1/ai/proposals/{row2.id}/apply", headers=nofamily, json={})
    assert r.status_code == 403 and "unrestricted" in r.json()["detail"], r.text


@pytest.mark.asyncio
async def test_expired_request_is_not_touched_by_a_wrong_family_token(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """The family check runs before approve's expiry branch, which writes
    (``mark_expired`` + commit): a token that cannot decide the request must
    not be able to move it either."""
    from sqlalchemy import select  # noqa: PLC0415

    await _enable(db_session, "governance.requests")
    requester = await _user(db_session, "req", _REQUESTER_PERMS)
    approver = await _user(db_session, "appr", _APPROVER_PERMS)
    wrong = await _api_token(db_session, approver, ["dns:write"])
    req_id = await _submit(client, db_session, requester)
    await db_session.commit()
    cr = (
        await db_session.execute(select(ChangeRequest).where(ChangeRequest.id == uuid.UUID(req_id)))
    ).scalar_one()
    cr.expires_at = datetime.now(UTC) - timedelta(minutes=1)
    await db_session.commit()

    r = await client.post(f"/api/v1/requests/{req_id}/approve", headers=wrong, json={})
    assert r.status_code == 403 and "ipam:write" in r.json()["detail"], r.text
    db_session.expire_all()
    cr = (
        await db_session.execute(select(ChangeRequest).where(ChangeRequest.id == uuid.UUID(req_id)))
    ).scalar_one()
    assert cr.state == "pending"


@pytest.mark.asyncio
async def test_domain_rdap_refresh_stays_unrestricted_only(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    await _enable(db_session, "network.domains")
    owner = await _user(db_session, "own", None, sa=True)
    dns = await _api_token(db_session, owner, ["dns:write"])
    await db_session.commit()
    r = await client.post(f"/api/v1/domains/{uuid.uuid4()}/refresh-whois", headers=dns)
    assert r.status_code == 403 and "scope" in r.text.lower(), r.text
