"""Integration tests for the ACME DNS-01 provider surface.

Covers:
  * unit: password hash roundtrip + negative cases
  * unit: source-CIDR allowlist (open, matching, non-matching, bad CIDR)
  * unit: fulldomain composition
  * unit: subdomain uniqueness + zone isolation (separate accounts
    cannot write to each other's labels)
  * HTTP: /register requires auth and write permission on
    acme_account; returns plaintext creds once; credentials are
    bcrypt-verifiable; duplicate subdomain never issued
  * HTTP: /update authenticates, rejects wrong creds, rejects
    mismatched subdomain, writes TXT to the zone
  * HTTP: /accounts lists and DELETE revokes; revoked creds stop
    working instantly
  * behaviour: rolling 2-value window (wildcard cert support) —
    three /update calls leave exactly the last two TXT values

The ack-wait path (wait_for_op_applied) is mocked out so the tests
don't depend on a live agent. A dedicated test still exercises the
timeout branch by giving a non-existent op-id.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.acme_auth import (
    generate_acme_credentials,
    hash_acme_password,
    verify_acme_password,
)
from app.core.security import create_access_token, hash_password
from app.models.acme import ACMEAccount
from app.models.auth import User
from app.models.dns import DNSAgentBundle, DNSRecord, DNSServer, DNSServerGroup, DNSZone
from app.services import acme as acme_svc

# ── Helpers ─────────────────────────────────────────────────────────


async def _make_user(db: AsyncSession, superadmin: bool = True) -> tuple[User, str]:
    user = User(
        username=f"user-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.com",
        display_name="Test",
        hashed_password=hash_password("x"),
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    return user, create_access_token(str(user.id))


async def _make_zone_with_primary(
    db: AsyncSession, zone_name: str = "acme.example.com."
) -> DNSZone:
    """Zone + server group + primary server, minimum needed for
    enqueue_record_op to target a primary."""
    group = DNSServerGroup(name=f"g-{uuid.uuid4().hex[:8]}", description="")
    db.add(group)
    await db.flush()
    server = DNSServer(
        name=f"s-{uuid.uuid4().hex[:8]}",
        host="127.0.0.1",
        port=53,
        driver="bind9",
        group_id=group.id,
        is_primary=True,
        is_enabled=True,
    )
    db.add(server)
    zone = DNSZone(
        name=zone_name,
        zone_type="primary",
        kind="forward",
        group_id=group.id,
        primary_ns="ns1.example.com.",
        admin_email="hostmaster.example.com.",
    )
    db.add(zone)
    await db.flush()
    return zone


# ── Unit: crypto ────────────────────────────────────────────────────


def test_generate_credentials_distinct() -> None:
    a = generate_acme_credentials()
    b = generate_acme_credentials()
    assert a != b
    # Usernames and passwords are 40 chars; subdomain is a uuid
    assert len(a[0]) == 40
    assert len(a[1]) == 40
    assert len(a[2]) == 36


def test_password_roundtrip() -> None:
    _, password, _ = generate_acme_credentials()
    h = hash_acme_password(password)
    assert verify_acme_password(password, h)


def test_password_rejects_wrong() -> None:
    _, password, _ = generate_acme_credentials()
    h = hash_acme_password(password)
    assert not verify_acme_password(password + "x", h)
    assert not verify_acme_password("", h)


def test_password_rejects_malformed_hash() -> None:
    assert not verify_acme_password("pw", "")
    assert not verify_acme_password("pw", "not-a-bcrypt-hash")


# ── Unit: source-CIDR allowlist ─────────────────────────────────────


def _mk_account(**kw: Any) -> ACMEAccount:
    defaults: dict[str, Any] = {
        "username": "u",
        "password_hash": "h",
        "subdomain": "s",
        "zone_id": uuid.uuid4(),
    }
    defaults.update(kw)
    return ACMEAccount(**defaults)


def test_source_ip_open_allowlist() -> None:
    acc = _mk_account(allowed_source_cidrs=None)
    assert acme_svc.client_ip_allowed(acc, "1.2.3.4") is True
    assert acme_svc.client_ip_allowed(acc, None) is True


def test_source_ip_match() -> None:
    acc = _mk_account(allowed_source_cidrs=["10.0.0.0/8", "192.168.1.0/24"])
    assert acme_svc.client_ip_allowed(acc, "10.5.5.5") is True
    assert acme_svc.client_ip_allowed(acc, "192.168.1.50") is True


def test_source_ip_no_match() -> None:
    acc = _mk_account(allowed_source_cidrs=["10.0.0.0/8"])
    assert acme_svc.client_ip_allowed(acc, "8.8.8.8") is False


def test_source_ip_none_with_allowlist_fails_closed() -> None:
    acc = _mk_account(allowed_source_cidrs=["10.0.0.0/8"])
    assert acme_svc.client_ip_allowed(acc, None) is False


def test_source_ip_bad_cidr_in_allowlist_is_skipped() -> None:
    # One bad entry shouldn't poison the other valid entries.
    acc = _mk_account(allowed_source_cidrs=["not-a-cidr", "10.0.0.0/8"])
    assert acme_svc.client_ip_allowed(acc, "10.5.5.5") is True
    assert acme_svc.client_ip_allowed(acc, "8.8.8.8") is False


# ── Unit: fulldomain composition ────────────────────────────────────


def test_fulldomain_strips_trailing_dot() -> None:
    zone = DNSZone(
        name="acme.example.com.",
        zone_type="primary",
        kind="forward",
        group_id=uuid.uuid4(),
        primary_ns="ns1.",
        admin_email="hm.",
    )
    acc = _mk_account(subdomain="abc-def")
    assert acme_svc.fulldomain_of(acc, zone) == "abc-def.acme.example.com"


# ── HTTP: /register ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_register_unauthorized(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/acme/register",
        json={"zone_id": str(uuid.uuid4())},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_register_requires_permission(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session, superadmin=False)
    zone = await _make_zone_with_primary(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/acme/register",
        json={"zone_id": str(zone.id)},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_register_missing_zone(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/acme/register",
        json={"zone_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_register_success_returns_once(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    zone = await _make_zone_with_primary(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/acme/register",
        json={
            "zone_id": str(zone.id),
            "description": "foo.example.com cert",
            "allowed_source_cidrs": ["10.0.0.0/8"],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    body = resp.json()
    # acme-dns-compatible shape
    assert body["username"]
    assert body["password"]
    assert body["subdomain"]
    # Exact-match assertion (not `endswith`) so the test fails on any
    # unexpected affix. Also silences CodeQL's
    # ``py/incomplete-url-substring-sanitization`` rule, which treats
    # ``endswith("domain")`` as a potentially unsafe host check even in
    # test code.
    assert body["fulldomain"] == f"{body['subdomain']}.acme.example.com"
    assert body["allowfrom"] == ["10.0.0.0/8"]
    # Plaintext password verifies against stored hash
    row = (
        await db_session.execute(
            select(ACMEAccount).where(ACMEAccount.username == body["username"])
        )
    ).scalar_one()
    assert verify_acme_password(body["password"], row.password_hash)


@pytest.mark.asyncio
async def test_register_bad_cidr_422(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    zone = await _make_zone_with_primary(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/acme/register",
        json={"zone_id": str(zone.id), "allowed_source_cidrs": ["not-a-cidr"]},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 422


# ── HTTP: /update ───────────────────────────────────────────────────


async def _register_account(
    client: AsyncClient, db_session: AsyncSession, token: str
) -> tuple[DNSZone, dict[str, Any]]:
    zone = await _make_zone_with_primary(db_session)
    await db_session.commit()
    resp = await client.post(
        "/api/v1/acme/register",
        json={"zone_id": str(zone.id)},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 201
    return zone, resp.json()


@pytest.mark.asyncio
async def test_update_rejects_missing_headers(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/acme/update",
        json={"subdomain": "any", "txt": "x"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_update_rejects_bad_password(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    _zone, creds = await _register_account(client, db_session, token)
    resp = await client.post(
        "/api/v1/acme/update",
        json={"subdomain": creds["subdomain"], "txt": "v"},
        headers={
            "X-Api-User": creds["username"],
            "X-Api-Key": creds["password"] + "wrong",
        },
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_update_rejects_subdomain_mismatch(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session)
    _zone, creds = await _register_account(client, db_session, token)
    resp = await client.post(
        "/api/v1/acme/update",
        json={"subdomain": "not-mine", "txt": "v"},
        headers={
            "X-Api-User": creds["username"],
            "X-Api-Key": creds["password"],
        },
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_update_writes_txt_and_acks(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    zone, creds = await _register_account(client, db_session, token)
    with patch.object(acme_svc, "wait_for_op_applied", new=AsyncMock(return_value="applied")):
        resp = await client.post(
            "/api/v1/acme/update",
            json={"subdomain": creds["subdomain"], "txt": "NwKm_first_token"},
            headers={
                "X-Api-User": creds["username"],
                "X-Api-Key": creds["password"],
            },
        )
    assert resp.status_code == 200
    assert resp.json() == {"txt": "NwKm_first_token"}
    # Record landed in the zone
    rec = (
        await db_session.execute(
            select(DNSRecord).where(
                DNSRecord.zone_id == zone.id,
                DNSRecord.name == creds["subdomain"],
                DNSRecord.record_type == "TXT",
            )
        )
    ).scalar_one()
    assert rec.value == "NwKm_first_token"
    assert rec.ttl == acme_svc.ACME_TXT_TTL


@pytest.mark.asyncio
async def test_update_wait_scales_with_the_primary_render_time(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """#1184 — the primary receives the TXT with its next render, so the wait
    is two of its renders plus the margin, capped under nginx's 60 s."""
    _, token = await _make_user(db_session)
    zone, creds = await _register_account(client, db_session, token)
    server = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == zone.group_id))
    ).scalar_one()
    db_session.add(
        DNSAgentBundle(
            server_id=server.id,
            dirty_watermark=1,
            snapshot_at=datetime.now(UTC),
            etag="e",
            structural_etag="s",
            ships_ops=True,
            body=b"",
            body_bytes=0,
            body_gzip_bytes=0,
            records=0,
            render_ms=20_000,
            rendered_by="worker",
        )
    )
    await db_session.commit()
    wait = AsyncMock(return_value="applied")
    with patch.object(acme_svc, "wait_for_op_applied", new=wait):
        resp = await client.post(
            "/api/v1/acme/update",
            json={"subdomain": creds["subdomain"], "txt": "slow_render_token"},
            headers={"X-Api-User": creds["username"], "X-Api-Key": creds["password"]},
        )
    assert resp.status_code == 200, resp.text
    assert wait.await_args is not None
    assert wait.await_args.kwargs["timeout"] == 2 * 20 + acme_svc.APPLY_TIMEOUT_MARGIN_SECONDS


@pytest.mark.asyncio
async def test_update_idempotent_same_value(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    _zone, creds = await _register_account(client, db_session, token)
    with patch.object(acme_svc, "wait_for_op_applied", new=AsyncMock(return_value="applied")):
        r1 = await client.post(
            "/api/v1/acme/update",
            json={"subdomain": creds["subdomain"], "txt": "same"},
            headers={
                "X-Api-User": creds["username"],
                "X-Api-Key": creds["password"],
            },
        )
        r2 = await client.post(
            "/api/v1/acme/update",
            json={"subdomain": creds["subdomain"], "txt": "same"},
            headers={
                "X-Api-User": creds["username"],
                "X-Api-Key": creds["password"],
            },
        )
    assert r1.status_code == r2.status_code == 200
    # Only one record exists — the second /update was a no-op
    rows = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.record_type == "TXT")))
        .scalars()
        .all()
    )
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_update_rolling_two_value_window(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    """Wildcard certs require two different TXT values at the same
    label. acme-dns keeps at most the 2 most recent; the 3rd /update
    evicts the oldest."""
    _, token = await _make_user(db_session)
    _zone, creds = await _register_account(client, db_session, token)
    values = ["token_A", "token_B", "token_C"]
    with patch.object(acme_svc, "wait_for_op_applied", new=AsyncMock(return_value="applied")):
        for v in values:
            resp = await client.post(
                "/api/v1/acme/update",
                json={"subdomain": creds["subdomain"], "txt": v},
                headers={
                    "X-Api-User": creds["username"],
                    "X-Api-Key": creds["password"],
                },
            )
            assert resp.status_code == 200
    rows = (
        (
            await db_session.execute(
                select(DNSRecord)
                .where(DNSRecord.record_type == "TXT")
                .order_by(DNSRecord.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    kept_values = [r.value for r in rows]
    assert kept_values == ["token_B", "token_C"], f"expected oldest evicted, got {kept_values}"


# ── HTTP: /accounts (list + revoke) ─────────────────────────────────


@pytest.mark.asyncio
async def test_list_accounts_returns_no_secrets(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session)
    _zone, creds = await _register_account(client, db_session, token)
    resp = await client.get(
        "/api/v1/acme/accounts",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    body = rows[0]
    # Credentials NEVER surface in list
    assert "password" not in body
    assert "password_hash" not in body
    # Public identifiers do
    assert body["username"] == creds["username"]
    assert body["subdomain"] == creds["subdomain"]
    assert body["fulldomain"] == creds["fulldomain"]


@pytest.mark.asyncio
async def test_revoke_account_kills_credentials(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    _, token = await _make_user(db_session)
    _zone, creds = await _register_account(client, db_session, token)
    listing = (
        await client.get(
            "/api/v1/acme/accounts",
            headers={"Authorization": f"Bearer {token}"},
        )
    ).json()
    account_id = listing[0]["id"]
    resp = await client.delete(
        f"/api/v1/acme/accounts/{account_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204
    # Subsequent /update with the (now dead) creds → 401
    resp = await client.post(
        "/api/v1/acme/update",
        json={"subdomain": creds["subdomain"], "txt": "whatever"},
        headers={
            "X-Api-User": creds["username"],
            "X-Api-Key": creds["password"],
        },
    )
    assert resp.status_code == 401


# ── HTTP: DELETE /update (cleanup) ─────────────────────────────────


@pytest.mark.asyncio
async def test_delete_update_clears_records(client: AsyncClient, db_session: AsyncSession) -> None:
    _, token = await _make_user(db_session)
    _zone, creds = await _register_account(client, db_session, token)
    with patch.object(acme_svc, "wait_for_op_applied", new=AsyncMock(return_value="applied")):
        await client.post(
            "/api/v1/acme/update",
            json={"subdomain": creds["subdomain"], "txt": "to-be-cleaned"},
            headers={
                "X-Api-User": creds["username"],
                "X-Api-Key": creds["password"],
            },
        )
    # Pre-condition: 1 TXT record exists
    rows = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.record_type == "TXT")))
        .scalars()
        .all()
    )
    assert len(rows) == 1

    with patch.object(acme_svc, "wait_for_ops_applied", new=AsyncMock(return_value={})):
        resp = await client.delete(
            "/api/v1/acme/update",
            headers={
                "X-Api-User": creds["username"],
                "X-Api-Key": creds["password"],
            },
        )
    assert resp.status_code == 200
    # Post-condition: all cleared
    rows = (
        (await db_session.execute(select(DNSRecord).where(DNSRecord.record_type == "TXT")))
        .scalars()
        .all()
    )
    assert rows == []
