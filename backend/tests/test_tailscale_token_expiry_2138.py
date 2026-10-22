"""Tailscale API access token expiry: read, store, warn, alert (#2138).

The token is capped at 90 days by Tailscale and, once it lapses, every sync
gets HTTP 401. These tests pin:

* the read against the ``getKey`` response shape from Tailscale's published
  OpenAPI spec (``expires`` / ``invalid``), with the key id taken from the
  ``tskey-api-<keyId>-<secret>`` token — over a mocked transport;
* that a failed read never clobbers a stored (or operator-entered) date;
* ``secret_expiring`` firing inside the threshold, on an expired token, and
  on an HTTP 401 sync error with no date at all;
* the daily refresh being idempotent;
* the REST surface (create / rotate / test-connection) and both dashboard
  surfaces carrying the credential state, and the MCP tool exposing it.
"""

from __future__ import annotations

import importlib.util
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_str
from app.core.security import create_access_token, hash_password
from app.models.alerts import AlertRule
from app.models.auth import User
from app.models.feature_module import FeatureModule
from app.models.ipam import IPSpace
from app.models.settings import PlatformSettings
from app.models.tailscale import TailscaleTenant
from app.services import alerts
from app.services.integration_credentials import credential_status
from app.services.tailscale import token_expiry
from app.services.tailscale.client import AUTH_REJECTED_PREFIX, is_auth_rejected
from app.services.tailscale.token_expiry import (
    TokenExpiryRead,
    apply_operator_expiry,
    apply_read,
    fetch_token_expiry,
    key_id_from_token,
    parse_key_expiry,
)

# ``app.api.v1.tailscale`` re-exports ``router`` (the APIRouter), which
# shadows the submodule under attribute access — fetch the module itself.
TS_ROUTER = importlib.import_module("app.api.v1.tailscale.router")

# A token in the documented shape; the secret half is filler.
TOKEN = "tskey-api-k123456CNTRL-" + "s" * 32

# The ``Key`` example from Tailscale's OpenAPI spec (getKey response).
SPEC_KEY = {
    "id": "k123456CNTRL",
    "keyType": "api",
    "created": "2021-12-09T23:22:39Z",
    "expires": "2022-03-09T23:22:39Z",
    "invalid": False,
    "description": "dev access",
    "userId": "uscwcTtzzo11DEVEL",
}


# ── Pure parsing ─────────────────────────────────────────────────────


def test_key_id_is_the_segment_after_tskey_api() -> None:
    assert key_id_from_token(TOKEN) == "k123456CNTRL"
    assert key_id_from_token("  " + TOKEN + "\n") == "k123456CNTRL"


@pytest.mark.parametrize(
    "token",
    [
        "",
        "tskey-client-k123-secret",  # OAuth client secret: no expiry to read
        "tskey-auth-k123-secret",
        "tskey-api-",
        "tskey-api-k12/../x-secret",  # never let a token shape a path
        "not-a-tailscale-token",
    ],
)
def test_non_access_tokens_have_no_key_id(token: str) -> None:
    assert key_id_from_token(token) is None


def test_parse_reads_expires_from_the_spec_example() -> None:
    read = parse_key_expiry(SPEC_KEY)
    assert read.ok
    assert read.expires_at == datetime(2022, 3, 9, 23, 22, 39, tzinfo=UTC)
    assert read.invalid is False


@pytest.mark.parametrize(
    "payload",
    [
        None,
        [],
        {"id": "k1"},  # no expires
        {"expires": ""},
        {"expires": "next tuesday"},
        {"expires": "0001-01-01T00:00:00Z"},  # Go zero time = never
    ],
)
def test_parse_reports_unreadable_without_raising(payload: Any) -> None:
    read = parse_key_expiry(payload)
    assert read.expires_at is None
    assert read.note


def test_parse_carries_the_invalid_flag() -> None:
    read = parse_key_expiry({**SPEC_KEY, "invalid": True})
    assert read.ok and read.invalid


# ── The HTTP read, over a mocked transport ───────────────────────────


@pytest.mark.asyncio
async def test_fetch_calls_get_key_with_the_same_token() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=SPEC_KEY)

    read = await fetch_token_expiry(
        api_key=TOKEN, tailnet="-", transport=httpx.MockTransport(handler)
    )
    assert read.expires_at == datetime(2022, 3, 9, 23, 22, 39, tzinfo=UTC)
    assert len(seen) == 1
    assert seen[0].url.host == "api.tailscale.com"
    assert seen[0].url.path == "/api/v2/tailnet/-/keys/k123456CNTRL"
    assert seen[0].headers["Authorization"] == f"Bearer {TOKEN}"


@pytest.mark.asyncio
@pytest.mark.parametrize(("status", "invalid"), [(401, True), (403, False), (404, False)])
async def test_fetch_error_statuses_are_unread(status: int, invalid: bool) -> None:
    read = await fetch_token_expiry(
        api_key=TOKEN,
        tailnet="-",
        transport=httpx.MockTransport(lambda r: httpx.Response(status, text="nope")),
    )
    assert read.expires_at is None
    assert read.invalid is invalid
    assert str(status) in (read.note or "")
    assert TOKEN not in (read.note or "")


@pytest.mark.asyncio
async def test_fetch_network_error_is_unread_and_never_echoes_the_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"boom {request.headers['Authorization']}")

    read = await fetch_token_expiry(
        api_key=TOKEN, tailnet="-", transport=httpx.MockTransport(handler)
    )
    assert read.expires_at is None
    assert TOKEN not in (read.note or "")


@pytest.mark.asyncio
async def test_fetch_never_raises_on_a_non_httpx_error() -> None:
    """``httpx.InvalidURL`` and friends derive from Exception, not
    ``HTTPError``; one bad tenant must not abort the daily refresh."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise RuntimeError(f"boom {request.headers['Authorization']}")

    read = await fetch_token_expiry(
        api_key=TOKEN, tailnet="-", transport=httpx.MockTransport(handler)
    )
    assert read.expires_at is None
    assert TOKEN not in (read.note or "")
    assert "RuntimeError" in (read.note or "")


@pytest.mark.asyncio
async def test_fetch_quotes_the_tailnet_into_one_path_segment() -> None:
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.raw_path.decode())
        return httpx.Response(200, json=SPEC_KEY)

    await fetch_token_expiry(
        api_key=TOKEN, tailnet="a/../b?x", transport=httpx.MockTransport(handler)
    )
    assert seen == ["/api/v2/tailnet/a%2F..%2Fb%3Fx/keys/k123456CNTRL"]


@pytest.mark.asyncio
async def test_fetch_skips_the_network_for_a_non_access_token() -> None:
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not be called")

    read = await fetch_token_expiry(
        api_key="tskey-client-kabc-secret", tailnet="-", transport=httpx.MockTransport(handler)
    )
    assert read.expires_at is None and read.note


# ── Storing a read, and the operator fallback ────────────────────────


def _tenant(**kw: Any) -> TailscaleTenant:
    return TailscaleTenant(name="t", tailnet="-", **kw)


def test_failed_read_keeps_the_operator_date() -> None:
    t = _tenant()
    when = datetime(2027, 1, 1, tzinfo=UTC)
    apply_operator_expiry(t, when)
    assert (t.api_key_expires_at, t.api_key_expiry_source) == (when, "operator")
    assert apply_read(t, TokenExpiryRead(None, note="403")) is False
    assert (t.api_key_expires_at, t.api_key_expiry_source) == (when, "operator")


def test_successful_read_replaces_the_operator_date() -> None:
    t = _tenant()
    apply_operator_expiry(t, datetime(2027, 1, 1, tzinfo=UTC))
    api_when = datetime(2026, 12, 1, tzinfo=UTC)
    assert apply_read(t, TokenExpiryRead(api_when)) is True
    assert (t.api_key_expires_at, t.api_key_expiry_source) == (api_when, "api")
    # Same answer again changes nothing.
    assert apply_read(t, TokenExpiryRead(api_when)) is False


def test_operator_clear_resets_to_unknown() -> None:
    t = _tenant()
    apply_operator_expiry(t, datetime(2027, 1, 1))  # naive → UTC
    assert t.api_key_expires_at is not None and t.api_key_expires_at.tzinfo is not None
    apply_operator_expiry(t, None)
    assert t.api_key_expires_at is None and t.api_key_expiry_source is None


# ── Credential state ─────────────────────────────────────────────────


def test_credential_states() -> None:
    now = datetime(2026, 10, 18, tzinfo=UTC)
    assert credential_status(expires_at=None, rejected=False, now=now).state == "unknown"
    assert (
        credential_status(expires_at=now + timedelta(days=60), rejected=False, now=now).state
        == "ok"
    )
    s = credential_status(expires_at=now + timedelta(days=10), rejected=False, now=now)
    assert (s.state, s.days_left) == ("expiring", 10)
    s = credential_status(expires_at=now - timedelta(days=2), rejected=False, now=now)
    assert (s.state, s.days_left) == ("expired", -2)
    # A 401 beats any recorded date, including a far-future one.
    s = credential_status(expires_at=now + timedelta(days=60), rejected=True, now=now)
    assert s.state == "rejected"


def test_auth_rejected_matches_both_401_messages() -> None:
    assert is_auth_rejected(f"{AUTH_REJECTED_PREFIX} — API key invalid, expired or revoked")
    assert not is_auth_rejected("HTTP 403 — API key lacks permission")
    assert not is_auth_rejected(None)
    assert not is_auth_rejected("")


# ── secret_expiring ──────────────────────────────────────────────────


async def _settings(db: AsyncSession, *, tailscale: bool = True) -> None:
    ps = await db.get(PlatformSettings, 1)
    if ps is None:
        ps = PlatformSettings(id=1)
        db.add(ps)
    ps.integration_tailscale_enabled = tailscale
    await db.flush()


async def _space(db: AsyncSession) -> IPSpace:
    space = IPSpace(name=f"ts-exp-{uuid.uuid4().hex[:6]}", description="")
    db.add(space)
    await db.flush()
    return space


async def _db_tenant(
    db: AsyncSession,
    space: IPSpace,
    *,
    expires_in_days: float | None = None,
    error: str | None = None,
    enabled: bool = True,
    source: str | None = "api",
    tailnet: str = "-",
) -> TailscaleTenant:
    t = TailscaleTenant(
        name=f"ts-{uuid.uuid4().hex[:6]}",
        tailnet=tailnet,
        api_key_encrypted=encrypt_str(TOKEN),
        ipam_space_id=space.id,
        enabled=enabled,
        last_sync_error=error,
    )
    if expires_in_days is not None:
        t.api_key_expires_at = datetime.now(UTC) + timedelta(days=expires_in_days)
        t.api_key_expiry_source = source
    db.add(t)
    await db.flush()
    return t


def _rule(**kw: Any) -> AlertRule:
    return AlertRule(
        name=f"r-{uuid.uuid4().hex[:6]}",
        rule_type="secret_expiring",
        severity=kw.pop("severity", "warning"),
        threshold_days=kw.pop("threshold_days", 30),
        enabled=True,
    )


@pytest.mark.asyncio
async def test_secret_expiring_fires_inside_the_threshold(db_session: AsyncSession) -> None:
    await _settings(db_session)
    space = await _space(db_session)
    near = await _db_tenant(db_session, space, expires_in_days=10.5)
    far = await _db_tenant(db_session, space, expires_in_days=80)
    unknown = await _db_tenant(db_session, space)
    await db_session.commit()

    subjects = await alerts._matching_secret_expiring_subjects(
        db_session, _rule(), datetime.now(UTC)
    )
    by_id = {sid: (disp, msg, sev) for sid, disp, msg, sev in subjects}
    assert f"tailscale_tenant:{near.id}" in by_id
    assert f"tailscale_tenant:{far.id}" not in by_id
    assert f"tailscale_tenant:{unknown.id}" not in by_id
    _disp, msg, sev = by_id[f"tailscale_tenant:{near.id}"]
    assert "expires in 10 day(s)" in msg and "read from Tailscale" in msg
    assert sev == "warning"
    assert TOKEN not in msg


@pytest.mark.asyncio
async def test_secret_expiring_fires_critical_once_expired(db_session: AsyncSession) -> None:
    await _settings(db_session)
    space = await _space(db_session)
    gone = await _db_tenant(db_session, space, expires_in_days=-3, source="operator")
    await db_session.commit()

    subjects = await alerts._matching_secret_expiring_subjects(
        db_session, _rule(), datetime.now(UTC)
    )
    hit = next(s for s in subjects if s[0] == f"tailscale_tenant:{gone.id}")
    assert "has expired" in hit[2] and "as entered on the tenant" in hit[2]
    assert hit[3] == "critical"


@pytest.mark.asyncio
async def test_secret_expiring_fires_critical_on_a_401_with_no_date(
    db_session: AsyncSession,
) -> None:
    await _settings(db_session)
    space = await _space(db_session)
    rejected = await _db_tenant(
        db_session,
        space,
        error=f"{AUTH_REJECTED_PREFIX} — API key invalid, expired or revoked. Generate …",
    )
    forbidden = await _db_tenant(db_session, space, error="HTTP 403 — no permission")
    await db_session.commit()

    subjects = await alerts._matching_secret_expiring_subjects(
        db_session, _rule(), datetime.now(UTC)
    )
    by_id = {s[0]: s for s in subjects}
    hit = by_id[f"tailscale_tenant:{rejected.id}"]
    assert hit[3] == "critical" and "HTTP 401" in hit[2] and rejected.name in hit[2]
    assert f"tailscale_tenant:{forbidden.id}" not in by_id


@pytest.mark.asyncio
async def test_secret_expiring_ignores_disabled_tenants_and_a_disabled_integration(
    db_session: AsyncSession,
) -> None:
    await _settings(db_session, tailscale=False)
    space = await _space(db_session)
    on = await _db_tenant(db_session, space, expires_in_days=2)
    off = await _db_tenant(db_session, space, expires_in_days=2, enabled=False)
    await db_session.commit()
    now = datetime.now(UTC)

    ids = {s[0] for s in await alerts._matching_secret_expiring_subjects(db_session, _rule(), now)}
    assert f"tailscale_tenant:{on.id}" not in ids  # integration off

    await _settings(db_session, tailscale=True)
    await db_session.commit()
    ids = {s[0] for s in await alerts._matching_secret_expiring_subjects(db_session, _rule(), now)}
    assert f"tailscale_tenant:{on.id}" in ids
    assert f"tailscale_tenant:{off.id}" not in ids


_MIGRATION = (
    Path(__file__).resolve().parents[1]
    / "alembic"
    / "versions"
    / "c8e2a5f71d39_tailscale_api_key_expiry.py"
)


def _load_migration() -> Any:
    spec = importlib.util.spec_from_file_location("_mig_c8e2a5f71d39", _MIGRATION)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.asyncio
async def test_migration_seed_creates_one_enabled_rule_and_respects_an_existing_one(
    db_session: AsyncSession,
) -> None:
    """The rule is seeded by the migration's own statement, once."""
    from sqlalchemy import func, select  # noqa: PLC0415

    mig = _load_migration()

    async def count() -> int:
        return int(
            await db_session.scalar(
                select(func.count())
                .select_from(AlertRule)
                .where(AlertRule.rule_type == "secret_expiring")
            )
            or 0
        )

    async def run_seed() -> None:
        await db_session.execute(mig.SEED_SECRET_EXPIRING_RULE_SQL, mig.seed_params())
        await db_session.commit()

    await run_seed()
    await run_seed()
    assert await count() == 1
    rule = await db_session.scalar(
        select(AlertRule).where(AlertRule.rule_type == "secret_expiring")
    )
    assert rule is not None
    assert rule.enabled and rule.threshold_days == 30 and rule.severity == "warning"
    assert rule.name == "Credential expiring or rejected"
    assert rule.notify_syslog and rule.notify_webhook and not rule.notify_smtp

    # An operator's own rule of the type, under another name, suppresses it.
    await db_session.delete(rule)
    db_session.add(_rule())
    await db_session.commit()
    await run_seed()
    assert await count() == 1


def test_secret_expiring_rule_is_not_seeded_at_startup() -> None:
    """A startup seed keyed on "none exists" brings a DELETED rule back on
    every restart. The rule is seeded by the migration only."""
    import inspect  # noqa: PLC0415

    import app.main as main_mod  # noqa: PLC0415

    src = inspect.getsource(main_mod)
    assert "seed_secret_expiring_alert_rule" not in src
    assert not hasattr(alerts, "seed_secret_expiring_alert_rule")


# ── Daily refresh ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_daily_refresh_is_idempotent_and_keeps_dates_on_failure(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.tasks.tailscale_sync import refresh_token_expiry  # noqa: PLC0415

    await _settings(db_session)
    space = await _space(db_session)
    readable = await _db_tenant(db_session, space, tailnet="readable")
    manual = await _db_tenant(
        db_session, space, expires_in_days=40, source="operator", tailnet="manual"
    )
    manual_when = manual.api_key_expires_at
    await db_session.commit()
    api_when = datetime(2026, 12, 24, 12, 0, tzinfo=UTC)

    async def fake_fetch(*, api_key: str, tailnet: str, **_: Any) -> TokenExpiryRead:
        assert api_key == TOKEN
        # One tenant's keys endpoint answers; the other's 403s.
        if tailnet == "readable":
            return TokenExpiryRead(api_when)
        return TokenExpiryRead(None, note="keys endpoint answered HTTP 403")

    monkeypatch.setattr(token_expiry, "fetch_token_expiry", fake_fetch)

    first = await refresh_token_expiry(db_session)
    assert first == {"status": "ok", "read": 1, "changed": 1, "unread": 1}
    second = await refresh_token_expiry(db_session)
    assert second == {"status": "ok", "read": 1, "changed": 0, "unread": 1}

    await db_session.refresh(readable)
    await db_session.refresh(manual)
    assert (readable.api_key_expires_at, readable.api_key_expiry_source) == (api_when, "api")
    assert (manual.api_key_expires_at, manual.api_key_expiry_source) == (
        manual_when,
        "operator",
    )


@pytest.mark.asyncio
async def test_daily_refresh_is_a_noop_with_the_integration_off(
    db_session: AsyncSession,
) -> None:
    from app.tasks.tailscale_sync import refresh_token_expiry  # noqa: PLC0415

    await _settings(db_session, tailscale=False)
    await db_session.commit()
    assert await refresh_token_expiry(db_session) == {"status": "disabled"}


# ── REST surface ─────────────────────────────────────────────────────


async def _headers(db: AsyncSession) -> dict[str, str]:
    user = User(
        username=f"a-{uuid.uuid4().hex[:8]}",
        email=f"{uuid.uuid4().hex[:8]}@example.test",
        display_name="Admin",
        hashed_password=hash_password("x" * 12),
        auth_source="local",
        is_superadmin=True,
    )
    db.add(user)
    if await db.get(FeatureModule, "integrations.tailscale") is None:
        db.add(FeatureModule(id="integrations.tailscale", enabled=True))
    await _settings(db)
    await db.flush()
    return {"Authorization": f"Bearer {create_access_token(str(user.id))}"}


def _patch_fetch(monkeypatch: pytest.MonkeyPatch, read: TokenExpiryRead) -> list[str]:
    seen: list[str] = []

    async def fake(*, api_key: str, tailnet: str, **_: Any) -> TokenExpiryRead:
        seen.append(api_key)
        return read

    monkeypatch.setattr(TS_ROUTER, "fetch_token_expiry", fake)
    return seen


@pytest.mark.asyncio
async def test_create_uses_the_api_date_over_the_operator_date(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = await _headers(db_session)
    space = await _space(db_session)
    await db_session.commit()
    api_when = datetime(2026, 12, 1, 8, 0, tzinfo=UTC)
    seen = _patch_fetch(monkeypatch, TokenExpiryRead(api_when))

    r = await client.post(
        "/api/v1/tailscale/tenants",
        json={
            "name": f"t-{uuid.uuid4().hex[:6]}",
            "api_key": TOKEN,
            "ipam_space_id": str(space.id),
            "api_key_expires_at": "2027-01-16T00:00:00Z",
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert seen == [TOKEN]
    assert body["api_key_expiry_source"] == "api"
    assert body["api_key_expires_at"].startswith("2026-12-01T08:00:00")
    assert body["credential_state"] in ("ok", "expiring")
    assert TOKEN not in r.text


@pytest.mark.asyncio
async def test_create_falls_back_to_the_operator_date(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = await _headers(db_session)
    space = await _space(db_session)
    await db_session.commit()
    _patch_fetch(monkeypatch, TokenExpiryRead(None, note="keys endpoint answered HTTP 403"))

    r = await client.post(
        "/api/v1/tailscale/tenants",
        json={
            "name": f"t-{uuid.uuid4().hex[:6]}",
            "api_key": TOKEN,
            "ipam_space_id": str(space.id),
            "api_key_expires_at": "2099-01-16T00:00:00Z",
        },
        headers=h,
    )
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["api_key_expiry_source"] == "operator"
    assert body["api_key_expires_at"].startswith("2099-01-16")
    assert body["credential_state"] == "ok"


@pytest.mark.asyncio
async def test_rotating_the_key_resets_expiry_and_clears_the_401(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = await _headers(db_session)
    space = await _space(db_session)
    t = await _db_tenant(
        db_session,
        space,
        expires_in_days=-1,
        error=f"{AUTH_REJECTED_PREFIX} — API key invalid, expired or revoked.",
    )
    await db_session.commit()
    _patch_fetch(monkeypatch, TokenExpiryRead(None, note="403"))

    listed = await client.get("/api/v1/tailscale/tenants", headers=h)
    row = next(x for x in listed.json() if x["id"] == str(t.id))
    assert row["credential_state"] == "rejected"

    new_token = "tskey-api-kNEW-" + "n" * 32
    r = await client.put(
        f"/api/v1/tailscale/tenants/{t.id}", json={"api_key": new_token}, headers=h
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["api_key_expires_at"] is None
    assert body["api_key_expiry_source"] is None
    assert body["last_sync_error"] is None
    assert body["credential_state"] == "unknown"
    assert new_token not in r.text


@pytest.mark.asyncio
async def test_operator_can_set_the_date_without_rotating(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = await _headers(db_session)
    space = await _space(db_session)
    t = await _db_tenant(db_session, space)
    await db_session.commit()
    seen = _patch_fetch(monkeypatch, TokenExpiryRead(None))

    r = await client.put(
        f"/api/v1/tailscale/tenants/{t.id}",
        json={"api_key_expires_at": "2099-03-01T00:00:00Z"},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["api_key_expiry_source"] == "operator"
    assert seen == []  # no rotation, no read


@pytest.mark.asyncio
async def test_test_connection_stores_expiry_only_for_the_stored_key(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    h = await _headers(db_session)
    space = await _space(db_session)
    t = await _db_tenant(
        db_session, space, error=f"{AUTH_REJECTED_PREFIX} — API key invalid, expired or revoked."
    )
    await db_session.commit()
    api_when = datetime(2026, 11, 30, tzinfo=UTC)
    _patch_fetch(monkeypatch, TokenExpiryRead(api_when))

    async def fake_probe(*, tailnet: str, api_key: str) -> Any:
        return TS_ROUTER.TestConnectionResponse(ok=True, message="Connected", device_count=1)

    monkeypatch.setattr(TS_ROUTER, "_probe", fake_probe)

    # A typed, unsaved key: reported, not stored, and the stored 401 stays.
    r = await client.post(
        "/api/v1/tailscale/tenants/test",
        json={"tenant_id": str(t.id), "api_key": "tskey-api-kOTHER-" + "o" * 30},
        headers=h,
    )
    assert r.status_code == 200, r.text
    assert r.json()["api_key_expires_at"].startswith("2026-11-30")
    await db_session.refresh(t)
    assert t.api_key_expires_at is None
    assert is_auth_rejected(t.last_sync_error)

    # The stored key: stored, and the 401 cleared.
    r = await client.post(
        "/api/v1/tailscale/tenants/test", json={"tenant_id": str(t.id)}, headers=h
    )
    assert r.status_code == 200, r.text
    await db_session.refresh(t)
    assert t.api_key_expires_at == api_when and t.api_key_expiry_source == "api"
    assert t.last_sync_error is None


# ── Dashboard + MCP ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_integrations_dashboard_carries_the_credential_state(
    client: AsyncClient, db_session: AsyncSession
) -> None:
    h = await _headers(db_session)
    space = await _space(db_session)
    expiring = await _db_tenant(db_session, space, expires_in_days=5.5)
    await db_session.commit()

    r = await client.get("/api/v1/dashboards/integrations/summary", headers=h)
    assert r.status_code == 200, r.text
    panel = next(p for p in r.json()["panels"] if p["kind"] == "tailscale")
    row = next(x for x in panel["targets"] if x["id"] == str(expiring.id))
    assert row["credential_state"] == "expiring"
    assert row["credential_days_left"] == 5
    assert row["credential_expires_at"] is not None
    # Integrations without a recorded expiry report null, not "ok".
    other = [p for p in r.json()["panels"] if p["kind"] != "tailscale"]
    assert all(t["credential_state"] is None for p in other for t in p["targets"])


@pytest.mark.asyncio
async def test_list_tailscale_targets_exposes_the_expiry(db_session: AsyncSession) -> None:
    from app.services.ai.tools.integrations import (  # noqa: PLC0415
        ListTailscaleTargetsArgs,
        list_tailscale_targets,
    )

    space = await _space(db_session)
    t = await _db_tenant(db_session, space, expires_in_days=12.5)
    await db_session.commit()

    rows = await list_tailscale_targets(
        db_session, None, ListTailscaleTargetsArgs(search=t.name)  # type: ignore[arg-type]
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["api_key_expires_at"] is not None
    assert row["api_key_expiry_source"] == "api"
    assert row["credential_state"] == "expiring"
    assert row["credential_days_left"] == 12
    assert "api_key" not in row and TOKEN not in str(row)


# ── Migration ────────────────────────────────────────────────────────


def test_migration_adds_the_columns_the_model_declares() -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "alembic"
        / "versions"
        / "c8e2a5f71d39_tailscale_api_key_expiry.py"
    )
    src = path.read_text()
    # The parent revision is re-pointed whenever another migration merges
    # first, so pin this migration's own id rather than its down_revision.
    assert 'revision = "c8e2a5f71d39"' in src
    cols = TailscaleTenant.__table__.columns
    for name in ("api_key_expires_at", "api_key_expiry_source"):
        assert f'"{name}"' in src
        assert cols[name].nullable  # NULL = unknown, no backfill
    assert "ck_tailscale_tenant_api_key_expiry_source" in src
