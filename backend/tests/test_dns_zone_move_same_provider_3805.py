"""#3805 — moving a zone between two groups whose agentless servers reach
the SAME provider deleted the zone at the provider.

The commit pushes ``create`` into the target group (the provider already
holds the zone, so it is adopted) and then ``delete`` into the source group.
With one provider behind a server on each side, that delete removed the only
copy while the database said the zone was live in the new group.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import encrypt_dict
from app.core.security import create_access_token, hash_password
from app.drivers.dns.route53 import Route53DNSDriver
from app.models.auth import User
from app.models.dns import DNSServer, DNSServerGroup, DNSZone


class _FakeProvider(Route53DNSDriver):
    """Route 53 identity rules, with the provider's zone store in memory."""

    def __init__(self) -> None:
        self.zones: set[tuple[str | None, str]] = set()
        self.calls: list[tuple[str, str]] = []

    async def apply_zone_change(self, server: Any, zone: Any, op: str, **_: Any) -> bool:
        self.calls.append((server.name, op))
        key = (self.provider_identity(server), zone.name)
        if op == "create":
            if key in self.zones:
                return False
            self.zones.add(key)
            return True
        if key not in self.zones:
            return False
        self.zones.discard(key)
        return True


@pytest.fixture
def provider(monkeypatch: pytest.MonkeyPatch) -> _FakeProvider:
    fake = _FakeProvider()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    return fake


async def _token(db: AsyncSession) -> str:
    u = User(
        username=f"root{uuid.uuid4().hex[:6]}",
        email=f"{uuid.uuid4().hex[:6]}@example.com",
        display_name="root",
        hashed_password=hash_password("password123"),
        is_superadmin=True,
    )
    db.add(u)
    await db.flush()
    return create_access_token(str(u.id))


async def _group(db: AsyncSession, name: str) -> DNSServerGroup:
    g = DNSServerGroup(name=name, description="")
    db.add(g)
    await db.flush()
    return g


async def _server(
    db: AsyncSession, group: DNSServerGroup, name: str, creds: dict[str, str] | None
) -> DNSServer:
    s = DNSServer(
        group_id=group.id,
        name=name,
        driver="route53",
        host=name,
        port=53,
        roles=["authoritative"],
        status="active",
        credentials_encrypted=encrypt_dict(creds) if creds is not None else None,
    )
    db.add(s)
    await db.flush()
    return s


async def _setup(
    db: AsyncSession, src_creds: dict[str, str], dst_creds: dict[str, str]
) -> tuple[DNSZone, DNSServerGroup]:
    src = await _group(db, f"src-{uuid.uuid4().hex[:6]}")
    dst = await _group(db, f"dst-{uuid.uuid4().hex[:6]}")
    await _server(db, src, "src-ns", src_creds)
    await _server(db, dst, "dst-ns", dst_creds)
    zone = DNSZone(group_id=src.id, name="example.com.", zone_type="primary")
    db.add(zone)
    await db.flush()
    return zone, dst


async def _move(client: AsyncClient, token: str, zone: DNSZone, dst: DNSServerGroup):
    return await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/move/commit",
        json={
            "target_group_id": str(dst.id),
            "confirmation_zone_name": zone.name,
            "acknowledgements": [],
        },
        headers={"Authorization": f"Bearer {token}"},
    )


_A = {"access_key_id": "AKIA-ONE", "secret_access_key": "s"}
_B = {"access_key_id": "AKIA-TWO", "secret_access_key": "s"}


@pytest.mark.asyncio
async def test_same_provider_move_keeps_the_zone_at_the_provider(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    provider.zones.add(("route53:key:AKIA-ONE", zone.name))

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert provider.zones == {("route53:key:AKIA-ONE", zone.name)}
    assert ("src-ns", "delete") not in provider.calls
    assert ("dst-ns", "create") in provider.calls


@pytest.mark.asyncio
async def test_same_provider_preview_says_the_source_copy_is_kept(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _A)
    resp = await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/move/preview",
        json={"target_group_id": str(dst.id)},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    assert any("Source copy kept on 'src-ns'" in w for w in resp.json()["warnings"])


@pytest.mark.asyncio
async def test_different_providers_still_delete_the_source_copy(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)
    provider.zones.add(("route53:key:AKIA-ONE", zone.name))

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert provider.zones == {("route53:key:AKIA-TWO", zone.name)}
    assert ("src-ns", "delete") in provider.calls


@pytest.mark.asyncio
async def test_unknown_identity_does_not_delete_and_warns(
    client: AsyncClient,
    db_session: AsyncSession,
    provider: _FakeProvider,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, {"secret_access_key": "s"}, _B)  # no key id: unknown
    provider.zones.add(("route53:key:AKIA-TWO", zone.name))

    warned: list[dict[str, Any]] = []
    from app.services.dns import zone_move

    monkeypatch.setattr(
        zone_move.logger, "warning", lambda event, **kw: warned.append({"event": event, **kw})
    )

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert ("src-ns", "delete") not in provider.calls
    assert any(
        w["event"] == "dns.zone_move.provider_identity_unknown" and w["source_server"] == "src-ns"
        for w in warned
    )


class _OneAccount(_FakeProvider):
    """Two different keys on ONE account: the store ignores the identity.

    This is the case the identity cannot see — two IAM keys on one AWS
    account, two Cloudflare tokens, an IP and a hostname for one Technitium,
    two domain controllers sharing an AD-integrated zone.
    """

    async def apply_zone_change(self, server: Any, zone: Any, op: str, **_: Any) -> bool:
        self.calls.append((server.name, op))
        key = (None, zone.name)
        if op == "create":
            if key in self.zones:
                return False
            self.zones.add(key)
            return True
        if key not in self.zones:
            return False
        self.zones.discard(key)
        return True


@pytest.mark.asyncio
async def test_one_account_behind_two_identities_keeps_the_zone(
    client: AsyncClient, db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = _OneAccount()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)
    fake.zones.add((None, zone.name))

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    # The target found the zone already there, so the source delete would
    # have removed the copy it just adopted.
    assert fake.zones == {(None, zone.name)}
    assert ("src-ns", "delete") not in fake.calls
    assert any("already held the zone" in w for w in resp.json()["warnings"])


@pytest.mark.asyncio
async def test_preview_with_distinct_identities_says_the_delete_is_conditional(
    client: AsyncClient, db_session: AsyncSession, provider: _FakeProvider
) -> None:
    token = await _token(db_session)
    zone, dst = await _setup(db_session, _A, _B)
    resp = await client.post(
        f"/api/v1/dns/groups/{zone.group_id}/zones/{zone.id}/move/preview",
        json={"target_group_id": str(dst.id)},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    assert any("Source copy on 'src-ns' is deleted unless" in w for w in resp.json()["warnings"])


def _row(host: str, creds: dict[str, Any]) -> DNSServer:
    return DNSServer(name="x", host=host, credentials_encrypted=encrypt_dict(creds))


def test_technitium_identity_is_the_normalised_api_root() -> None:
    from app.drivers.dns.technitium_api import TechnitiumAPIDriver

    d = TechnitiumAPIDriver()
    a = d.provider_identity(_row("a", {"api_url": "http://DNS.example.com:5380/", "token": "t1"}))
    b = d.provider_identity(
        _row("b", {"api_url": "http://dns.example.com:5380/api/zones", "token": "t2"})
    )
    c = d.provider_identity(_row("c", {"api_url": "http://other.example.com:5380", "token": "t"}))
    assert a is not None and a == b
    assert c is not None and c != a
    # The token never takes part in (or leaks into) the identity.
    assert "t1" not in a
    assert d.provider_identity(_row("d", {"token": "t"})) is None


def test_windows_identity_is_the_ad_domain() -> None:
    from app.drivers.dns.windows import WindowsDNSDriver

    d = WindowsDNSDriver()
    creds = {"username": "u", "password": "secret-pw"}
    a = d.provider_identity(_row("DC1.corp.example.", creds))
    b = d.provider_identity(_row("dc1.corp.example", {**creds, "winrm_port": 5985}))
    tls = d.provider_identity(_row("dc1.corp.example", {**creds, "use_tls": True}))
    # #3888: the AD domain (DNS suffix of the host), not host + port.
    assert a == b == tls == "windows_dns:ad:corp.example"
    assert "secret-pw" not in (a or "")
    assert d.provider_identity(_row("", creds)) is None


# ── Technitium: a zone holding records moves between groups on ONE daemon ──

from app.drivers.dns.technitium_api import TechnitiumAPIDriver  # noqa: E402

_T_URL = "https://tech.test:53443"
_REC_OF_OURS = [{"type": "SOA", "name": "example.com"}, {"type": "A", "name": "www.example.com"}]


class _TechStore(TechnitiumAPIDriver):
    """Real adoption guard; Technitium's HTTP replaced by an in-memory daemon."""

    def __init__(self) -> None:
        self.zones: dict[str, list[dict[str, Any]]] = {}
        self.deleted: list[str] = []

    async def _call(self, client: Any, path: str, what: str, params: Any = None) -> Any:
        bare = params["zone"]
        if path == "zones/create":
            if bare in self.zones:
                return {}  # "already exists" is the empty body (#1537)
            self.zones[bare] = [{"type": "SOA", "name": bare}]
            return {"domain": bare}
        if path == "zones/delete":
            self.deleted.append(bare)
            self.zones.pop(bare, None)
            return {}
        return {"records": self.zones[bare]}  # zones/records/get

    async def _walk_zones(self, creds: Any) -> list[dict[str, Any]]:
        return [{"name": z, "type": "Primary"} for z in self.zones]

    def _client(self, *a: Any, **k: Any) -> Any:
        class _C:
            async def __aenter__(self) -> Any:
                return self

            async def __aexit__(self, *e: Any) -> bool:
                return False

        return _C()


async def _tech_setup(
    db: AsyncSession, src_url: str, dst_url: str
) -> tuple[DNSZone, DNSServerGroup]:
    src = await _group(db, f"tsrc-{uuid.uuid4().hex[:6]}")
    dst = await _group(db, f"tdst-{uuid.uuid4().hex[:6]}")
    for g, url, name in ((src, src_url, "t-src"), (dst, dst_url, "t-dst")):
        s = await _server(db, g, name, {"api_url": url, "api_token": "t"})
        s.driver = "technitium_api"
    zone = DNSZone(group_id=src.id, name="example.com.", zone_type="primary")
    db.add(zone)
    await db.flush()
    return zone, dst


@pytest.fixture
def tech(monkeypatch: pytest.MonkeyPatch) -> _TechStore:
    fake = _TechStore()
    monkeypatch.setattr("app.drivers.dns.get_driver", lambda name: fake)
    return fake


@pytest.mark.asyncio
async def test_technitium_same_daemon_move_of_a_zone_with_records_commits(
    client: AsyncClient, db_session: AsyncSession, tech: _TechStore
) -> None:
    token = await _token(db_session)
    zone, dst = await _tech_setup(db_session, _T_URL, _T_URL + "/")
    tech.zones["example.com"] = list(_REC_OF_OURS)

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 200, resp.text
    assert tech.deleted == []
    assert tech.zones["example.com"] == _REC_OF_OURS


@pytest.mark.asyncio
async def test_technitium_other_daemon_still_refuses_foreign_records(
    client: AsyncClient, db_session: AsyncSession, tech: _TechStore
) -> None:
    token = await _token(db_session)
    zone, dst = await _tech_setup(db_session, _T_URL, "https://other.test:53443")
    tech.zones["example.com"] = list(_REC_OF_OURS)

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 409, resp.text
    assert "did not create" in resp.text
    assert ".." not in resp.text


@pytest.mark.asyncio
async def test_technitium_plain_create_onto_a_non_empty_zone_still_refuses(
    client: AsyncClient, db_session: AsyncSession, tech: _TechStore
) -> None:
    token = await _token(db_session)
    g = await _group(db_session, f"plain-{uuid.uuid4().hex[:6]}")
    s = await _server(db_session, g, "t-one", {"api_url": _T_URL, "api_token": "t"})
    s.driver = "technitium_api"
    await db_session.flush()
    tech.zones["example.com"] = list(_REC_OF_OURS)

    resp = await client.post(
        f"/api/v1/dns/groups/{g.id}/zones",
        json={"name": "example.com.", "zone_type": "primary"},
        headers={"Authorization": f"Bearer {token}"},
    )

    assert resp.status_code == 409, resp.text
    assert "did not create" in resp.text


@pytest.mark.asyncio
async def test_technitium_unknown_identity_still_refuses_foreign_records(
    client: AsyncClient,
    db_session: AsyncSession,
    tech: _TechStore,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same URL, but the identity cannot be derived: the guard still runs."""
    token = await _token(db_session)
    zone, dst = await _tech_setup(db_session, _T_URL, _T_URL)
    tech.zones["example.com"] = list(_REC_OF_OURS)
    monkeypatch.setattr(tech, "provider_identity", lambda server: None)

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 409, resp.text
    assert "did not create" in resp.text
    assert tech.deleted == []
    assert tech.zones["example.com"] == _REC_OF_OURS


@pytest.mark.asyncio
async def test_technitium_disabled_source_server_does_not_vouch_for_the_records(
    client: AsyncClient, db_session: AsyncSession, tech: _TechStore
) -> None:
    """A paused source server serves nothing, so it is no evidence the
    daemon's copy is SpatiumDDI's own: the target create keeps the guard."""
    from sqlalchemy import select

    token = await _token(db_session)
    zone, dst = await _tech_setup(db_session, _T_URL, _T_URL)
    src = (
        await db_session.execute(select(DNSServer).where(DNSServer.group_id == zone.group_id))
    ).scalar_one()
    src.is_enabled = False
    await db_session.flush()
    tech.zones["example.com"] = list(_REC_OF_OURS)

    resp = await _move(client, token, zone, dst)

    assert resp.status_code == 409, resp.text
    assert "did not create" in resp.text
    assert tech.zones["example.com"] == _REC_OF_OURS
