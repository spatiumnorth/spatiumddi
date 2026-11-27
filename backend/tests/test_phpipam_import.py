"""Tests for the phpIPAM one-shot IPAM importer (issue #4734).

Layers, mirroring the NetBox importer's test split (``test_netbox_import.py``):

* **Client + mapping unit tests** -- no DB. The client runs against an
  ``httpx.MockTransport``; the mappers against recorded-shape dicts.
* **Preview** -- ``preview_phpipam_import`` against a Postgres session with the
  client swapped for a fake that replays ``fixtures/phpipam/phpipam_16.json``
  (hand-written from the documented object shapes; no live phpIPAM). Asserts
  counts, space splitting, block/subnet classification, the warnings for what
  does not map, conflicts, and that **nothing is written**.
* **Commit** -- the shared pipeline end to end: provenance, audit, idempotent
  re-run, skip / overwrite, custom-field definitions, and the Trash rules.
* **API / MCP** -- the REST surface (auth, validation, 502, module gate,
  source mismatch) and the MCP tools.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import pytest
from httpx import AsyncClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import create_access_token, hash_password
from app.models.audit import AuditLog
from app.models.auth import User
from app.models.feature_module import FeatureModule
from app.models.ipam import CustomFieldDefinition, IPAddress, IPBlock, IPSpace, Subnet
from app.models.vlans import VLAN
from app.models.vrf import VRF
from app.services.netbox_import.canonical import ImportPreview
from app.services.netbox_import.commit import commit_import
from app.services.phpipam_import import client as ipam_client
from app.services.phpipam_import import mapping as ipam_mapping
from app.services.phpipam_import import preview as ipam_preview
from app.services.phpipam_import.client import (
    PhpipamClient,
    PhpipamClientError,
    _normalize_base,
)
from app.services.phpipam_import.preview import preview_phpipam_import

_FIXTURE = json.loads(
    (Path(__file__).parent / "fixtures" / "phpipam" / "phpipam_16.json").read_text()
)
_URL = "https://ipam.test"


# --------------------------------------------------------------------------- #
# Fakes + helpers.
# --------------------------------------------------------------------------- #


class FakePhpipamClient:
    """Drop-in for :class:`PhpipamClient` that replays the recorded fixture.

    An unknown list path answers ``[]``, the way phpIPAM answers an empty list
    (HTTP 404 turned into ``[]`` by the real client).
    """

    seen: list[dict[str, Any]] = []
    requested: list[str] = []

    def __init__(self, **kw: Any) -> None:
        FakePhpipamClient.seen.append(kw)

    async def __aenter__(self) -> FakePhpipamClient:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def get_list(self, path: str) -> list[dict[str, Any]]:
        FakePhpipamClient.requested.append(path)
        return list(_FIXTURE["lists"].get(path, []))

    async def get_data(self, path: str) -> Any:
        FakePhpipamClient.requested.append(path)
        return _FIXTURE["data"].get(path)


@pytest.fixture(autouse=True)
def _reset_fake() -> None:
    FakePhpipamClient.seen = []
    FakePhpipamClient.requested = []


def _patch_client(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ipam_preview, "PhpipamClient", FakePhpipamClient)
    # The package re-exports ``router`` (the APIRouter), shadowing the module.
    monkeypatch.setattr(
        sys.modules["app.api.v1.phpipam_import.router"], "PhpipamClient", FakePhpipamClient
    )


async def _make_admin(
    db: AsyncSession, *, superadmin: bool = True, name: str = "ipam-admin"
) -> User:
    user = User(
        username=name,
        email=f"{name}@example.com",
        display_name=name,
        hashed_password=hash_password("password123"),
        auth_source="local",
        is_superadmin=superadmin,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user, ["groups"])  # the permission check reads it outside a greenlet
    return user


async def _run_preview(db: AsyncSession, **kwargs: Any) -> ImportPreview:
    kwargs.setdefault("token", "app-code-0123")
    return await preview_phpipam_import(db, base_url=_URL, app_id="spatium", **kwargs)


async def _import(
    db: AsyncSession,
    actor: User,
    *,
    conflict_actions: dict[str, Any] | None = None,
    **preview_kw: Any,
) -> Any:
    preview = await _run_preview(db, **preview_kw)
    return await commit_import(
        db,
        preview=preview,
        conflict_actions=conflict_actions or {},
        space_strategy=preview_kw.get("space_strategy", "per_section"),
        target_space_id=preview_kw.get("target_space_id"),
        default_router_name="Imported VLANs (phpIPAM)",
        actor=actor,
    )


async def _count(db: AsyncSession, model: Any) -> int:
    return int((await db.execute(select(func.count()).select_from(model))).scalar_one())


# =========================================================================== #
# 1. Client unit tests (httpx.MockTransport).
# =========================================================================== #


def _mock_client(
    monkeypatch: pytest.MonkeyPatch, handler: Any, captured: dict[str, Any] | None = None
) -> None:
    real = httpx.AsyncClient

    def factory(**kw: Any) -> httpx.AsyncClient:
        if captured is not None:
            captured.update(kw)
        kw.pop("verify", None)
        return real(transport=httpx.MockTransport(handler), **kw)

    monkeypatch.setattr(ipam_client.httpx, "AsyncClient", factory)


def test_base_url_normalisation() -> None:
    assert _normalize_base("https://ipam.example.com/") == "https://ipam.example.com"
    assert _normalize_base("https://ipam.example.com/api") == "https://ipam.example.com"
    assert _normalize_base("https://ipam.example.com/api/spatium/") == "https://ipam.example.com"
    assert _normalize_base("https://h/phpipam") == "https://h/phpipam"


def test_client_needs_a_credential_and_a_sane_app_id() -> None:
    with pytest.raises(PhpipamClientError, match="token, or a username"):
        PhpipamClient(base_url=_URL, app_id="spatium")
    with pytest.raises(PhpipamClientError, match="app_id"):
        PhpipamClient(base_url=_URL, app_id="a/b", token="t")


@pytest.mark.asyncio
async def test_client_sends_app_code_as_token_header_and_verifies_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []
    captured: dict[str, Any] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(200, json={"code": 200, "success": True, "data": [{"id": "1"}]})

    _mock_client(monkeypatch, handler, captured)
    async with PhpipamClient(base_url=_URL, app_id="spatium", token="secret-code") as ipam:
        assert await ipam.get_list("/sections/") == [{"id": "1"}]
    assert seen[0].url == "https://ipam.test/api/spatium/sections/"
    assert seen[0].headers["token"] == "secret-code"
    # TLS verification is the default; opting out is explicit.
    assert captured["verify"] is True


@pytest.mark.asyncio
async def test_client_tls_opt_out_is_explicit_and_warned(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    _mock_client(monkeypatch, lambda r: httpx.Response(200, json={"data": []}), captured)
    async with PhpipamClient(base_url=_URL, app_id="a", token="t", verify_tls=False):
        pass
    assert captured["verify"] is False


@pytest.mark.asyncio
async def test_client_user_password_logs_in_once_then_uses_the_session_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.method == "POST":
            return httpx.Response(
                200, json={"code": 200, "success": True, "data": {"token": "sess-tok"}}
            )
        return httpx.Response(200, json={"success": True, "data": [{"id": "9"}]})

    _mock_client(monkeypatch, handler)
    async with PhpipamClient(
        base_url=_URL, app_id="spatium", username="admin", password="pw"
    ) as ipam:
        await ipam.get_list("/vrf/")
    assert seen[0].method == "POST" and seen[0].url.path == "/api/spatium/user/"
    assert seen[0].headers["authorization"].startswith("Basic ")
    assert seen[1].headers["token"] == "sess-tok"


@pytest.mark.asyncio
async def test_client_bad_login_is_a_client_error_without_the_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_client(
        monkeypatch,
        lambda r: httpx.Response(
            401, json={"code": 401, "success": False, "message": "Invalid username or password"}
        ),
    )
    with pytest.raises(PhpipamClientError) as exc:
        async with PhpipamClient(base_url=_URL, app_id="a", username="u", password="hunter2"):
            pass
    assert "401" in str(exc.value) and "hunter2" not in str(exc.value)


@pytest.mark.asyncio
async def test_client_json_404_is_an_empty_list_but_html_404_is_an_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/subnets/5/addresses/"):
            return httpx.Response(
                404, json={"code": 404, "success": False, "message": "No addresses found"}
            )
        return httpx.Response(404, text="<html>not found</html>")

    _mock_client(monkeypatch, handler)
    async with PhpipamClient(base_url=_URL, app_id="a", token="t") as ipam:
        assert await ipam.get_list("/subnets/5/addresses/") == []
        with pytest.raises(PhpipamClientError, match="404"):
            await ipam.get_list("/sections/")


@pytest.mark.asyncio
async def test_client_refuses_an_oversized_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ipam_client, "MAX_RESPONSE_BYTES", 1024)
    _mock_client(monkeypatch, lambda r: httpx.Response(200, content=b"x" * 5000))
    async with PhpipamClient(base_url=_URL, app_id="a", token="t") as ipam:
        with pytest.raises(PhpipamClientError, match="limit"):
            await ipam.get_list("/sections/")


@pytest.mark.asyncio
async def test_client_does_not_follow_a_redirect_with_the_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(302, headers={"location": "https://evil.test/"})

    _mock_client(monkeypatch, handler)
    async with PhpipamClient(base_url=_URL, app_id="a", token="t") as ipam:
        with pytest.raises(PhpipamClientError):
            await ipam.get_list("/sections/")
    assert seen == ["https://ipam.test/api/a/sections/"]


@pytest.mark.asyncio
async def test_client_gives_up_on_a_persistent_5xx(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr(ipam_client.asyncio, "sleep", no_sleep)
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(503)

    _mock_client(monkeypatch, handler)
    async with PhpipamClient(base_url=_URL, app_id="a", token="t") as ipam:
        with pytest.raises(PhpipamClientError, match="gave up"):
            await ipam.get_list("/sections/")
    assert calls["n"] == ipam_client._MAX_RETRIES


# =========================================================================== #
# 2. Mapping unit tests.
# =========================================================================== #


def test_subnet_network_accepts_dotted_and_decimal_addresses() -> None:
    assert str(ipam_mapping.subnet_network({"subnet": "10.1.2.0", "mask": "24"})) == "10.1.2.0/24"
    assert (
        str(ipam_mapping.subnet_network({"subnet": str(0x0A010200), "mask": "24"})) == "10.1.2.0/24"
    )
    v6 = ipam_mapping.subnet_network({"subnet": "2001:db8::", "mask": "64"})
    assert str(v6) == "2001:db8::/64"
    assert ipam_mapping.subnet_network({"subnet": "garbage", "mask": "24"}) is None
    assert ipam_mapping.subnet_network({"subnet": "10.0.0.0", "mask": ""}) is None


def test_state_map_reserved_deprecated_and_never_dhcp() -> None:
    states = ipam_mapping.build_state_map(_FIXTURE["lists"]["/tools/tags/"])
    assert states[2][0] == "allocated"  # Used
    assert states[3][0] == "reserved"
    assert states[5][0] == "deprecated"  # Decommissioned
    assert {s for s, _n in states.values()} <= {"allocated", "reserved", "deprecated"}
    # No tag table: the stock ids still map Reserved.
    assert ipam_mapping.build_state_map([])[3][0] == "reserved"


def test_custom_field_types_and_names() -> None:
    cf = ipam_mapping.build_cf_map(
        {
            "custom_Site Code": {"type": "varchar(64)", "Comment": "Site code"},
            "custom_n": {"type": "int(11)"},
            "custom_b": {"type": "tinyint(1)"},
            "custom_d": {"type": "date"},
            "custom_e": {"type": "enum('a','b')"},
            "9lives": {"type": "text"},
        }
    )
    assert cf["custom_Site Code"][:2] == ("custom_site_code", "text")
    assert cf["custom_n"][1] == "number"
    assert cf["custom_b"][1] == "boolean"
    assert cf["custom_d"][1] == "date"
    assert cf["custom_e"][1:3] == ("select", ["a", "b"])
    assert cf["9lives"][0] == "f_9lives"
    # Every name satisfies the custom-field name grammar.
    import re

    assert all(re.match(r"^[a-z][a-z0-9_]*$", v[0]) for v in cf.values())


def test_address_mapping_mac_hostname_owner_gateway() -> None:
    states = ipam_mapping.build_state_map(_FIXTURE["lists"]["/tools/tags/"])
    raw = {
        "id": "7",
        "ip": "10.0.1.5",
        "hostname": "web01.corp.example",
        "mac": "00-11-22-33-44-55",
        "owner": "ops",
        "is_gateway": "1",
        "tag": "3",
        "note": "n",
        "description": "d",
    }
    a = ipam_mapping.map_address(
        raw, subnet_cidr="10.0.1.0/24", space_name="S", state_map=states, cf_map={}, mask=24
    )
    assert a is not None
    assert (a.hostname, a.fqdn) == ("web01", "web01.corp.example")
    assert a.mac_address == "00:11:22:33:44:55"
    assert a.role == "gateway" and a.status == "reserved"
    assert a.custom_fields["phpipam_owner"] == "ops" and a.custom_fields["phpipam_id"] == 7
    assert a.description == "d\nn"
    bad = ipam_mapping.map_address(
        {**raw, "mac": "nope"},
        subnet_cidr="10.0.1.0/24",
        space_name="S",
        state_map=states,
        cf_map={},
        mask=24,
    )
    assert bad is not None and bad.mac_address is None
    assert bad.custom_fields["phpipam_mac"] == "nope"
    assert (
        ipam_mapping.map_address(
            {"ip": "x"}, subnet_cidr="c", space_name=None, state_map=states, cf_map={}, mask=24
        )
        is None
    )


def test_vlan_mapping_rejects_out_of_range_vid() -> None:
    assert ipam_mapping.map_vlan({"vlanId": "1", "number": "5000", "name": "x"}) is None
    assert ipam_mapping.map_vlan({"vlanId": "1", "number": "10", "name": ""}) is None
    v = ipam_mapping.map_vlan({"vlanId": "1", "number": "10", "name": "x"})
    assert v is not None and v.vid == 10 and v.netbox_id == 1


# =========================================================================== #
# 3. Preview (DB-backed, fixture-replayed; NO writes).
# =========================================================================== #


@pytest.mark.asyncio
async def test_preview_shape_counts_and_no_writes(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    preview = await _run_preview(db_session)

    assert preview.source == "phpipam"
    # Corp, Lab, Mixed (split in two), Empty.
    assert {s.name for s in preview.spaces} == {
        "Corp",
        "Lab",
        "Mixed",
        "Mixed / RED",
        "Empty",
    }
    red = next(s for s in preview.spaces if s.name == "Mixed / RED")
    assert red.vrf_name == "RED"
    assert [v.name for v in preview.vrfs] == ["RED"]
    assert preview.vrfs[0].rd == "65000:1"

    # 10.0.0.0/16 encloses two subnets -> block; the rest are leaves.
    assert {(b.space_name, b.network) for b in preview.blocks} == {("Corp", "10.0.0.0/16")}
    leaves = {(s.space_name, s.network) for s in preview.subnets}
    assert leaves == {
        ("Corp", "10.0.1.0/24"),
        ("Corp", "10.0.2.0/24"),
        ("Corp", "239.1.1.0/24"),
        ("Lab", "10.0.1.0/24"),  # same CIDR as Corp's: separate space, no clash
        ("Lab", "2001:db8:1::/64"),
        ("Mixed", "192.168.0.0/24"),
        ("Mixed / RED", "192.168.0.0/24"),
    }
    users = next(
        s for s in preview.subnets if s.space_name == "Corp" and s.network == "10.0.1.0/24"
    )
    assert users.vlan_vid == 100  # vlanId 10 -> VID 100
    assert users.custom_fields["phpipam_id"] == 11
    assert users.custom_fields["custom_site_code"] == "HQ"
    assert users.custom_fields["phpipam_is_pool"] is True
    assert next(s for s in preview.subnets if s.network == "239.1.1.0/24").kind == "multicast"

    # VLANs: the lab VID clash and the out-of-range VID are dropped.
    assert {(v.vid, v.name) for v in preview.vlans} == {(100, "users"), (200, "voice")}

    # Addresses: junk, the container's stray, and the duplicate-CIDR twin are out.
    got = {(a.space_name, a.address) for a in preview.addresses}
    assert ("Corp", "10.0.1.5") in got and ("Lab", "10.0.1.5") in got
    assert ("Corp", "10.0.9.9") not in got
    assert ("Mixed", "192.168.0.10") in got and ("Mixed / RED", "192.168.0.10") in got
    by_ip = {(a.space_name, a.address): a for a in preview.addresses}
    web = by_ip[("Corp", "10.0.1.5")]
    assert web.mac_address == "00:11:22:33:44:55"
    assert (web.hostname, web.fqdn) == ("web 01", "web 01.corp.example")
    assert web.custom_fields["phpipam_owner"] == "ops team"
    assert by_ip[("Corp", "10.0.1.1")].role == "gateway"
    assert by_ip[("Corp", "10.0.1.9")].status == "reserved"
    assert by_ip[("Corp", "10.0.1.9")].custom_fields["phpipam_mac"] == "not-a-mac"
    assert by_ip[("Corp", "10.0.1.10")].status == "allocated"  # DHCP is never "dhcp"
    assert by_ip[("Corp", "10.0.1.20")].status == "deprecated"
    assert by_ip[("Lab", "2001:db8:1::10")].status == "allocated"

    # Custom-field definitions, typed.
    defs = {(d.resource_type, d.name): d for d in preview.custom_field_defs}
    assert defs[("subnet", "custom_site_code")].field_type == "text"
    assert defs[("ip_block", "custom_site_code")].field_type == "text"
    assert defs[("subnet", "custom_tier")].field_type == "select"
    assert defs[("subnet", "custom_tier")].options == ["gold", "silver"]
    assert ("ip_address", "custom_notes") in defs
    assert ("ip_address", "phpipam_owner") in defs

    assert preview.counts["custom_fields"] == len(preview.custom_field_defs)

    # A preview writes nothing and audits nothing.
    for model in (IPSpace, IPBlock, Subnet, IPAddress, VRF, VLAN, CustomFieldDefinition):
        assert await _count(db_session, model) == 0
    assert await _count(db_session, AuditLog) == 0


@pytest.mark.asyncio
async def test_preview_warns_about_what_does_not_map(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    preview = await _run_preview(db_session)
    text = "\n".join(preview.warnings)
    assert "folder" in text
    assert "nested section" in text
    assert "2 VLAN domains" in text
    assert "VID" in text and "clashes" in text
    assert "references phpIPAM VLAN id=99" in text
    assert "multicast" in text
    assert "10.0.0.0/16" in text and "none of its leaf subnets" in text
    assert "appears twice" in text  # 192.168.0.0/24 twice in "Mixed"
    assert "device" in text
    assert "custom_vlan_owner" in text  # vlan custom fields cannot be stored


@pytest.mark.asyncio
async def test_preview_filters_narrow_the_pull(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    only_lab = await _run_preview(db_session, filters={"section_ids": [2]})
    assert {s.space_name for s in only_lab.subnets} == {"Lab"}
    # Only that section's subnets were asked for.
    assert "/sections/1/subnets/" not in FakePhpipamClient.requested
    v4 = await _run_preview(db_session, filters={"family": 4})
    assert all(":" not in s.network for s in v4.subnets)
    inside = await _run_preview(db_session, filters={"within_include": "10.0.1.0/24"})
    assert {s.network for s in inside.subnets} == {"10.0.1.0/24"}
    with pytest.raises(PhpipamClientError, match="within_include"):
        await _run_preview(db_session, filters={"within_include": "nope"})


@pytest.mark.asyncio
async def test_preview_pull_ceiling_refuses_an_oversized_pull(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    monkeypatch.setattr(ipam_preview, "PULL_CEILING", 5)
    with pytest.raises(PhpipamClientError, match="ceiling"):
        await _run_preview(db_session)


@pytest.mark.asyncio
async def test_preview_single_strategy_collapses_into_the_target_space(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    no_target = await _run_preview(db_session, space_strategy="single")
    assert no_target.spaces == []
    assert any("requires target_space_id" in w for w in no_target.warnings)
    # Same CIDR from two sections collapses to one, and says so.
    assert sum(1 for s in no_target.subnets if s.network == "10.0.1.0/24") == 1
    assert any("appears twice" in w for w in no_target.warnings)


@pytest.mark.asyncio
async def test_preview_flags_conflicts_without_overwriting(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    space = IPSpace(name="Corp")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="mine")
    db_session.add(block)
    db_session.add(
        CustomFieldDefinition(
            resource_type="subnet", name="custom_tier", label="Tier", field_type="text"
        )
    )
    db_session.add(VRF(name="RED"))
    await db_session.commit()

    preview = await _run_preview(db_session)
    keys = {(c.kind, c.key) for c in preview.conflicts}
    assert ("ip_space", "ip_space:Corp") in keys
    assert ("ip_block", "ip_block:Corp:10.0.0.0/16") in keys
    assert ("custom_field", "custom_field:subnet:custom_tier") in keys
    assert ("vrf", "vrf:65000:1") in keys
    assert all(c.action == "skip" for c in preview.conflicts)


# =========================================================================== #
# 4. Commit (shared pipeline).
# =========================================================================== #


@pytest.mark.asyncio
async def test_commit_creates_rows_with_provenance_and_audit(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    actor = await _make_admin(db_session)
    await db_session.commit()

    result = await _import(db_session, actor)

    assert result.source == "phpipam"
    assert result.total_failed == 0, [e.error for e in result.entities if e.error]
    assert result.spaces_created == 5
    assert result.vrfs_created == 1
    assert result.vlans_created == 2
    assert result.subnets_created == 7
    # 10.0.0.0/16 + wrapper blocks for the un-enclosed leaves.
    assert result.blocks_created >= 1
    assert result.custom_fields_created == len(
        (await db_session.execute(select(CustomFieldDefinition))).scalars().all()
    )

    sub = (
        await db_session.execute(
            select(Subnet)
            .join(IPSpace, IPSpace.id == Subnet.space_id)
            .where(IPSpace.name == "Corp", Subnet.network == "10.0.1.0/24")
        )
    ).scalar_one()
    assert sub.import_source == "phpipam" and sub.imported_at is not None
    assert sub.custom_fields["phpipam_id"] == 11
    assert sub.vlan_ref_id is not None
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "subnet", AuditLog.resource_id == str(sub.id)
            )
        )
    ).scalar_one()
    assert audit.action == "create"
    assert audit.new_value["import_source"] == "phpipam"
    assert audit.new_value["phpipam_id"] == 11
    assert "netbox_id" not in audit.new_value

    # Every row the import wrote carries the label; none says netbox.
    for model in (IPSpace, IPBlock, Subnet, IPAddress, VRF, VLAN):
        sources = set(
            (await db_session.execute(select(model.import_source).distinct())).scalars().all()
        )
        assert sources == {"phpipam"}, model

    # Address: MAC, hostname, role, status, and the CF-typed owner.
    web = (
        await db_session.execute(
            select(IPAddress).where(
                IPAddress.address == "10.0.1.5", IPAddress.description == "web\nrack 4"
            )
        )
    ).scalar_one()
    assert web.hostname == "web-01" and web.fqdn == "web-01.corp.example"
    assert str(web.mac_address) == "00:11:22:33:44:55"
    assert web.custom_fields["phpipam_owner"] == "ops team"
    gw = (
        await db_session.execute(select(IPAddress).where(IPAddress.role == "gateway"))
    ).scalar_one()
    assert str(gw.address) == "10.0.1.1"

    # The same CIDR coexists in two spaces; a VRF-split section links the VRF.
    assert await _count(db_session, Subnet) == 7
    red_space = (
        await db_session.execute(select(IPSpace).where(IPSpace.name == "Mixed / RED"))
    ).scalar_one()
    red_vrf = (await db_session.execute(select(VRF).where(VRF.name == "RED"))).scalar_one()
    assert red_space.vrf_id == red_vrf.id
    # The multicast subnet's address is skipped, not failed.
    assert any(
        e.kind == "ip_address" and e.action_taken == "skipped" and "multicast" in (e.error or "")
        for e in result.entities
    )


@pytest.mark.asyncio
async def test_commit_rerun_is_a_noop(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    actor = await _make_admin(db_session)
    await db_session.commit()
    await _import(db_session, actor)
    models = (IPSpace, IPBlock, Subnet, IPAddress, VRF, VLAN, CustomFieldDefinition, AuditLog)
    before = [await _count(db_session, m) for m in models]

    second = await _import(db_session, actor)

    assert [await _count(db_session, m) for m in models] == before
    assert second.total_created == 0 and second.total_failed == 0
    assert second.total_skipped > 0


@pytest.mark.asyncio
async def test_commit_conflict_defaults_to_skip_and_overwrite_is_per_entity(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    actor = await _make_admin(db_session)
    space = IPSpace(name="Corp")
    db_session.add(space)
    await db_session.flush()
    block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="hand-made")
    db_session.add(block)
    await db_session.flush()
    sub = Subnet(
        space_id=space.id,
        block_id=block.id,
        network="10.0.1.0/24",
        name="hand-made-subnet",
        total_ips=256,
    )
    db_session.add(sub)
    await db_session.commit()
    block_id, sub_id = block.id, sub.id

    first = await _import(db_session, actor)
    assert first.total_failed == 0, [e.error for e in first.entities if e.error]
    await db_session.refresh(sub)
    await db_session.refresh(block)
    # Reported, not touched: no provenance stamped, name kept.
    assert sub.import_source is None and sub.name == "hand-made-subnet"
    assert block.import_source is None
    skipped = {e.key for e in first.entities if e.action_taken == "skipped"}
    assert "subnet:Corp:10.0.1.0/24" in skipped

    second = await _import(
        db_session, actor, conflict_actions={"subnet:Corp:10.0.1.0/24": "overwrite"}
    )
    await db_session.refresh(sub)
    assert sub.import_source == "phpipam"
    assert sub.custom_fields["phpipam_id"] == 11
    assert sub.id == sub_id and block_id == block.id
    assert any(
        e.key == "subnet:Corp:10.0.1.0/24" and e.action_taken == "overwrote"
        for e in second.entities
    )
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.resource_type == "subnet",
                AuditLog.resource_id == str(sub.id),
                AuditLog.action == "update",
            )
        )
    ).scalar_one()
    assert audit.new_value["import_source"] == "phpipam"


@pytest.mark.asyncio
async def test_commit_never_reshapes_an_existing_custom_field(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    actor = await _make_admin(db_session)
    db_session.add(
        CustomFieldDefinition(
            resource_type="subnet", name="custom_tier", label="Mine", field_type="text"
        )
    )
    await db_session.commit()

    result = await _import(
        db_session, actor, conflict_actions={"custom_field:subnet:custom_tier": "overwrite"}
    )

    row = (
        await db_session.execute(
            select(CustomFieldDefinition).where(
                CustomFieldDefinition.resource_type == "subnet",
                CustomFieldDefinition.name == "custom_tier",
            )
        )
    ).scalar_one()
    assert (row.label, row.field_type, row.options) == ("Mine", "text", None)
    entry = next(e for e in result.entities if e.key == "custom_field:subnet:custom_tier")
    assert entry.action_taken == "skipped" and "select" in (entry.error or "")


@pytest.mark.asyncio
async def test_commit_rejects_an_unknown_source_and_a_bad_target(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    actor = await _make_admin(db_session)
    await db_session.commit()
    preview = await _run_preview(db_session)
    preview.source = "bogus"  # type: ignore[assignment]
    with pytest.raises(ValueError, match="unknown import source"):
        await commit_import(db_session, preview=preview, conflict_actions={}, actor=actor)
    preview.source = "phpipam"
    with pytest.raises(ValueError, match="requires target_space_id"):
        await commit_import(
            db_session, preview=preview, conflict_actions={}, space_strategy="single", actor=actor
        )


# ── Trash ─────────────────────────────────────────────────────────────── #


@pytest.mark.asyncio
async def test_commit_refuses_a_trashed_target_space(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    actor = await _make_admin(db_session)
    space = IPSpace(name="gone", deleted_at=datetime.now(UTC))
    db_session.add(space)
    await db_session.commit()

    preview = await _run_preview(db_session, space_strategy="single", target_space_id=space.id)
    with pytest.raises(ValueError, match="does not exist"):
        await commit_import(
            db_session,
            preview=preview,
            conflict_actions={},
            space_strategy="single",
            target_space_id=space.id,
            actor=actor,
        )
    assert await _count(db_session, Subnet) == 0
    assert await _count(db_session, AuditLog) == 0


@pytest.mark.asyncio
async def test_a_trashed_twin_never_blocks_or_receives_the_import(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A trashed space / block / subnet is neither a conflict nor a parent."""
    _patch_client(monkeypatch)
    actor = await _make_admin(db_session)
    now = datetime.now(UTC)
    space = IPSpace(name="Corp", deleted_at=now)
    db_session.add(space)
    await db_session.flush()
    old_block = IPBlock(space_id=space.id, network="10.0.0.0/16", name="trashed", deleted_at=now)
    db_session.add(old_block)
    await db_session.flush()
    old_subnet = Subnet(
        space_id=space.id,
        block_id=old_block.id,
        network="10.0.1.0/24",
        name="trashed",
        total_ips=256,
        deleted_at=now,
    )
    db_session.add(old_subnet)
    await db_session.commit()

    preview = await _run_preview(db_session)
    assert not [c for c in preview.conflicts if c.kind in {"ip_space", "ip_block", "subnet"}]

    result = await commit_import(db_session, preview=preview, conflict_actions={}, actor=actor)
    assert result.total_failed == 0, [e.error for e in result.entities if e.error]

    live_space = (
        await db_session.execute(
            select(IPSpace).where(IPSpace.name == "Corp", IPSpace.deleted_at.is_(None))
        )
    ).scalar_one()
    assert live_space.id != space.id
    live_block = (
        await db_session.execute(
            select(IPBlock).where(
                IPBlock.space_id == live_space.id,
                IPBlock.network == "10.0.0.0/16",
                IPBlock.deleted_at.is_(None),
            )
        )
    ).scalar_one()
    assert live_block.id != old_block.id
    live_subnets = (
        (
            await db_session.execute(
                select(Subnet).where(Subnet.space_id == live_space.id, Subnet.deleted_at.is_(None))
            )
        )
        .scalars()
        .all()
    )
    assert {str(s.network) for s in live_subnets} == {"10.0.1.0/24", "10.0.2.0/24", "239.1.1.0/24"}
    assert all(s.block_id != old_block.id for s in live_subnets)
    # Nothing was written into the trashed rows.
    await db_session.refresh(old_subnet)
    assert old_subnet.import_source is None and old_subnet.deleted_at is not None
    n_in_trashed = (
        await db_session.execute(
            select(func.count()).select_from(IPAddress).where(IPAddress.subnet_id == old_subnet.id)
        )
    ).scalar_one()
    assert n_in_trashed == 0


@pytest.mark.asyncio
async def test_a_subnet_trashed_after_import_is_recreated_not_written_into(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    actor = await _make_admin(db_session)
    await db_session.commit()
    await _import(db_session, actor)
    users = (
        await db_session.execute(
            select(Subnet)
            .join(IPSpace, IPSpace.id == Subnet.space_id)
            .where(IPSpace.name == "Corp", Subnet.network == "10.0.1.0/24")
        )
    ).scalar_one()
    users.deleted_at = datetime.now(UTC)
    await db_session.commit()
    old_id = users.id

    again = await _import(db_session, actor)
    assert again.total_failed == 0, [e.error for e in again.entities if e.error]
    fresh = (
        await db_session.execute(
            select(Subnet)
            .join(IPSpace, IPSpace.id == Subnet.space_id)
            .where(
                IPSpace.name == "Corp", Subnet.network == "10.0.1.0/24", Subnet.deleted_at.is_(None)
            )
        )
    ).scalar_one()
    assert fresh.id != old_id
    # The addresses went into the new subnet (5 valid rows in the fixture).
    fresh_addrs = (
        await db_session.execute(
            select(func.count()).select_from(IPAddress).where(IPAddress.subnet_id == fresh.id)
        )
    ).scalar_one()
    assert fresh_addrs == 5


# =========================================================================== #
# 5. REST surface.
# =========================================================================== #

_API = "/api/v1/ipam/import/phpipam"


def _hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


_CONN = {"base_url": _URL, "app_id": "spatium", "token": "app-code-0123"}


@pytest.mark.asyncio
async def test_api_requires_a_superadmin(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    plain = await _make_admin(db_session, superadmin=False, name="plain")
    await db_session.commit()
    h = _hdr(create_access_token(str(plain.id)))
    for path in ("test-connection", "preview", "commit"):
        resp = await client.post(f"{_API}/{path}", json=_CONN, headers=h)
        assert resp.status_code == 403, (path, resp.text)
        anon = await client.post(f"{_API}/{path}", json=_CONN)
        assert anon.status_code == 401, (path, anon.text)


@pytest.mark.asyncio
async def test_api_validation_is_422_with_a_message(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    admin = await _make_admin(db_session)
    await db_session.commit()
    h = _hdr(create_access_token(str(admin.id)))
    cases = [
        {"base_url": _URL, "app_id": "spatium"},  # no credential
        {"base_url": _URL, "app_id": "spatium", "username": "u"},  # half a credential
        {**_CONN, "app_id": "a/b"},
        {**_CONN, "base_url": "http://x/\U000482f8"},
        {**_CONN, "token": "k\nx"},
        {**_CONN, "space_strategy": "per_vrf"},
        {**_CONN, "filters": {"family": 5}},
    ]
    for body in cases:
        resp = await client.post(f"{_API}/preview", json=body, headers=h)
        assert resp.status_code == 422, (body, resp.text)
        assert resp.json()["detail"], body
    assert FakePhpipamClient.seen == []


@pytest.mark.asyncio
async def test_api_preview_never_writes_and_never_echoes_credentials(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    admin = await _make_admin(db_session)
    await db_session.commit()
    h = _hdr(create_access_token(str(admin.id)))
    body = {**_CONN, "token": "VERY-SECRET-APP-CODE"}
    resp = await client.post(f"{_API}/preview", json=body, headers=h)
    assert resp.status_code == 200, resp.text
    assert resp.json()["source"] == "phpipam"
    assert resp.json()["counts"]["subnets"] == 7
    assert "VERY-SECRET-APP-CODE" not in resp.text
    assert FakePhpipamClient.seen[0]["token"] == "VERY-SECRET-APP-CODE"
    assert FakePhpipamClient.seen[0]["verify_tls"] is True
    assert await _count(db_session, Subnet) == 0
    assert await _count(db_session, AuditLog) == 0

    off = await client.post(f"{_API}/preview", json={**body, "verify_tls": False}, headers=h)
    assert off.status_code == 200
    assert FakePhpipamClient.seen[-1]["verify_tls"] is False


@pytest.mark.asyncio
async def test_api_upstream_failure_is_502(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Boom(FakePhpipamClient):
        async def get_list(self, path: str) -> list[dict[str, Any]]:
            raise PhpipamClientError("HTTP 401 (unauthorised: bad token or credentials)")

    monkeypatch.setattr(ipam_preview, "PhpipamClient", Boom)
    monkeypatch.setattr(sys.modules["app.api.v1.phpipam_import.router"], "PhpipamClient", Boom)
    admin = await _make_admin(db_session)
    await db_session.commit()
    h = _hdr(create_access_token(str(admin.id)))
    for path in ("preview", "test-connection"):
        resp = await client.post(f"{_API}/{path}", json=_CONN, headers=h)
        assert resp.status_code == 502, (path, resp.text)
        assert "401" in resp.json()["detail"]
        assert "app-code-0123" not in resp.text


@pytest.mark.asyncio
async def test_api_test_connection_reports_counts(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    admin = await _make_admin(db_session)
    await db_session.commit()
    resp = await client.post(
        f"{_API}/test-connection",
        json=_CONN,
        headers=_hdr(create_access_token(str(admin.id))),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True, "counts": {"sections": 4, "vrfs": 1, "vlans": 4}}


@pytest.mark.asyncio
async def test_api_commit_roundtrip_audits_and_is_idempotent(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    admin = await _make_admin(db_session)
    await db_session.commit()
    h = _hdr(create_access_token(str(admin.id)))

    plan = (await client.post(f"{_API}/preview", json=_CONN, headers=h)).json()
    resp = await client.post(f"{_API}/commit", json={"plan": plan}, headers=h)
    assert resp.status_code == 200, resp.text
    out = resp.json()
    assert out["source"] == "phpipam"
    assert out["total_failed"] == 0 and out["subnets_created"] == 7
    assert out["custom_fields_created"] > 0
    assert await _count(db_session, Subnet) == 7
    audited = (
        await db_session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.new_value["import_source"].astext == "phpipam")
        )
    ).scalar_one()
    assert audited >= out["total_created"]

    again = (await client.post(f"{_API}/commit", json={"plan": plan}, headers=h)).json()
    assert again["total_created"] == 0 and again["total_failed"] == 0
    assert await _count(db_session, Subnet) == 7


@pytest.mark.asyncio
async def test_api_commit_refuses_a_foreign_plan_and_a_bad_target(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    admin = await _make_admin(db_session)
    trashed = IPSpace(name="gone", deleted_at=datetime.now(UTC))
    db_session.add(trashed)
    await db_session.commit()
    h = _hdr(create_access_token(str(admin.id)))
    plan = (await client.post(f"{_API}/preview", json=_CONN, headers=h)).json()

    netbox_plan = {**plan, "source": "netbox"}
    resp = await client.post(f"{_API}/commit", json={"plan": netbox_plan}, headers=h)
    assert resp.status_code == 400 and "mismatch" in resp.json()["detail"]
    # ...and the NetBox endpoint refuses ours.
    resp = await client.post("/api/v1/ipam/import/netbox/commit", json={"plan": plan}, headers=h)
    assert resp.status_code == 400

    resp = await client.post(
        f"{_API}/commit", json={"plan": plan, "space_strategy": "single"}, headers=h
    )
    assert resp.status_code == 422
    resp = await client.post(
        f"{_API}/commit",
        json={"plan": plan, "space_strategy": "single", "target_space_id": str(trashed.id)},
        headers=h,
    )
    assert resp.status_code == 422 and "does not exist" in resp.json()["detail"]
    resp = await client.post(
        f"{_API}/commit",
        json={"plan": plan, "space_strategy": "single", "target_space_id": "x"},
        headers=h,
    )
    assert resp.status_code == 422
    assert await _count(db_session, Subnet) == 0


@pytest.mark.asyncio
async def test_api_is_404_when_the_module_is_off(
    db_session: AsyncSession, client: AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_client(monkeypatch)
    admin = await _make_admin(db_session)
    db_session.add(FeatureModule(id="ipam.import.phpipam", enabled=False))
    await db_session.commit()
    from app.services import feature_modules as fm

    fm.invalidate_cache()
    h = _hdr(create_access_token(str(admin.id)))
    resp = await client.post(f"{_API}/preview", json=_CONN, headers=h)
    assert resp.status_code == 404
    # The NetBox importer is a separate module and is unaffected.
    assert (
        await client.post("/api/v1/ipam/import/netbox/commit", json={}, headers=h)
    ).status_code != 404


@pytest.mark.asyncio
async def test_openapi_documents_the_phpipam_routes() -> None:
    from app.main import app

    spec = app.openapi()
    for path in ("test-connection", "preview", "commit"):
        assert f"{_API}/{path}" in spec["paths"], path
    props = spec["components"]["schemas"]["PhpipamPreviewIn"]["properties"]
    assert {"base_url", "app_id", "token", "username", "password", "verify_tls"} <= set(props)


# =========================================================================== #
# 6. MCP tools.
# =========================================================================== #


@pytest.mark.asyncio
async def test_mcp_preview_tool_is_superadmin_only_and_reads_only(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.ai.operations_writes import CommitPhpipamImportArgs
    from app.services.ai.tools.imports import find_phpipam_import_preview

    _patch_client(monkeypatch)
    admin = await _make_admin(db_session)
    plain = await _make_admin(db_session, superadmin=False, name="plain-mcp")
    await db_session.commit()
    args = CommitPhpipamImportArgs(base_url=_URL, app_id="spatium", token="t")

    refused = await find_phpipam_import_preview(db_session, plain, args)
    assert "restricted to superadmin" in refused["error"]
    assert FakePhpipamClient.seen == []

    out = await find_phpipam_import_preview(db_session, admin, args)
    assert out["source"] == "phpipam" and out["subnet_count"] == 7
    assert out["custom_field_count"] > 0 and out["warnings"]
    assert await _count(db_session, Subnet) == 0

    with pytest.raises(ValueError, match="token, or a username"):
        CommitPhpipamImportArgs(base_url=_URL, app_id="spatium")


@pytest.mark.asyncio
async def test_mcp_propose_does_not_write_and_apply_needs_a_superadmin(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.services.ai.operations import get_operation
    from app.services.ai.operations_writes import CommitPhpipamImportArgs

    _patch_client(monkeypatch)
    admin = await _make_admin(db_session)
    plain = await _make_admin(db_session, superadmin=False, name="plain-op")
    await db_session.commit()
    op = get_operation("commit_phpipam_import")
    assert op is not None and op.requires_superadmin is True
    args = CommitPhpipamImportArgs(base_url=_URL, app_id="spatium", token="t")

    blocked = await op.preview(db_session, plain, args)
    assert blocked.ok is False
    ready = await op.preview(db_session, admin, args)
    assert ready.ok is True and "phpipam" in (ready.preview_text or "")
    # Previewing a proposal writes no IPAM row.
    assert await _count(db_session, Subnet) == 0

    with pytest.raises(Exception):  # noqa: B017 - the permission error type is not public
        await op.apply(db_session, plain, args)
    assert await _count(db_session, Subnet) == 0

    applied = await op.apply(db_session, admin, args)
    assert applied["subnets_created"] == 7 and applied["total_failed"] == 0
