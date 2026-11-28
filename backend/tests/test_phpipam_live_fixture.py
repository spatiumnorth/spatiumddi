"""phpIPAM importer against responses recorded from a REAL phpIPAM (issue #4734).

``fixtures/phpipam/phpipam_1_9_1_live.json`` holds the bodies a live phpIPAM
v1.9.1 answered (seeded through its own API with documentation-range data), so
these tests replay real wire shapes through the real client, preview and commit
rather than the hand-written ``phpipam_16.json`` shapes. Things the recording
established that the hand-written fixture got wrong or never showed:

* ids / masks / flags are JSON **integers** (``"id": 3``), not strings; only a
  few columns (``mask``, ``Null``) stay strings, and ``mask`` is ``null`` on a
  folder;
* a folder's ``subnet`` is ``"0.0.0.0"``; IPv6 comes back as a readable string;
* every empty list is an HTTP 404 envelope (including ``Invalid subnet Id``),
  and a controller with no custom fields answers 404 too;
* a refusal is a ``success: false`` envelope under a non-2xx code, and the SSL
  refusal is a **503**, which is not a transient gateway failure.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditLog
from app.models.ipam import CustomFieldDefinition, IPAddress, IPBlock, IPSpace, Subnet
from app.models.vlans import VLAN
from app.models.vrf import VRF
from app.services.netbox_import.commit import commit_import
from app.services.phpipam_import import client as ipam_client
from app.services.phpipam_import.client import PhpipamClient, PhpipamClientError
from app.services.phpipam_import.preview import preview_phpipam_import
from tests.test_phpipam_import import _make_admin, _mock_client

_LIVE = json.loads(
    (Path(__file__).parent / "fixtures" / "phpipam" / "phpipam_1_9_1_live.json").read_text()
)
_URL = "https://ipam.example.com"


def _replay(req: httpx.Request) -> httpx.Response:
    if req.method == "POST" and req.url.path.endswith("/user/"):
        return httpx.Response(_LIVE["login"]["status"], json=_LIVE["login"]["body"])
    path = req.url.path.split("/api/codeapp", 1)[1]
    rec = _LIVE["responses"].get(path)
    assert rec is not None, f"importer asked for a path that was not recorded: {path}"
    return httpx.Response(rec["status"], json=rec["body"])


def _error(name: str) -> httpx.Response:
    e = _LIVE["errors"][name]
    return httpx.Response(e["status"], json=e["body"])


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_sleep(_s: float) -> None:
        return None

    monkeypatch.setattr(ipam_client.asyncio, "sleep", no_sleep)


# --------------------------------------------------------------------------- #
# Client against the real envelopes.
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_live_ssl_refusal_is_raised_at_once_with_phpipams_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plain-http URL gets a 503 envelope; retrying it five times then saying
    "gave up ... throttled / 5xx" hid the one line that tells the operator what
    to fix."""
    calls = {"n": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return _error("ssl_required")

    _mock_client(monkeypatch, handler)
    async with PhpipamClient(base_url="http://ipam.example.com", app_id="a", token="t") as ipam:
        with pytest.raises(PhpipamClientError, match="SSL connection is required for API"):
            await ipam.get_list("/sections/")
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_live_refusals_carry_phpipams_message(monkeypatch: pytest.MonkeyPatch) -> None:
    answer = {"name": "bad_token"}
    _mock_client(monkeypatch, lambda req: _error(answer["name"]))
    for name, text in (("bad_token", "Unauthorized"), ("bad_app", "Invalid application id")):
        answer["name"] = name
        async with PhpipamClient(base_url=_URL, app_id="a", token="t") as ipam:
            with pytest.raises(PhpipamClientError, match=text):
                await ipam.get_list("/sections/")
    answer["name"] = "bad_password"
    with pytest.raises(PhpipamClientError, match="Invalid username or password"):
        async with PhpipamClient(base_url=_URL, app_id="a", username="u", password="p"):
            pass


@pytest.mark.asyncio
async def test_live_user_login_envelope_yields_the_session_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.method == "GET":
            seen.append(req.headers["token"])
            return httpx.Response(200, json={"code": 200, "success": True, "data": []})
        return _replay(req)

    _mock_client(monkeypatch, handler)
    async with PhpipamClient(
        base_url=_URL, app_id="tokenapp", username="Admin", password="x"
    ) as ipam:
        assert await ipam.get_list("/sections/") == []
    assert seen == ["EXAMPLE-SESSION-TOKEN"]


@pytest.mark.asyncio
async def test_live_empty_answers_are_empty_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    _mock_client(monkeypatch, _replay)
    async with PhpipamClient(base_url=_URL, app_id="codeapp", token="t") as ipam:
        assert await ipam.get_list("/subnets/6/addresses/") == []  # a subnet with no addresses
        assert await ipam.get_data("/vrf/custom_fields/") is None  # no custom fields


# --------------------------------------------------------------------------- #
# Preview + commit of the whole recorded estate.
# --------------------------------------------------------------------------- #


async def _preview(db: AsyncSession, monkeypatch: pytest.MonkeyPatch) -> Any:
    _mock_client(monkeypatch, _replay)
    return await preview_phpipam_import(db, base_url=_URL, app_id="codeapp", token="t")


@pytest.mark.asyncio
async def test_live_preview_counts_and_warnings(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    preview = await _preview(db_session, monkeypatch)
    assert preview.counts == {
        "customers": 0,
        "sites": 0,
        "vrfs": 2,
        "spaces": 4,
        "vlans": 4,
        "blocks": 2,
        "subnets": 7,
        "addresses": 25,
        "custom_fields": 12,
        "conflicts": 0,
    }
    text = " | ".join(preview.warnings)
    assert "folder" in text and "nested section" in text and "site_code" in text


@pytest.mark.asyncio
async def test_live_commit_matches_what_was_seeded(
    db_session: AsyncSession, monkeypatch: pytest.MonkeyPatch
) -> None:
    admin = await _make_admin(db_session)
    preview = await _preview(db_session, monkeypatch)

    async def commit() -> Any:
        return await commit_import(
            db_session,
            preview=preview,
            conflict_actions={},
            space_strategy="per_section",
            target_space_id=None,
            default_router_name="Imported VLANs (phpIPAM)",
            actor=admin,
        )

    first = await commit()
    assert first.total_failed == 0 and first.total_created == 61

    subnets = {str(s.network): s for s in (await db_session.execute(select(Subnet))).scalars()}
    assert sorted(subnets) == [
        "10.20.0.0/22",
        "192.0.2.0/24",
        "192.0.3.0/24",
        "198.51.100.0/25",
        "2001:db8:10::/64",
        "2001:db8:20:1::/64",
        "203.0.113.0/26",
    ]
    hq = subnets["192.0.2.0/24"]
    assert hq.custom_fields["owner_team"] == "Network"
    assert hq.custom_fields["vlan_count"] == 1 and hq.custom_fields["review_date"] == "2026-06-30"
    assert subnets["198.51.100.0/25"].custom_fields["pci_scope"] is True
    assert hq.vlan_ref_id is not None and subnets["192.0.3.0/24"].vlan_ref_id is None
    # The supernets became blocks and the nested subnets sit under them.
    blocks = {str(b.network) for b in (await db_session.execute(select(IPBlock))).scalars()}
    assert {"198.51.100.0/24", "2001:db8:20::/48"} <= blocks

    addrs = {str(a.address): a for a in (await db_session.execute(select(IPAddress))).scalars()}
    assert len(addrs) == 25
    assert addrs["192.0.2.1"].role == "gateway"
    assert str(addrs["192.0.2.20"].mac_address) == "aa:bb:cc:dd:ee:20"  # aa-bb-... input
    assert str(addrs["192.0.2.51"].mac_address) == "00:11:22:33:44:51"  # 0011.2233.4451 input
    assert addrs["192.0.2.21"].status == "reserved"
    assert addrs["192.0.2.99"].status == "deprecated"
    assert addrs["192.0.2.100"].hostname == "a"
    assert addrs["192.0.2.100"].fqdn == "a.b.c.example.com"
    assert addrs["2001:db8:10::ff"].hostname == "v6host2"  # sent as 2001:db8:10:0:0:0:0:ff
    assert addrs["192.0.2.1"].custom_fields["rack_u"] == 1
    assert addrs["192.0.2.1"].custom_fields["is_critical"] is True
    assert addrs["192.0.2.1"].custom_fields["warranty_end"] == "2028-01-01"

    types = {
        (d.resource_type, d.name): d.field_type
        for d in (await db_session.execute(select(CustomFieldDefinition))).scalars()
    }
    assert types[("ip_address", "asset_tag")] == "text"
    assert types[("ip_address", "is_critical")] == "boolean"
    assert types[("ip_address", "rack_u")] == "number"
    assert types[("ip_address", "warranty_end")] == "date"

    vlans = {v.vlan_id: v.name for v in (await db_session.execute(select(VLAN))).scalars()}
    assert vlans == {10: "Users", 20: "Servers", 30: "Voice", 99: "Management"}
    vrfs = {
        v.name: v.route_distinguisher for v in (await db_session.execute(select(VRF))).scalars()
    }
    assert vrfs == {"MGMT": "65000:100", "GUEST": "65000:200"}
    spaces = {s.name for s in (await db_session.execute(select(IPSpace))).scalars()}
    assert spaces == {"Corporate", "Corporate / GUEST", "Datacenter", "IPv6"}

    audited = (
        await db_session.execute(
            select(func.count())
            .select_from(AuditLog)
            .where(AuditLog.new_value["import_source"].astext == "phpipam")
        )
    ).scalar_one()
    assert audited >= first.total_created

    again = await commit()
    assert again.total_created == 0 and again.total_failed == 0
