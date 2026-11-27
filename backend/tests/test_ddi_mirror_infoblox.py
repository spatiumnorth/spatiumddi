"""Infoblox WAPI provider for the commercial-DDI mirror (#4729), on recorded
fixture JSON: paging, mapping, unmapped reporting, view scoping, auth and
rate-limit handling, and that nothing but GET is ever sent."""

from __future__ import annotations

import httpx
import pytest

from app.services.ddi_mirror import infoblox as ib
from app.services.ddi_mirror.base import DDIProviderError, ProviderConfig
from app.services.ddi_mirror.infoblox import InfobloxProvider
from app.services.ddi_mirror.registry import PLANNED_VENDORS, get_provider_class, vendor_error
from tests._ddi_mirror_support import FakeWapi


def _provider(wapi: FakeWapi, **kw: object) -> InfobloxProvider:
    cfg = ProviderConfig(
        base_url="https://gm.test",
        api_version="v2.12",
        username="admin",
        password="secret",
        transport=wapi.transport(),
        **kw,  # type: ignore[arg-type]
    )
    return InfobloxProvider(cfg)


@pytest.fixture(autouse=True)
def _no_pause(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ib, "_PAGE_PAUSE_SECONDS", 0)


@pytest.mark.asyncio
async def test_networks_are_paged_and_mapped() -> None:
    wapi = FakeWapi()
    async with _provider(wapi, page_size=2) as p:
        res = await p.fetch("network")
    assert [o.value for o in res.objects] == ["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"]
    assert res.complete is True
    # the unparseable network is reported, not silently dropped
    assert len(res.unmapped) == 1 and "not-a-cidr" in res.unmapped[0]
    first = res.objects[0]
    assert first.data["extattrs"] == {"VLAN": "110"}
    assert first.data["options"] == {"routers": "10.1.0.1"}
    assert res.objects[1].data["disabled"] is True
    reqs = [r for r in wapi.requests if r.url.path.endswith("/network")]
    assert len(reqs) == 2
    assert reqs[0].url.params["_max_results"] == "2"
    assert reqs[0].url.params["_paging"] == "1"
    assert "_page_id" not in reqs[0].url.params
    assert reqs[1].url.params["_page_id"] == "page-2"


@pytest.mark.asyncio
async def test_every_kind_maps() -> None:
    wapi = FakeWapi()
    async with _provider(wapi) as p:
        got = {k: (await p.fetch(k)) for k in p.kinds if k != "network"}
    assert [o.name for o in got["view"].objects] == ["default", "internal"]
    assert got["container"].objects[0].value == "10.0.0.0/8"
    rng = got["range"].objects[0]
    assert (rng.value, rng.name, rng.data["network"]) == (
        "10.1.0.100-10.1.0.199",
        "srv-pool",
        "10.1.0.0/24",
    )
    res = got["reservation"].objects[0]
    assert (res.value, res.name, res.data["mac"]) == ("10.1.0.10", "printer1", "00:50:56:aa:bb:cc")
    assert {o.name for o in got["zone"].objects} == {"example.com", "1.10.in-addr.arpa"}
    host = got["host"].objects[0]
    assert host.name == "web1.example.com" and host.value == "10.1.0.20"
    assert host.data["addresses"][0]["dhcp"] is True
    # a host record with no IPv4 address is reported as unmapped
    assert len(got["host"].unmapped) == 1
    assert got["a"].objects[0].value == "10.1.0.30"
    ptr = got["ptr"].objects[0]
    assert (ptr.name, ptr.value) == ("30.0.1.10.in-addr.arpa", "app.example.com")


@pytest.mark.asyncio
async def test_only_get_is_sent_and_view_filter_is_applied() -> None:
    wapi = FakeWapi()
    async with _provider(wapi, network_view="default", dns_view="internal") as p:
        await p.probe()
        for k in p.kinds:
            await p.fetch(k)
    assert {r.method for r in wapi.requests} == {"GET"}
    by_obj = {r.url.path.rsplit("/", 1)[1]: r.url.params for r in wapi.requests}
    assert by_obj["networkcontainer"]["network_view"] == "default"
    assert by_obj["zone_auth"]["view"] == "internal"
    assert by_obj["record:a"]["view"] == "internal"
    assert by_obj["view"]["name"] == "internal"


@pytest.mark.asyncio
async def test_probe_reports_grid_and_rejects_bad_credentials() -> None:
    wapi = FakeWapi()
    async with _provider(wapi) as p:
        info = await p.probe()
    assert info.version == "WAPI v2.12" and "Infoblox" in info.detail

    wapi.require_auth = ("admin", "other")
    async with _provider(wapi) as p:
        with pytest.raises(DDIProviderError) as ei:
            await p.probe()
    assert ei.value.is_auth and "401" in str(ei.value)


@pytest.mark.asyncio
async def test_rate_limit_is_retried_then_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []

    async def fake_sleep(s: float) -> None:
        slept.append(s)

    monkeypatch.setattr(ib.asyncio, "sleep", fake_sleep)
    calls = {"n": 0}
    wapi = FakeWapi()
    inner = wapi._handle

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, headers={"Retry-After": "2"}, json={})
        return inner(request)

    cfg = ProviderConfig(
        base_url="https://gm.test", api_version="v2.12", username="admin", password="secret",
        transport=httpx.MockTransport(handler),
    )  # fmt: skip
    async with InfobloxProvider(cfg) as p:
        info = await p.probe()
    assert info.version and calls["n"] == 2 and slept == [2.0]


@pytest.mark.asyncio
async def test_non_json_and_unexpected_shapes_are_errors() -> None:
    wapi = FakeWapi()
    wapi.overrides["zone_auth"] = (200, {"not": "paged"})
    async with _provider(wapi) as p:
        with pytest.raises(DDIProviderError, match="no 'result' list"):
            await p.fetch("zone")
    wapi.overrides["zone_auth"] = (500, {"text": "boom"})
    async with _provider(wapi) as p:
        with pytest.raises(DDIProviderError) as ei:
            await p.fetch("zone")
    assert ei.value.status_code == 500 and not ei.value.is_auth


@pytest.mark.asyncio
async def test_object_cap_marks_the_kind_incomplete(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ib, "MAX_OBJECTS_PER_KIND", 2)
    wapi = FakeWapi()
    async with _provider(wapi, page_size=2) as p:
        res = await p.fetch("network")
    assert res.complete is False and len(res.objects) == 2


def test_tls_is_verified_unless_explicitly_disabled() -> None:
    base = dict(base_url="https://gm.test", api_version="v2.12", username="u", password="p")
    assert InfobloxProvider._verify(ProviderConfig(**base)) is True  # type: ignore[arg-type]
    assert InfobloxProvider._verify(ProviderConfig(verify_tls=False, **base)) is False  # type: ignore[arg-type]


def test_registry_names_planned_vendors() -> None:
    assert get_provider_class("infoblox") is InfobloxProvider
    for v in PLANNED_VENDORS:
        assert "planned" in (vendor_error(v) or "")
    assert "unknown vendor" in (vendor_error("nope") or "")
