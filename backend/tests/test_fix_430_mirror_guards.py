"""#430 — integration-mirror clients raise on a wrong-shape 200.

The #426 defect class: a degraded read that LOOKS successful (HTTP 200 with
a wrong-shape body — a proxy error page, an envelope change, ``data: null``)
collapses to zero items and the reconciler's absence-delete pass purges the
whole mirror while reporting ``ok=True``. These tests pin the per-client
guards: a degraded 200 raises the client's typed error (so the reconciler
aborts and keeps last-known rows), while a *legitimately empty* upstream
(documented envelope present, no rows) returns an empty list.

The list methods that hit HTTP are tested by feeding the parse layer a
canned body: ``_get`` is stubbed for the clients that parse after ``_get``
(docker / tailscale / proxmox / opnsense); Kubernetes raises inside
``_list`` itself, so it gets a real ``httpx.MockTransport``.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from app.services.docker.client import DockerClient, DockerClientError
from app.services.kubernetes.client import KubernetesClient, KubernetesClientError
from app.services.opnsense.client import OPNsenseClient, OPNsenseClientError
from app.services.proxmox.client import ProxmoxClient, ProxmoxClientError
from app.services.tailscale.client import TailscaleClient, TailscaleClientError
from app.services.unifi.client import UnifiClient, UnifiClientConfig, UnifiClientError


def _stub_get(client: Any, value: Any) -> None:
    """Replace the instance's async ``_get`` with one that returns ``value``."""

    async def _fake(*_a: Any, **_k: Any) -> Any:
        return value

    client._get = _fake  # type: ignore[assignment]


# ── Kubernetes (require_keyed_list inside _list) ──────────────────────


def _k8s_with_body(body: Any) -> KubernetesClient:
    client = KubernetesClient(api_server_url="https://k8s.test", token="t")

    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://k8s.test"
    )
    return client


@pytest.mark.asyncio
async def test_k8s_empty_cluster_is_legitimate() -> None:
    client = _k8s_with_body({"items": []})
    assert await client.list_nodes() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"items": None}, {"kind": "Status"}, []])
async def test_k8s_wrong_shape_200_raises(body: Any) -> None:
    client = _k8s_with_body(body)
    with pytest.raises(KubernetesClientError):
        await client.list_nodes()


# ── Kubernetes pagination (#1560) ─────────────────────────────────────


def _k8s_paged(pages: list[tuple[int, Any]]) -> KubernetesClient:
    """Mock transport serving ``pages`` in request order."""
    client = KubernetesClient(api_server_url="https://k8s.test", token="t")
    calls: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req)
        status, body = pages[len(calls) - 1]
        return httpx.Response(status, json=body)

    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler), base_url="https://k8s.test"
    )
    client._calls = calls  # type: ignore[attr-defined]
    return client


@pytest.mark.asyncio
async def test_k8s_list_follows_continue_token_until_empty() -> None:
    node = {"metadata": {"name": "n1"}, "status": {"addresses": [], "conditions": []}}
    node2 = {"metadata": {"name": "n2"}, "status": {"addresses": [], "conditions": []}}
    client = _k8s_paged(
        [
            (200, {"items": [node], "metadata": {"continue": "tok-1"}}),
            (200, {"items": [node2], "metadata": {"continue": ""}}),
        ]
    )
    out = await client.list_nodes()
    assert [n.name for n in out] == ["n1", "n2"]
    calls = client._calls  # type: ignore[attr-defined]
    assert len(calls) == 2
    assert calls[0].url.params.get("continue") is None
    assert calls[1].url.params.get("continue") == "tok-1"


@pytest.mark.asyncio
async def test_k8s_paging_failure_midway_raises_instead_of_partial_list() -> None:
    # 410 Gone = expired continue token. The reconcile must abort, not
    # prune everything past page one against a partial list.
    node = {"metadata": {"name": "n1"}, "status": {"addresses": [], "conditions": []}}
    client = _k8s_paged(
        [
            (200, {"items": [node], "metadata": {"continue": "tok-1"}}),
            (410, {"kind": "Status", "reason": "Expired"}),
        ]
    )
    with pytest.raises(KubernetesClientError):
        await client.list_nodes()


# ── Docker (require_list after _get) ──────────────────────────────────


@pytest.mark.asyncio
async def test_docker_empty_arrays_are_legitimate() -> None:
    client = DockerClient(connection_type="tcp", endpoint="localhost:2375")
    _stub_get(client, [])
    assert await client.list_networks() == []
    assert await client.list_containers(include_stopped=False) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"message": "bad gateway"}, None])
async def test_docker_non_array_200_raises(body: Any) -> None:
    client = DockerClient(connection_type="tcp", endpoint="localhost:2375")
    _stub_get(client, body)
    with pytest.raises(DockerClientError):
        await client.list_networks()
    with pytest.raises(DockerClientError):
        await client.list_containers(include_stopped=True)


# ── Tailscale (require_keyed_list after _get) ─────────────────────────


@pytest.mark.asyncio
async def test_tailscale_empty_tailnet_is_legitimate() -> None:
    client = TailscaleClient(api_key="k", tailnet="-")
    _stub_get(client, {"devices": []})
    assert await client.list_devices() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, {"devices": None}, {"foo": 1}])
async def test_tailscale_missing_devices_raises(body: Any) -> None:
    client = TailscaleClient(api_key="k", tailnet="-")
    _stub_get(client, body)
    with pytest.raises(TailscaleClientError):
        await client.list_devices()


# ── Proxmox (require_list after _get unwraps data) ────────────────────


def _proxmox() -> ProxmoxClient:
    return ProxmoxClient(
        host="pve.test", port=8006, token_id="root@pam!t", token_secret="s", verify_tls=False
    )


@pytest.mark.asyncio
async def test_proxmox_empty_lists_are_legitimate() -> None:
    client = _proxmox()
    _stub_get(client, [])  # data:[] → _get returns []
    assert await client.list_nodes() == []
    assert await client.list_qemu("pve", include_stopped=True) == []
    assert await client.list_lxc("pve", include_stopped=True) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [None, {}, {"foo": "bar"}])
async def test_proxmox_data_null_raises(body: Any) -> None:
    # data:null → _get returns None; data:{} → returns a dict. Either is a
    # degraded read for a list endpoint and must raise, not yield zero nodes.
    client = _proxmox()
    _stub_get(client, body)
    with pytest.raises(ProxmoxClientError):
        await client.list_nodes()
    with pytest.raises(ProxmoxClientError):
        await client.list_qemu("pve", include_stopped=False)


# ── OPNsense (bespoke envelope guards) ────────────────────────────────


def _opnsense() -> OPNsenseClient:
    return OPNsenseClient(host="fw.test", port=443, api_key="k", api_secret="s", verify_tls=False)


@pytest.mark.asyncio
async def test_opnsense_interfaces_real_data_parses() -> None:
    # The payload here was invented when this guard was written, and it was
    # wrong: it used flat ipaddr/subnet string keys that no OPNsense
    # endpoint returns. #797 replaced it with the real shape — addresses in
    # an ipv4[] array of {ipaddr, subnetbits} — which is what both the
    # overview and ifconfig endpoints actually emit.
    client = _opnsense()
    _stub_get(
        client,
        [
            {
                "identifier": "lan",
                "device": "igb0",
                "ipv4": [{"ipaddr": "10.0.0.1", "subnetbits": 24}],
                "ipv6": [],
            }
        ],
    )
    out = await client.list_interfaces()
    assert len(out) == 1 and out[0].cidr == "10.0.0.0/24"


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, [], None, "oops"])
async def test_opnsense_interfaces_degraded_200_raises(body: Any) -> None:
    # A firewall always has interfaces, so an empty or non-list/non-dict 200
    # is a degraded read that would otherwise delete every interface subnet.
    # Both the overview endpoint and the ifconfig fallback must hold this;
    # ``_stub_get`` answers whichever one the client reaches.
    client = _opnsense()
    _stub_get(client, body)
    with pytest.raises(OPNsenseClientError):
        await client.list_interfaces()


@pytest.mark.asyncio
async def test_opnsense_interfaces_all_filtered_is_not_degraded() -> None:
    # The counterpart to the guard above: entries that ARE the right shape
    # but get skipped for a reason we understand (WAN on DHCP here) are a
    # legitimate zero, and must reach the reconciler's zero-interface
    # warning rather than aborting the pass as a degraded read (#797).
    client = _opnsense()
    _stub_get(
        client,
        [
            {
                "identifier": "wan",
                "device": "igb0",
                "link_type": "dhcp",
                "ipv4": [{"ipaddr": "198.51.100.2", "subnetbits": 29}],
            }
        ],
    )
    assert await client.list_interfaces() == []


@pytest.mark.asyncio
async def test_opnsense_vlans_empty_envelope_is_legitimate() -> None:
    client = _opnsense()
    _stub_get(client, {"vlan": {"vlan": {}}})  # box with zero VLANs
    assert await client.list_vlans() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{}, [], None, {"vlan": {}}])
async def test_opnsense_vlans_missing_envelope_raises(body: Any) -> None:
    client = _opnsense()
    _stub_get(client, body)
    with pytest.raises(OPNsenseClientError):
        await client.list_vlans()
