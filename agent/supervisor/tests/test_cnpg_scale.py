"""#272 — patch_cnpg_instances directly scales the CNPG Cluster CR.

The Cluster carries ``helm.sh/resource-policy: keep`` (so a failed-release
recovery can't delete it), and the supervisor sizes it directly with a
merge-patch; the chart renders the count that patch leaves
(``test_cnpg_instances_rendered``, #1313). These tests pin the GET-then-PATCH contract: idempotent on a
matching size, a real PATCH on a change, a quiet no-op when the Cluster
isn't up yet (404), and the ``< 1`` guard.
"""

from __future__ import annotations

import json

from spatium_supervisor import k8s_api


class _Recorder:
    """Stand-in for k8s_api._request that scripts a GET response then
    records the follow-up PATCH (if any)."""

    def __init__(self, get_status: int, get_body: str, patch_status: int = 200):
        self._get = (get_status, get_body)
        self._patch_status = patch_status
        self.calls: list[tuple[str, str, bytes | None]] = []

    def __call__(self, method, path, body=None, content_type=None):
        self.calls.append((method, path, body))
        if method == "GET":
            return self._get
        return (self._patch_status, "{}")

    @property
    def patched(self) -> bool:
        return any(m == "PATCH" for m, _, _ in self.calls)

    @property
    def patch_body(self) -> dict:
        for method, _, body in self.calls:
            if method == "PATCH" and body is not None:
                return json.loads(body)
        return {}


_SETTLED_AFFINITY = {
    "enablePodAntiAffinity": True,
    "podAntiAffinityType": "required",
    "topologyKey": "kubernetes.io/hostname",
}


def test_scale_up_patches_when_size_differs(monkeypatch) -> None:
    rec = _Recorder(200, json.dumps({"spec": {"instances": 1}}))
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.patch_cnpg_instances(3)

    assert (changed, err) == (True, None)
    assert rec.patched
    assert rec.patch_body == {"spec": {"instances": 3, "affinity": _SETTLED_AFFINITY}}


def test_idempotent_when_size_and_affinity_match(monkeypatch) -> None:
    rec = _Recorder(
        200, json.dumps({"spec": {"instances": 3, "affinity": _SETTLED_AFFINITY}})
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.patch_cnpg_instances(3)

    # Already at target — no PATCH, no "applied" log on the next heartbeat.
    assert (changed, err) == (False, None)
    assert not rec.patched


def test_patches_affinity_even_when_size_matches(monkeypatch) -> None:
    """#590 — an appliance that A/B-upgrades into the fix is already at the
    right instance count, but CNPG's ``preferred`` default let two instances
    stack on the seed. The Cluster carries ``resource-policy: keep`` so Helm
    will never fix it; this patch is the only path."""
    rec = _Recorder(
        200,
        json.dumps(
            {
                "spec": {
                    "instances": 3,
                    "affinity": {
                        "enablePodAntiAffinity": True,
                        "podAntiAffinityType": "preferred",
                    },
                }
            }
        ),
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.patch_cnpg_instances(3)

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["affinity"]["podAntiAffinityType"] == "required"


def test_patches_when_cnpg_has_no_affinity_block(monkeypatch) -> None:
    """A pre-#590 Cluster CR has no ``spec.affinity`` at all."""
    rec = _Recorder(200, json.dumps({"spec": {"instances": 3}}))
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.patch_cnpg_instances(3)

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["affinity"] == _SETTLED_AFFINITY


def test_rejects_bad_anti_affinity_type(monkeypatch) -> None:
    rec = _Recorder(200, json.dumps({"spec": {"instances": 3}}))
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.patch_cnpg_instances(3, pod_anti_affinity_type="hard")

    assert changed is False
    assert err is not None and "pod_anti_affinity_type" in err
    assert not rec.calls  # guard short-circuits before any kubeapi call


def test_preferred_is_honoured_when_requested(monkeypatch) -> None:
    """BYO-Kubernetes shape: more instances than nodes wants best-effort."""
    rec = _Recorder(200, json.dumps({"spec": {"instances": 3}}))
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.patch_cnpg_instances(3, pod_anti_affinity_type="preferred")

    assert (changed, err) == (True, None)
    assert rec.patch_body["spec"]["affinity"]["podAntiAffinityType"] == "preferred"


def test_missing_cluster_is_quiet_noop(monkeypatch) -> None:
    rec = _Recorder(404, "not found")
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.patch_cnpg_instances(3)

    # Cluster not up yet (early boot / non-cnpg deploy) — not an error.
    assert (changed, err) == (False, None)
    assert not rec.patched


def test_rejects_sub_one_size(monkeypatch) -> None:
    rec = _Recorder(200, json.dumps({"spec": {"instances": 1}}))
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.patch_cnpg_instances(0)

    assert changed is False
    assert err == "instances < 1"
    assert not rec.calls  # guard short-circuits before any kubeapi call


# ── #272 Phase 10 — data-plane VIP overrides (HelmChartConfig render) ──


def test_dataplane_vip_overrides_render(monkeypatch) -> None:
    # No existing HelmChartConfig (404) → create POST carrying the values.
    rec = _Recorder(404, "")
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.apply_dataplane_vip_overrides(
        dns_vip="192.168.0.242", dhcp_relay_vip="192.168.0.243"
    )

    assert (changed, err) == (True, None)
    body = next(json.loads(b) for m, _, b in rec.calls if m == "POST" and b)
    vals = body["spec"]["valuesContent"]
    assert "useMetalLBVIP: true" in vals
    assert 'vip: "192.168.0.242"' in vals
    assert 'relayVIP: "192.168.0.243"' in vals


def test_dataplane_vip_overrides_empty_disables(monkeypatch) -> None:
    rec = _Recorder(404, "")
    monkeypatch.setattr(k8s_api, "_request", rec)

    k8s_api.apply_dataplane_vip_overrides(dns_vip="", dhcp_relay_vip="")

    body = next(json.loads(b) for m, _, b in rec.calls if m == "POST" and b)
    vals = body["spec"]["valuesContent"]
    assert "useMetalLBVIP: false" in vals
    assert 'vip: ""' in vals
    assert 'relayVIP: ""' in vals


# ── issue #566 decision D1 — MetalLB BGP mode overrides ────────────────


def test_metallb_bgp_overrides_render(monkeypatch) -> None:
    # No existing HelmChartConfig (404) → create POST carrying the values.
    rec = _Recorder(404, "")
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.apply_metallb_overrides(
        metallb_enabled=True,
        pool_addresses=["192.168.0.240/32"],
        bgp_enabled=True,
        bgp_peers=[
            {
                "my_asn": 65000,
                "peer_asn": 65001,
                "peer_address": "203.0.113.1",
                "peer_port": 1179,
                "hold_time": "90s",
            }
        ],
        bgp_advertisements=[{"ip_address_pools": ["spatium-control-plane"]}],
    )

    assert (changed, err) == (True, None)
    body = next(json.loads(b) for m, _, b in rec.calls if m == "POST" and b)
    vals = body["spec"]["valuesContent"]
    assert "frrk8s:\n    enabled: true" in vals
    assert "bgp:\n    enabled: true" in vals
    assert '"myASN": 65000' in vals
    assert '"peerASN": 65001' in vals
    assert '"peerAddress": "203.0.113.1"' in vals
    assert '"peerPort": 1179' in vals
    assert '"holdTime": "90s"' in vals
    assert '"ipAddressPools": ["spatium-control-plane"]' in vals


def test_metallb_bgp_overrides_disabled_shape(monkeypatch) -> None:
    # No peers / bgp_enabled=False (default) — L2-only shape, matching
    # today's behavior unchanged. Also the shape a heartbeat renders
    # when the operator hasn't configured BGP at all.
    rec = _Recorder(404, "")
    monkeypatch.setattr(k8s_api, "_request", rec)

    changed, err = k8s_api.apply_metallb_overrides(
        metallb_enabled=True, pool_addresses=["192.168.0.240/32"]
    )

    assert (changed, err) == (True, None)
    body = next(json.loads(b) for m, _, b in rec.calls if m == "POST" and b)
    vals = body["spec"]["valuesContent"]
    assert "frrk8s:\n    enabled: false" in vals
    assert "bgp:\n    enabled: false" in vals
    assert "peers: []" in vals
    assert "advertisements: []" in vals


# ---- #1059: a scale-down is never written blind -----------------------------------

_HOLD = ("replacing ['ddipg-member-2']: the committed count 2 is short until the "
         "replacement is promoted")


def _cr(spec: int, ready: int | None, reported: int | None, affinity: dict | None = None) -> str:
    status = {}
    if ready is not None:
        status["readyInstances"] = ready
    if reported is not None:
        status["instances"] = reported
    return json.dumps({"spec": {"instances": spec, "affinity": affinity or _SETTLED_AFFINITY},
                       "status": status})


def test_scale_down_is_deferred_while_the_cluster_reports_fewer_ready_than_instances(
    monkeypatch,
) -> None:
    """The refused branch, live on nightly-2026.09.13: the dead node's pod had
    gone NotReady before the tick, CNPG would not take the smaller spec, and
    writing it only stopped the operator re-creating the instance until the
    promote — Postgres two of three for 860 s. Nothing is written now."""
    rec = _Recorder(200, _cr(3, ready=2, reported=3))
    monkeypatch.setattr(k8s_api, "_request", rec)

    res = k8s_api.patch_cnpg_instances(2)

    assert not rec.patched
    assert (res.changed, res.scaled, res.error) == (False, False, None)
    assert res.deferred == "readyInstances 2 < instances 3"
    assert (res.current, res.ready, res.reported) == (3, 2, 3)
    changed, err = res  # the (changed, error) contract still unpacks
    assert (changed, err) == (False, None)


def test_scale_down_is_held_on_an_eviction_tick_even_when_every_pod_reads_ready(
    monkeypatch,
) -> None:
    """The honoured branch: on the eviction tick the dead node's pod still
    reads Ready (node-monitor grace), so CNPG WOULD take the smaller spec and
    delete the highest-serial ready non-primary instance — a healthy replica
    unless the serial happens to be the dead node's. The caller holds it
    (heartbeat._ReplaceHold, from that tick until the count is back)."""
    rec = _Recorder(200, _cr(3, ready=3, reported=3))
    monkeypatch.setattr(k8s_api, "_request", rec)

    res = k8s_api.patch_cnpg_instances(2, scale_down=False, hold_reason=_HOLD)

    assert not rec.patched
    assert res.scaled is False
    assert res.deferred == _HOLD


def test_scale_down_proceeds_on_a_whole_cluster_when_nothing_holds_it(monkeypatch) -> None:
    """A real demote: every instance ready, no eviction in flight."""
    rec = _Recorder(200, _cr(3, ready=3, reported=3))
    monkeypatch.setattr(k8s_api, "_request", rec)

    res = k8s_api.patch_cnpg_instances(2)

    assert rec.patch_body["spec"]["instances"] == 2
    assert (res.changed, res.scaled, res.deferred, res.error) == (True, True, "", None)


def test_scale_down_with_no_readiness_in_the_status_is_deferred(monkeypatch) -> None:
    rec = _Recorder(200, _cr(3, ready=None, reported=None))
    monkeypatch.setattr(k8s_api, "_request", rec)

    res = k8s_api.patch_cnpg_instances(2)

    assert not rec.patched
    assert res.deferred == "the Cluster reports no readiness yet"


def test_scale_up_is_never_deferred(monkeypatch) -> None:
    """A 1->3 promote scales up while the single instance is the only ready
    one; the guards are about shrinking, not growing."""
    rec = _Recorder(200, _cr(1, ready=1, reported=1))
    monkeypatch.setattr(k8s_api, "_request", rec)

    res = k8s_api.patch_cnpg_instances(3, scale_down=False, hold_reason=_HOLD)

    assert rec.patch_body["spec"]["instances"] == 3
    assert (res.scaled, res.deferred) == (True, "")


def test_a_deferred_scale_down_still_repairs_the_affinity(monkeypatch) -> None:
    """#590's affinity patch rides the same call and must not wait on the
    size: it lands alone, with no ``instances`` in the merge-patch."""
    rec = _Recorder(
        200,
        _cr(3, ready=2, reported=3,
            affinity={"enablePodAntiAffinity": True, "podAntiAffinityType": "preferred"}),
    )
    monkeypatch.setattr(k8s_api, "_request", rec)

    res = k8s_api.patch_cnpg_instances(2)

    assert rec.patched
    assert "instances" not in rec.patch_body["spec"]
    assert rec.patch_body["spec"]["affinity"]["podAntiAffinityType"] == "required"
    assert (res.changed, res.scaled) == (True, False)
    assert res.deferred == "readyInstances 2 < instances 3"
