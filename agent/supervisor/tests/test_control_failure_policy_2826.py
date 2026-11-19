"""The spatium-control HelmChartConfig the supervisor creates runs the release
under ``failurePolicy: retry`` (#2826).

helm-controller hands klipper-helm a HelmChartConfig's failurePolicy in place of
its HelmChart's, and the HelmChartConfig CRD defaults an omitted failurePolicy to
``reinstall`` (helm-controller v0.17.9, the one k3s v1.36.5+k3s1 embeds:
``getJobAndRelatedResources`` and ``HelmChartConfigSpec``). The control release's
HelmChart asks for ``retry`` and firstboot pins the Config to ``retry`` on every
boot (#1299), but on a fresh appliance whose first-boot pin could not read the
Config, the supervisor created it at the first promote with ``valuesContent``
alone. It read ``reinstall`` until the seed's next boot, and two override writes
44 s apart left the release failed, so klipper-helm uninstalled it and installed
it again.

The stand-in applies the CRD's default to a create that omits the policy, as the
apiserver does, so each test reads the policy the CR ends up with.
"""

from __future__ import annotations

import json

import yaml

from spatium_supervisor import k8s_api

_CFG = "/helmchartconfigs/"
# HelmChartConfigSpec.FailurePolicy is ``+kubebuilder:default=reinstall``.
_CRD_DEFAULT = "reinstall"


class _Kube:
    """kubeapi stand-in holding each HelmChartConfig's whole ``spec`` (a GET of
    anything else is a 404, as for a HelmChart the test does not model).

    A create without ``failurePolicy`` stores the CRD's default; a merge-patch
    replaces only the ``spec`` keys it carries, and honours a
    ``metadata.resourceVersion`` precondition (409 on a mismatch)."""

    def __init__(self, specs: dict[str, dict] | None = None):
        self.specs: dict[str, dict] = {n: dict(s) for n, s in (specs or {}).items()}
        self.rv: dict[str, int] = {n: 1 for n in self.specs}
        self.writes: list[tuple[str, str, dict]] = []

    @staticmethod
    def _name(path: str) -> str:
        return path.rstrip("/").rsplit("/", 1)[-1]

    def __call__(self, method, path, body=None, content_type=None):
        if method == "GET":
            name = self._name(path)
            if _CFG not in path or name not in self.specs:
                return (404, "")
            meta = {"name": name, "resourceVersion": str(self.rv[name])}
            return (200, json.dumps({"metadata": meta, "spec": self.specs[name]}))
        payload = json.loads(body)
        if method == "POST":
            name = payload["metadata"]["name"]
            if name in self.specs:
                return (409, '{"reason":"AlreadyExists"}')
            spec = dict(payload["spec"])
            spec.setdefault("failurePolicy", _CRD_DEFAULT)
            self.specs[name] = spec
            self.rv[name] = 1
        elif method == "PATCH":
            name = self._name(path)
            want = (payload.get("metadata") or {}).get("resourceVersion")
            if want is not None and want != str(self.rv[name]):
                return (409, '{"reason":"Conflict"}')
            self.specs[name].update(payload["spec"])
            self.rv[name] += 1
        else:
            raise AssertionError(f"unexpected {method} {path}")
        self.writes.append((method, name, payload))
        return (201 if method == "POST" else 200, "{}")

    def policy(self, name: str) -> str:
        return self.specs[name]["failurePolicy"]

    def values(self, name: str) -> dict:
        return yaml.safe_load(self.specs[name].get("valuesContent") or "") or {}


def _promote(cp_size: int):
    return k8s_api.apply_control_plane_overrides(cp_size, "", web_ui_allowed_cidrs=[])


def test_the_first_promote_creates_the_control_config_under_retry(monkeypatch) -> None:
    """The reported formation: no Config when the first promote's overrides are
    written, so the supervisor creates it. It must not take the CRD's default."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _promote(2) == (True, None)

    assert [(m, n) for m, n, _ in kube.writes] == [("POST", "spatium-control")]
    assert kube.writes[0][2]["spec"]["failurePolicy"] == "retry"
    assert kube.policy("spatium-control") == "retry"
    assert kube.values("spatium-control")["api"]["replicas"] == 2


def test_the_next_promote_patches_the_values_and_keeps_retry(monkeypatch) -> None:
    """The formation's second write (three nodes, 44 s after the first on the
    reported walk) is a merge-patch of valuesContent, which leaves the policy."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    _promote(2)

    assert _promote(3) == (True, None)

    method, _, patch = kube.writes[-1]
    assert method == "PATCH"
    assert "failurePolicy" not in patch["spec"]
    assert kube.policy("spatium-control") == "retry"
    assert kube.values("spatium-control")["api"]["replicas"] == 3


def test_a_deleted_control_config_is_created_again_under_retry(monkeypatch) -> None:
    """The supervisor's advice for a Config it cannot read is to delete it
    (``_merge_owned_overrides``). The next beat creates it again, under retry."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)
    _promote(3)
    del kube.specs["spatium-control"]

    assert _promote(3) == (True, None)

    assert [m for m, _, _ in kube.writes] == ["POST", "POST"]
    assert kube.policy("spatium-control") == "retry"


def test_an_existing_control_config_keeps_the_policy_it_has(monkeypatch) -> None:
    """Only the create sets the policy. The supervisor's write to a Config that
    exists stays a merge-patch of valuesContent alone (#2024), so the policy an
    existing Config carries is the one firstboot's pin gave it (#1299)."""
    kube = _Kube({"spatium-control": {"failurePolicy": "abort", "valuesContent": ""}})
    monkeypatch.setattr(k8s_api, "_request", kube)

    assert _promote(3) == (True, None)

    method, _, patch = kube.writes[-1]
    assert method == "PATCH"
    assert set(patch["spec"]) == {"valuesContent"}
    assert kube.policy("spatium-control") == "abort"


def test_the_other_configs_are_created_without_a_policy(monkeypatch) -> None:
    """firstboot renders a failurePolicy for the control chart alone, so the
    MetalLB and appliance HelmCharts run under the CRD's default, and a Config
    the supervisor creates for them leaves their policy where their chart has
    it rather than overriding it."""
    kube = _Kube()
    monkeypatch.setattr(k8s_api, "_request", kube)

    k8s_api.apply_metallb_overrides(metallb_enabled=True, pool_addresses=["192.0.2.10/32"])
    k8s_api.apply_dataplane_vip_overrides(dns_vip="192.0.2.53", dhcp_relay_vip="")

    created = {n: p["spec"] for m, n, p in kube.writes if m == "POST"}
    assert set(created) == {"spatium-metallb", "spatiumddi-appliance"}
    assert all("failurePolicy" not in spec for spec in created.values())
