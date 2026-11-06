"""Every long-poll proxy thread must reach its first poll (#1072).

The supervisor starts four of these from ``__main__`` — k8s, nettool,
storage, pcap — each a daemon thread whose body is ``with httpx.Client(...)
as client: while True: try: _once(...) except Exception: ...``. The guard
is INSIDE the ``with``, so anything that goes wrong while building the
client ends the thread with nothing but a traceback in the pod log; the
process, the heartbeat and the Fleet page all carry on looking healthy.
That is how the storage loop shipped dead on every appliance (#1072): it
read ``cfg.verify_tls``, which ``SupervisorConfig`` never had, and none of
its tests entered the loop.

So each loop is driven here with a config built the way
``SupervisorConfig.from_env`` builds it — the real frozen dataclass, no
attribute stand-ins — and its poll stubbed to end the loop after one pass.
A loop that cannot get that far fails here instead of on the fleet.
"""

from __future__ import annotations

from pathlib import Path
from types import ModuleType

import pytest

from spatium_supervisor import k8s_proxy, nettools_proxy, pcap_proxy, storage_proxy
from spatium_supervisor.config import SupervisorConfig
from spatium_supervisor.identity import load_or_generate


class _FirstPassDone(BaseException):
    """Ends the forever-loop. A ``BaseException`` so the loop's
    ``except Exception`` guard cannot swallow it and hang the test."""


def _bare_config(state_dir: Path) -> SupervisorConfig:
    """Exactly the seven fields ``from_env`` populates, nothing stapled on."""
    return SupervisorConfig(
        control_plane_url="https://control-plane.example",
        hostname="qa-node",
        state_dir=state_dir,
        bootstrap_pairing_code="",
        heartbeat_interval_seconds=30,
        k8s_proxy_enabled=False,
        in_pod_firewall_enabled=True,
    )


_LOOPS = [
    pytest.param(k8s_proxy, "proxy_loop_forever", "_proxy_once", id="k8s"),
    pytest.param(nettools_proxy, "nettool_loop_forever", "_nettool_once", id="nettool"),
    pytest.param(storage_proxy, "storage_loop_forever", "_storage_once", id="storage"),
    pytest.param(pcap_proxy, "pcap_loop_forever", "_pcap_once", id="pcap"),
]


@pytest.mark.parametrize(("module", "loop_name", "once_name"), _LOOPS)
def test_the_loop_reaches_its_first_poll(
    module: ModuleType,
    loop_name: str,
    once_name: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []

    def _once(*args: object) -> None:
        calls.append(args)
        raise _FirstPassDone

    monkeypatch.setattr(module, once_name, _once)
    identity, _ = load_or_generate(tmp_path)
    with pytest.raises(_FirstPassDone):
        getattr(module, loop_name)(_bare_config(tmp_path), identity)
    assert len(calls) == 1


def test_k8s_proxy_is_on_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # #3618: nothing ever set K8S_PROXY_ENABLED, so the Fleet pod list and
    # logs always 504'd. Unset means on; an explicit false is the opt-out.
    monkeypatch.delenv("K8S_PROXY_ENABLED", raising=False)
    assert SupervisorConfig.from_env().k8s_proxy_enabled is True
    monkeypatch.setenv("K8S_PROXY_ENABLED", "false")
    assert SupervisorConfig.from_env().k8s_proxy_enabled is False


def test_k8s_proxy_polls_the_in_cluster_url_on_a_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # #3618: a cluster member has an empty CONTROL_PLANE_URL; the poll and
    # reply URLs must come from _effective_control_plane_url, not the raw cfg.
    from spatium_supervisor import appliance_state, heartbeat

    monkeypatch.setattr(appliance_state, "is_control_plane_member", lambda: True)
    monkeypatch.setattr(appliance_state, "detect_runtime", lambda: "k3s")
    monkeypatch.setattr(k8s_proxy, "load_appliance_id", lambda _d: "app-1")
    monkeypatch.setattr(k8s_proxy, "load_cert", lambda _d: "CERT")
    monkeypatch.setattr(k8s_proxy, "build_auth_headers", lambda *a, **k: {})
    monkeypatch.setattr(k8s_proxy, "_call_local_kubeapi", lambda *a, **k: (200, b"{}"))
    urls: list[str] = []

    class _Resp:
        def __init__(self, body: dict[str, object]) -> None:
            self.status_code = 200
            self._body = body

        def json(self) -> dict[str, object]:
            return self._body

    class _Client:
        def post(self, url: str, **_k: object) -> _Resp:
            urls.append(url)
            return _Resp({"request_id": "r1", "method": "GET", "path": "/x"})

    cfg = SupervisorConfig(
        control_plane_url="",
        hostname="member",
        state_dir=tmp_path,
        bootstrap_pairing_code="",
        heartbeat_interval_seconds=30,
        k8s_proxy_enabled=True,
        in_pod_firewall_enabled=True,
    )
    identity, _ = load_or_generate(tmp_path)
    k8s_proxy._proxy_once(cfg, identity, _Client())  # type: ignore[arg-type]
    base = heartbeat._IN_CLUSTER_CONTROL_PLANE_URL.rstrip("/")
    assert len(urls) == 2
    assert all(
        u.startswith(base + "/api/v1/appliance/supervisor/k8s-proxy/") for u in urls
    )
