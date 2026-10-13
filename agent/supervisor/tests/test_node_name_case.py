"""#1757 — k3s registers the Node under the LOWERCASED hostname, so the seed's
Node delete must not use an uppercase hostname as stored."""

from __future__ import annotations

from spatium_supervisor import k8s_api


def test_delete_node_uses_the_lowercase_node_name(monkeypatch) -> None:
    seen: list[tuple[str, str]] = []

    def kube(method: str, path: str, *a, **kw):
        seen.append((method, path))
        return 200, ""

    monkeypatch.setattr(k8s_api, "_request", kube)

    assert k8s_api.delete_node("Ddi-Member-1.") == (True, None)
    assert seen == [("DELETE", "/api/v1/nodes/ddi-member-1")]
