"""Shared fixtures for the supervisor tests."""

from __future__ import annotations

import pytest

from spatium_supervisor import k8s_api


@pytest.fixture(autouse=True)
def _node_memory_for_dns_sizing(monkeypatch: pytest.MonkeyPatch) -> None:
    """#2223 — the role apply reads the node list to size dns-bind9's memory
    limit. Tests that stub the kubeapi piecemeal did not stub that read, and an
    unreadable node list fails the apply by design, so give every test an 8 GiB
    cluster (the 2Gi floor, the chart's own default). The sizing tests replace
    it with their own."""
    monkeypatch.setattr(k8s_api, "dns_sizing_memory_mib", lambda **_k: (8192, None))
