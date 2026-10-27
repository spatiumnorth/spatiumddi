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


@pytest.fixture(autouse=True)
def _no_apply_grace_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    """#2833 — ``watchdog.note_apply`` stamps module state, and a role apply in
    one test must not put the next test's watchdog pass inside its grace."""
    from spatium_supervisor import watchdog

    monkeypatch.setattr(watchdog, "_last_apply_at", None, raising=False)
