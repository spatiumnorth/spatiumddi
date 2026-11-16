"""Console paths named in Copilot tool descriptions must exist (#4334)."""

from __future__ import annotations

from app.services.ai.tools import REGISTRY

# Appliance page tabs (frontend AppliancePage.tsx) and the sub-sections the
# descriptions name beneath them.
_APPLIANCE_TABS = {
    "Fleet",
    "Cluster",
    "Logs & Diagnostics",
    "Maintenance",
    "Network & Host",
    "Firewall",
}
_SUBSECTIONS = {
    "Cluster": {"Overview", "Pods", "etcd snapshots"},
    "Fleet": {"Appliances", "Pairing codes", "Upgrade images"},
}


def _desc(name: str) -> str:
    tool = REGISTRY.get(name)
    assert tool is not None
    return " ".join(tool.description.split())


def test_vip_and_etcd_point_at_real_pages() -> None:
    vip = _desc("find_control_plane_vip")
    etcd = _desc("find_etcd_snapshots")
    assert "Fleet → Control plane" not in vip + etcd
    assert "Appliance → Network & Host" in vip
    assert "Appliance → Cluster → etcd snapshots" in etcd


def test_appliance_paths_in_descriptions_exist() -> None:
    seen = 0
    for tool in REGISTRY.all():
        text = " ".join(tool.description.split())
        assert "Fleet → Control plane" not in text, tool.name
        assert "Fleet → Firewall" not in text, tool.name
        for chunk in text.split("Appliance → ")[1:]:
            seen += 1
            tab = next((t for t in _APPLIANCE_TABS if chunk.startswith(t)), None)
            assert tab is not None, (tool.name, chunk[:40])
            rest = chunk[len(tab) :]
            if rest.startswith(" → ") and tab in _SUBSECTIONS:
                sub = rest[3:]
                assert any(sub.startswith(x) for x in _SUBSECTIONS[tab]), (tool.name, sub[:30])
    assert seen >= 4
