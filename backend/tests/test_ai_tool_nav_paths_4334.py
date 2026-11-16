"""Console paths named in Copilot text must exist in the console (#4334).

The Copilot is told where an operator changes something ("Appliance → Cluster →
etcd snapshots"). Those names were hand-typed and drifted: two tools sent the
operator to a "Fleet → Control plane" section that never existed. This reads the
labels the frontend actually defines (nav, Appliance tabs, Settings sections)
and checks every "X → Y" console path in ``app/services/ai`` against them.
"""

from __future__ import annotations

import re
from pathlib import Path

_SRC = Path(__file__).resolve().parents[2] / "frontend" / "src"
_AI = Path(__file__).resolve().parents[1] / "app" / "services" / "ai"


def _read(rel: str) -> str:
    return (_SRC / rel).read_text()


def _quoted(text: str, key: str) -> set[str]:
    return set(re.findall(rf'\b{key}\s*[:=]\s*"([^"]+)"', text))


def _labels() -> dict[str, set[str]]:
    nav = _read("lib/navigation.ts")
    sidebar = _read("components/layout/Sidebar.tsx")
    appliance = _read("pages/appliance/AppliancePage.tsx")
    settings = _read("pages/SettingsPage.tsx")
    admin_blob = " ".join(p.read_text() for p in (_SRC / "pages" / "admin").glob("*.tsx"))
    admin_nav = nav[nav.index("export const adminIdentityNav") :]
    admin_nav = admin_nav[: admin_nav.index("export const footerNav")]
    main = nav[nav.index("export const baseMainNav") : nav.index("export const coreIpamNav")]
    top = _quoted(main, "label") | _quoted(sidebar, "label")
    return {
        "top": top,
        "Appliance": _quoted(appliance, "label"),
        "Appliance/Fleet": _quoted(_read("pages/appliance/FleetTab.tsx"), "label"),
        "Appliance/Cluster": _quoted(_read("pages/appliance/ClusterTab.tsx"), "label"),
        "Settings": _quoted(settings, "title")
        | set(re.findall(r'\| "([A-Z][A-Za-z]+)"', settings)),
        "settings_blob": {settings.lower()},
        "Administration": _quoted(admin_nav, "label"),
        "admin_blob": {admin_blob.lower()},
        "DNS": {_read("pages/dns/DNSPage.tsx").lower()},
    }


# Names the parser cannot resolve, each with why. Keep this short.
_ALLOW = {
    # DNS page headings / menus are JSX text and an action menu, not labels.
    ("DNS", "Zones"),
    ("DNS", "Zone"),
    ("DNS", "Server Groups"),
    # Tailored instruction in the system prompt about the row's action menu.
    ("DNS", "Zones", "⋯ menu"),
}

_FIRST = (
    "Settings|Administration|Admin|Appliance|Fleet|Cluster|Platform Insights|DNS|DHCP|IPAM|"
    "Groups|Network|Integrations|Features & Integrations|Tools"
)
_PATH = re.compile(rf"(?<!\w)({_FIRST})((?: → [^→.;,:()\"'`*\n]+)*)")


def _starts(seg: str, labels: set[str]) -> bool:
    s = seg.strip().lower()
    return any(s.startswith(label.lower()) for label in labels)


def _paths() -> list[tuple[str, list[str], str]]:
    out = []
    for f in sorted(_AI.rglob("*.py")):
        text = f.read_text()
        # Fold wrapped string literals and wrapped comments back into one line.
        text = re.sub(r'["\']\s*\n\s*f?["\']', "", text)
        text = re.sub(r"\n\s*(?:#|\*)?\s*", " ", text)
        for m in _PATH.finditer(text):
            segs = [s.strip() for s in m.group(2).split(" → ")[1:]]
            if segs:
                out.append((f.name, [m.group(1), *segs], m.group(0)))
    return out


def _resolves(path: list[str], lab: dict[str, set[str]]) -> bool:
    first, rest = path[0], path[1:]
    if tuple(path) in _ALLOW or tuple(p for p in path[:2]) in _ALLOW and first == "DNS":
        return True
    if first == "Appliance":
        if not _starts(rest[0], lab["Appliance"]):
            return False
        tab = next((t for t in lab["Appliance"] if rest[0].lower().startswith(t.lower())), rest[0])
        sub = lab.get(f"Appliance/{tab}")
        return len(rest) == 1 or sub is None or _starts(rest[1], sub | lab["Appliance/Fleet"])
    if first == "Settings":
        blob = next(iter(lab["settings_blob"]))
        return _starts(rest[0], lab["Settings"]) and all(s.lower() in blob for s in rest[1:])
    if first == "Administration":
        if not _starts(rest[0], lab["Administration"]):
            return False
        blob = next(iter(lab["admin_blob"]))
        return all(re.sub(r" (tab|form|page)$", "", s.lower()) in blob for s in rest[1:])
    if first == "Platform Insights":
        return False  # a page under Administration, never a section of its own
    if first in ("DNS", "DHCP", "IPAM", "Network", "Integrations", "Tools"):
        return first in lab["top"] or first == "Network"
    return first in lab["top"]


def test_console_paths_in_ai_text_exist() -> None:
    lab = _labels()
    assert {"Fleet", "Cluster", "Network & Host", "Firewall"} <= lab["Appliance"]
    paths = _paths()
    assert len(paths) >= 8, "path scan found almost nothing; the regex is broken"
    bad = [(f, raw) for f, p, raw in paths if not _resolves(p, lab)]
    assert not bad, f"console paths that do not exist: {bad}"


def test_old_vip_and_etcd_pointers_are_gone() -> None:
    blob = " ".join(p.read_text() for p in _AI.rglob("*.py"))
    assert "Fleet → Control plane" not in blob
    assert "Appliance → Network & Host" in blob
    assert "Appliance → Cluster → etcd snapshots" in blob
