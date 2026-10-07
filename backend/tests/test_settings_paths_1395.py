"""Every place in Settings the backend's copy sends an operator to exists (#1395).

Module descriptions on the Features & Integrations page, AI tool descriptions on
the AI Tool Catalog, the Copilot's instructions to the model, alert texts and
API error details told operators to turn things on under "Settings → …" places
the Settings page does not have: "Settings → Import → DNS surface",
"Settings → AI → Tool Catalog", "Settings → Backup", "Settings → Features",
"Settings → Appliance → SNMP", and raw column names such as
"Settings → acme_enabled" and "Settings → firewall_enabled". The switches live
on other pages (Administration → Import, Administration → AI Tool Catalog,
Appliance → Firewall, Features & Integrations, …) or, for a few, have no
console control at all.

This walks every string constant in ``app/`` (docstrings and comments are not
copy) and fails on a "Settings → …" path whose first step is neither a group
nor a section of the Settings page's sidebar, or whose second step is not a
section of that group. The sidebar is ``SECTIONS`` in
``frontend/src/pages/SettingsPage.tsx``; it is mirrored below rather than read,
because a backend test that reads ``frontend/`` would have to declare the read
as must-run for every frontend change (see test_ci_backend_relevant.py). The
frontend's own copy is held against that file directly by
``frontend/src/lib/settings-paths.test.ts``.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"

#: The Settings page's sidebar: each group and its sections, as SECTIONS in
#: frontend/src/pages/SettingsPage.tsx lists them.
SETTINGS_SIDEBAR: dict[str, tuple[str, ...]] = {
    "Application": ("Branding & URL", "Updates"),
    "Security": (
        "Account Lockout",
        "Agent bootstrap keys",
        "Audit Event Forwarding",
        "Maintenance Mode",
        "Password Policy",
        "Session & Security",
    ),
    "IPAM": (
        "IP Allocation",
        "OUI Vendor Lookup",
        "Device Profiling",
        "Subnet Tree UI",
        "Utilization Thresholds",
        "Reverse DNS (PTR)",
    ),
    "DNS": (
        "DNS Defaults",
        "IPAM → DNS Reconciliation",
        "Zone ↔ Server Reconciliation",
        "TLD Registry",
    ),
    "DHCP": ("DHCP Defaults", "DHCP Lease Sync"),
    "Network": ("ASN Refresh", "Domain Refresh", "VRF Validation"),
    "Metrics": ("InfluxDB Export",),
    "AI": ("Operator Daily Digest",),
}

#: Another product's Settings, named where its own steps are walked.
ALLOWED = {
    # NetBird's own dashboard, where its API token is created.
    "services/netbird/client.py: Settings → Users in the NetBird dashboard",
}

PATH = re.compile(r"Settings\s*(?:→|->)\s*([^\n.,;:()\"“”]+)")
#: "System → Settings → LLDP": a Settings step inside another product's path.
INSIDE_ANOTHER_PATH = re.compile(r"(?:→|->)\s*(?:\w+\s+)?$")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.lower().replace("&", "and")).strip()


def _begins(said: str, name: str) -> bool:
    """ "IPAM and vendors come back empty" names the IPAM group."""
    return said == name or said.startswith(f"{name} ")


def _exists(path: str) -> bool:
    first, *rest = (_norm(step) for step in re.split(r"\s*(?:→|->)\s*", path))
    second = rest[0] if rest else None
    for group, sections in SETTINGS_SIDEBAR.items():
        if _begins(first, _norm(group)):
            return second is None or any(_begins(second, _norm(s)) for s in sections)
    return any(_begins(first, _norm(s)) for ss in SETTINGS_SIDEBAR.values() for s in ss)


def _copy(tree: ast.Module) -> list[tuple[int, str]]:
    """Every string constant that is not a docstring: the copy of one module."""
    docstrings: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                docstrings.add(id(body[0].value))
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def _dead_paths(rel: str, texts: list[tuple[int, str]]) -> list[str]:
    dead = []
    for lineno, text in texts:
        for m in PATH.finditer(text):
            if INSIDE_ANOTHER_PATH.search(text[: m.start()]):
                continue
            said = f"Settings → {m.group(1).strip()}"
            if f"{rel}: {said}" in ALLOWED:
                continue
            if not _exists(m.group(1).strip()):
                dead.append(f"{rel}:{lineno}: {said!r} in {text.strip()[:160]!r}")
    return dead


def test_backend_copy_sends_operators_only_to_settings_places_that_exist() -> None:
    dead: list[str] = []
    for path in sorted(APP.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        if not re.search(r"Settings\s*(?:→|->)", source):
            continue
        dead += _dead_paths(path.relative_to(APP).as_posix(), _copy(ast.parse(source)))
    assert not dead, (
        "Copy that sends the operator to a Settings place the Settings page does not "
        "have. Name the place where the control really is (Features & Integrations, "
        "Administration → …, Appliance → …):\n  " + "\n  ".join(dead)
    )


def test_the_scan_sees_the_dead_paths_1395_found_and_passes_real_ones() -> None:
    """Negative control: a scanner that matched nothing would pass the test above."""
    sample = ast.parse(
        "A = ('One-shot import. Settings → Import → DNS surface; sources gate.')\n"
        "B = 'master switch (Settings → firewall_enabled, default OFF)'\n"
        "C = f'enable {name!r} under Settings → AI → Tool Catalog. Do not retry.'\n"
        "D = 'when False, OUI lookup is disabled in Settings → IPAM and vendors come back empty.'\n"
        "E = 'Rotate it from Settings → Security → Session & Security.'\n"
        "F = 'Open System → Settings → LLDP on the firewall.'\n"
        "def f():\n    'Settings → Nowhere in a docstring is not copy.'\n"
    )
    dead = "\n".join(_dead_paths("sample.py", _copy(sample)))
    assert "Settings → Import → DNS surface" in dead
    assert "Settings → firewall_enabled" in dead
    assert "Settings → AI → Tool Catalog" in dead
    assert "IPAM" not in dead
    assert "Session" not in dead
    assert "LLDP" not in dead
    assert "Nowhere" not in dead
