"""Backend strings the console shows describe what ships (#1161).

Two backend channels reach console pages verbatim. The built-in roles'
descriptions are shown on Administration → Roles, refreshed from
``_BUILTIN_ROLES`` on every boot. The Operator Copilot tools' descriptions
are listed on the AI Tool Catalog page. The Appliance Operator role read
"(issue #134, Phase 4)", and five tool descriptions carried labels like
"#272 Phase 10": development-phase labels in shipped copy, the defect the
frontend's ``src/lib/console-copy.test.ts`` guards against. Same phrases.
"""

from __future__ import annotations

import re

from app.main import _BUILTIN_ROLES
from app.services.ai.tools import REGISTRY

PHRASES = (
    re.compile(r"\bPhase \d+[a-z]?\b"),
    re.compile(r"\bonce (?:those|these|the|its|their)\b[^.]{0,80}?\bships?\b", re.IGNORECASE),
    re.compile(r"\b(?:coming soon|not yet (?:implemented|supported|available))\b", re.IGNORECASE),
)


def _hits(text: str) -> list[str]:
    text = " ".join(text.split())
    return [m.group(0) for rx in PHRASES for m in rx.finditer(text)]


def test_the_phrases_still_catch_what_1161_found() -> None:
    """Negative control: a pattern that matches nothing passes both tests."""
    assert _hits("appliance management surface (issue #134, Phase 4): TLS")
    assert _hits("resolver VIPs (DNS :53 and DHCP relay :67, #272 Phase 10)")
    assert not _hits("resolver VIPs (DNS :53 and DHCP relay :67)")


def test_built_in_role_descriptions_describe_what_ships() -> None:
    hits = {
        name: _hits(description)
        for name, (description, _permissions) in _BUILTIN_ROLES.items()
        if _hits(description)
    }
    assert not hits, f"built-in role descriptions carry roadmap language: {hits}"


def test_copilot_tool_descriptions_describe_what_ships() -> None:
    hits = {
        tool.name: _hits(tool.description) for tool in REGISTRY.all() if _hits(tool.description)
    }
    assert not hits, f"Copilot tool descriptions carry roadmap language: {hits}"


def test_appliance_operator_does_not_claim_full_control() -> None:
    """#2620 — the role reaches a node, not the Fleet surface.

    The upgrade-image store, Fleet member actions, MetalLB, the kube-api CIDRs
    and pairing take a superadmin, so "Full control" of the appliance
    management surface was false; the description names what still needs one.
    """
    desc, perms = _BUILTIN_ROLES["Appliance Operator"]
    assert "full control" not in desc.lower()
    assert "superadmin" in desc.lower()
    assert "upgrade-image store" in desc
    # #2620 changed only the description: the appliance grant is untouched,
    # beside the alert read every builtin role carries (#2588) and the
    # certificate-store grant the TLS store's own type needs (#3067).
    assert perms == [
        {"action": "admin", "resource_type": "appliance"},
        {"action": "admin", "resource_type": "certificate_store"},
        {"action": "read", "resource_type": "alert"},
    ]
