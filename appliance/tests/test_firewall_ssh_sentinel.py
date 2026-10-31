"""The SSH source-CIDR allowlist can finally be enforced (#1009).

``ssh_allowed_source_networks`` has shipped since #157 and, on the default
port, restricted nothing.  ``/etc/nftables.conf`` opened ``tcp dport 22``
unconditionally in its management floor, ABOVE the
``include "/etc/nftables.d/*.nft"`` glob that pulls in the scoped rule
``spatiumddi-ssh-reload`` renders — and nftables is first-match-wins, so the
scoped rule was dead code.  Verified against a real kernel while #1001 was
written: both rules load, the unconditional one lists first.

The floor moves here, to a baked sentinel, for exactly one reason: a rule in
the base config cannot be taken out of the chain, and one in this directory
can — by the same ``apply_sentinel_directive`` machinery
``00-spatium-webui.nft`` has used since #769.

Retiring it removes what ``docs/design/FLEET_FIREWALL.md`` §6.1 calls the
irreducible recovery channel and R1 names as the mitigation for every OTHER
firewall risk, so it happens only under ``ssh_lockdown`` — a second,
default-off switch, which is the shape §6.1 specified (as
``firewall_mgmt_lockdown``) and the anti-lockout pattern pfSense / OPNsense
ship.  An install that never opts in is byte-for-byte unchanged.

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_firewall_ssh_sentinel.py -v

No appliance, no nftables, no root — this reads the shipped files.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NFT_DIR = REPO / "appliance/mkosi.extra/etc/nftables.d"
SENTINEL = NFT_DIR / "00-spatium-ssh.nft"
WEBUI_SENTINEL = NFT_DIR / "00-spatium-webui.nft"
RELOAD = REPO / "appliance/mkosi.extra/usr/local/bin/spatium-firewall-reload"
REVERT = REPO / "appliance/mkosi.extra/usr/local/bin/spatiumddi-firewall-revert"
SSH_RELOAD = REPO / "appliance/mkosi.extra/usr/local/bin/spatiumddi-ssh-reload"
BASE_CONF = REPO / "appliance/mkosi.extra/etc/nftables.conf"


def _text(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def _one(p: Path, pattern: str) -> str:
    """The single regex capture in ``p``, or a loud failure.

    Deliberately asserts on the match count: a renamed or reformatted
    declaration must fail the extraction rather than quietly yield the first
    of several, or none.
    """
    hits = re.findall(pattern, _text(p), re.MULTILINE)
    assert len(hits) == 1, f"{p.name}: {pattern!r} matched {len(hits)}x"
    return hits[0]


def _rules(p: Path) -> list[str]:
    return [
        ln.strip()
        for ln in _text(p).splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]


# --------------------------------------------------------------------------
# 1. the floor still exists, and still opens 22 from a cold boot
# --------------------------------------------------------------------------
def test_the_floor_is_baked_and_still_opens_port_22() -> None:
    """Moving it must not close it.

    This is the recovery channel for a bad Web-UI scope and a peer-CIDR typo
    alike, and it has to be live from the first boot — before the supervisor
    exists, and on a node whose drop-in has never rendered.
    """
    assert SENTINEL.is_file(), "the SSH escape hatch would be gone entirely"
    assert _rules(SENTINEL) == ['tcp dport 22 accept comment "ssh-floor"']


def test_it_is_a_bare_rule_like_its_sibling() -> None:
    """The glob includes these INSIDE ``chain input``.

    A ``table``/``chain`` wrapper here fails the whole transactional
    ``nft -f`` at boot — which is fail-OPEN, no input filtering at all.
    """
    # Rule lines only — the header prose necessarily says "chain input".
    for rule in _rules(SENTINEL):
        assert not rule.startswith(("table ", "chain ", "add rule"))
        assert "{" not in rule and "}" not in rule


def test_it_sorts_before_the_scoped_rule_and_the_supervisor_drop_in() -> None:
    """Ordering IS the mechanism, in both directions.

    While present the floor must win over ``50-spatium-ssh.nft`` (that is what
    makes it a floor); once retired, the scoped rule is what remains, and it
    must in turn win over the management line in ``spatium-role.nft``.

    The three names are read from the places that actually produce them — the
    shipped file on disk, and the two runners' own path constants — rather
    than restated here. A test that sorts its own literals exercises
    ``sorted()``: rename the sentinel to ``60-…`` and lockdown silently stops
    enforcing, with the literal version still green.
    """
    floor = SENTINEL.name

    scoped = _one(SSH_RELOAD, r"^NFT_DROPIN=/etc/nftables\.d/(\S+)$")
    role = _one(RELOAD, r"^DROP_IN=/etc/nftables\.d/(\S+)$")

    glob_order = sorted([floor, scoped, role])
    assert glob_order == [floor, scoped, role], (
        f"the include glob applies these in the order {glob_order}, but the "
        f"mechanism needs floor({floor}) < scoped({scoped}) < role({role}) — "
        "nftables accepts on first match"
    )


def test_the_base_conf_no_longer_opens_22_itself() -> None:
    """The whole point: a rule in the base config cannot be retired.

    Leaving it there would keep the allowlist dead however correctly
    everything else behaves — which is the #1009 bug.
    """
    for line in _text(BASE_CONF).splitlines():
        code = line.split("#", 1)[0].strip()
        assert code != "tcp dport 22 accept", (
            "the port-22 accept is back in the base config, where it cannot be "
            "retired — the ssh allowlist is dead code again (#1009)"
        )


def test_the_base_conf_still_includes_the_drop_in_glob() -> None:
    """...and the floor is only still open because of this line."""
    assert 'include "/etc/nftables.d/*.nft"' in _text(BASE_CONF)


# --------------------------------------------------------------------------
# 2. the runners manage it
# --------------------------------------------------------------------------
def test_the_reload_runner_manages_all_three_sentinels() -> None:
    body = _text(RELOAD)
    for directive in ("spatium-bootstrap", "spatium-webui", "spatium-ssh"):
        assert f'"{directive}"' in body, directive
    # Three CALLS (the definition is ``apply_sentinel_directive() {``, no
    # space) — a directive declared but never applied is the failure this
    # catches, and it would look exactly like success.
    assert body.count("apply_sentinel_directive ") == 3


def test_the_reload_runner_snapshots_the_ssh_state_for_revert() -> None:
    """A test-apply that retires the floor must be undoable.

    This is the sharpest case the revert plane covers: retiring the floor is
    the only change in it that can close the operator's OWN session, so a
    revert that left it retired would strand them on the one ruleset nobody
    confirmed.
    """
    body = _text(RELOAD)
    assert "LAST_GOOD_SSH_SENTINEL" in body
    for state in ("present", "retired", "absent"):
        assert f'echo {state} | state_write "$LAST_GOOD_SSH_SENTINEL"' in body, state


def test_the_revert_runner_restores_the_ssh_sentinel() -> None:
    body = _text(REVERT)
    assert (
        'restore_sentinel_state "$LAST_GOOD_SSH_SENTINEL" "$SSH_SENTINEL" '
        '"$SSH_SENTINEL_RETIRED"' in body
    )
    assert '"$LAST_GOOD_SSH_SENTINEL"' in body.split("rm -f")[-1]


def test_the_sentinel_paths_agree_across_both_runners() -> None:
    """Two files, one path. A typo here retires nothing and reverts nothing,
    silently — both runners would still report success."""
    for body in (_text(RELOAD), _text(REVERT)):
        assert "SSH_SENTINEL=/etc/nftables.d/00-spatium-ssh.nft" in body
        assert 'SSH_SENTINEL_RETIRED="$SSH_SENTINEL.retired"' in body


# --------------------------------------------------------------------------
# 3. the pair that must move together
# --------------------------------------------------------------------------
def test_retiring_the_floor_alone_would_not_be_enough() -> None:
    """The renderers emit a SECOND unconditional accept, after the scoped one.

    ``spatium-role.nft`` sorts after ``50-spatium-ssh.nft`` in the glob, so a
    packet the scoped rule declined would fall straight through to it. The
    renderers therefore scope that line under lockdown too — this test exists
    so a future edit that retires the sentinel without scoping the management
    line (or vice versa) fails rather than half-working.
    """
    renderers = [
        REPO / "agent/supervisor/spatium_supervisor/firewall_renderer.py",
        REPO / "backend/app/services/appliance/firewall.py",
        REPO / "backend/app/services/appliance/firewall_merge.py",
    ]
    for path in renderers:
        if not path.is_file():
            continue
        body = _text(path)
        assert "# spatium-ssh: {ssh_action}" in body, f"{path.name}: no directive"
        assert "ssh_scope_cidrs" in body, f"{path.name}: floor not scoped under lockdown"


def test_the_ssh_reload_runner_still_renders_the_scoped_rule() -> None:
    """The other half of the pair, from #1001. Retiring the floor is only
    useful because this rule is waiting behind it."""
    body = _text(SSH_RELOAD)
    assert 'python3 - "$PORT" "$CIDR_JSON"' in body
    assert "ip saddr" in body
