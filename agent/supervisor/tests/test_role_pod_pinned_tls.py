"""Role pods verify the control plane against the supervisor's pin (#1281).

The DNS, DHCP and looking-glass pods on an off-cluster appliance used to be
rendered with SPATIUM_INSECURE_SKIP_TLS_VERIFY=1 whenever they were given the
external control-plane URL, sending the agent key out and taking their
configuration back over a connection nobody verified. The chart now mounts the
supervisor's tls/ directory and sets TLS_PINNED_CERTS_PATH instead.

Two halves have to agree, and neither can see the other:

* the chart must point the agents at the file ``cp_tls`` actually writes; and
* the supervisor must never hand the external URL to the agents of a node
  whose supervisor has stopped maintaining the pin. A control-plane member
  heartbeats in-cluster, so it never re-pins, while a member joining re-mints
  the Web UI certificate: verifying the external URL there would fail on the
  first join after a promotion. So a member's agents get no external URL, and
  the apply key moves when membership does, or a promotion would change
  nothing the heartbeat compares and the agents would keep the stale path.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from spatium_supervisor import appliance_state, cp_tls, heartbeat, service_lifecycle

REPO = Path(__file__).resolve().parents[3]
CHART = REPO / "charts" / "spatiumddi-appliance"
ROLE_TEMPLATES = {
    "dns-bind9": "dnsBind9",
    "dns-powerdns": "dnsPowerdns",
    "dns-technitium": "dnsTechnitium",
    "dhcp-kea": "dhcpKea",
    "looking-glass": "lookingGlass",
}
AGENT_BLOCKS = tuple(ROLE_TEMPLATES.values())
EXTERNAL = "https://cp.example"
KEYS = {"DNS_AGENT_KEY": "a" * 48, "DHCP_AGENT_KEY": "b" * 48, "LG_AGENT_KEY": "c" * 48}


@pytest.fixture
def member(monkeypatch: pytest.MonkeyPatch):
    """Set whether this node is a control-plane member."""

    def set_member(value: bool) -> None:
        monkeypatch.setattr(appliance_state, "is_control_plane_member", lambda: value)

    return set_member


# ── which URL the agents get ─────────────────────────────────────────────────


def test_an_off_cluster_node_gives_its_agents_the_external_url(member) -> None:
    member(False)
    values = service_lifecycle._build_values(
        ["dns-bind9", "dhcp", "looking-glass"], {"CONTROL_PLANE_URL": EXTERNAL, **KEYS}
    )
    assert {values[b]["controlPlaneUrl"] for b in AGENT_BLOCKS} == {EXTERNAL}


def test_a_member_gives_its_agents_no_external_url(member) -> None:
    """Empty makes the chart fall through to the in-cluster api Service, the
    path the member's own heartbeat takes."""
    member(True)
    values = service_lifecycle._build_values(
        ["dns-bind9", "dhcp", "looking-glass"], {"CONTROL_PLANE_URL": EXTERNAL, **KEYS}
    )
    assert {values[b]["controlPlaneUrl"] for b in AGENT_BLOCKS} == {""}


def test_membership_has_one_definition(monkeypatch: pytest.MonkeyPatch) -> None:
    """The heartbeat's in-cluster switch and the agents' must not disagree."""
    for value in (True, False):
        monkeypatch.setattr(
            appliance_state, "is_control_plane_member", lambda v=value: v
        )
        assert heartbeat._is_control_plane_member() is value


@pytest.mark.parametrize(
    ("variant", "join_state", "expected"),
    [
        ("control-plane", None, True),
        ("appliance", "ready", True),
        ("appliance", "joining", False),
        ("appliance", None, False),
        (None, None, False),
    ],
)
def test_membership_signals(
    monkeypatch: pytest.MonkeyPatch,
    variant: str | None,
    join_state: str | None,
    expected: bool,
) -> None:
    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: variant)
    monkeypatch.setattr(
        appliance_state, "read_cluster_join_state", lambda: (join_state, None)
    )
    assert appliance_state.is_control_plane_member() is expected


def test_a_promotion_moves_the_apply_key(
    member, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Nothing in the role env changes on a promotion, so without the URL in
    the key the heartbeat would skip the apply and leave the agents on the
    external URL against a pin nobody re-pins."""
    chart = tmp_path / "spatiumddi-appliance.tgz"
    chart.write_bytes(b"chart")
    monkeypatch.setattr(service_lifecycle, "_BAKED_CHART_TARBALL", chart)
    monkeypatch.setattr(service_lifecycle, "_chart_digest_cache", None)
    env = tmp_path / "role-compose.env"
    env.write_text(
        f"COMPOSE_PROFILES=dns-bind9\nCONTROL_PLANE_URL={EXTERNAL}\n", encoding="utf-8"
    )

    member(False)
    before = heartbeat._role_apply_key(env.read_text(), env)
    member(True)
    after = heartbeat._role_apply_key(env.read_text(), env)
    assert before != after


# ── the chart points at the file the supervisor writes ───────────────────────


def _helpers() -> str:
    return (CHART / "templates" / "_helpers.tpl").read_text(encoding="utf-8")


def _define(name: str) -> str:
    m = re.search(
        r'\{\{-? define "' + re.escape(name) + r'" -?\}\}(.*?)\{\{-? end -?\}\}',
        _helpers(),
        re.DOTALL,
    )
    assert m, name
    return m.group(1)


def test_the_agent_reads_the_pin_the_supervisor_writes() -> None:
    env = _define("spatiumddi-appliance.cpPin.env")
    mount = _define("spatiumddi-appliance.cpPin.mount")
    volume = _define("spatiumddi-appliance.cpPin.volume")

    pinned = re.search(r"value: (\S+)", env)
    mount_path = re.search(r"mountPath: (\S+)", mount)
    assert pinned and mount_path
    assert "name: TLS_PINNED_CERTS_PATH" in env
    # The file the agent reads is the pin, inside the mounted directory.
    assert pinned.group(1) == f"{mount_path.group(1)}/{cp_tls.PIN_FILENAME}"
    assert "readOnly: true" in mount
    # The mounted directory is the supervisor's <state dir>/tls on the host.
    assert cp_tls._pin_path(Path("/state")) == Path("/state/tls") / cp_tls.PIN_FILENAME
    assert 'printf "%s/tls" .Values.supervisor.hostMounts.stateDir' in volume
    # Never created by kubelet ahead of the supervisor (root-owned, unwritable).
    assert "type: Directory\n" in volume + "\n"


def test_the_supervisor_state_dir_is_the_host_path_the_chart_mounts() -> None:
    """The supervisor pod mounts the same hostPath as its state dir, so the
    pin it writes lands where the role pods look."""
    supervisor = (CHART / "templates" / "supervisor.yaml").read_text(encoding="utf-8")
    assert "path: {{ .Values.supervisor.hostMounts.stateDir }}" in supervisor


@pytest.mark.parametrize(("template", "block"), sorted(ROLE_TEMPLATES.items()))
def test_no_role_pod_skips_verification(template: str, block: str) -> None:
    text = (CHART / "templates" / f"{template}.yaml").read_text(encoding="utf-8")
    assert "SPATIUM_INSECURE_SKIP_TLS_VERIFY" not in text
    # Each of the three pieces, under the same external-URL guard.
    for piece in ("env", "mount", "volume"):
        pattern = (
            r"\{\{- if \.Values\." + block + r"\.controlPlaneUrl \}\}\s*"
            r'\{\{- include "spatiumddi-appliance\.cpPin\.' + piece + r'"'
        )
        assert re.search(pattern, text), (template, piece)
