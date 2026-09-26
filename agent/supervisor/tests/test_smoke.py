"""Smoke tests for the Phase A1 scaffolding.

These are intentionally thin — Phase A1 has no real behaviour to test.
Wave A2+ will add tests for the bootstrap → register → poll cycle, the
identity keypair generator, etc.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import spatium_supervisor
from spatium_supervisor.config import SupervisorConfig
from spatium_supervisor.state import ensure_layout


def _version_with(monkeypatch, stamp: str | None) -> str:
    if stamp is None:
        monkeypatch.delenv("SPATIUM_SUPERVISOR_VERSION", raising=False)
    else:
        monkeypatch.setenv("SPATIUM_SUPERVISOR_VERSION", stamp)
    try:
        return importlib.reload(spatium_supervisor).__version__
    finally:
        monkeypatch.undo()
        importlib.reload(spatium_supervisor)


def test_version_is_the_build_stamp(monkeypatch) -> None:
    """#1183: the image stamps the release it was built from. The version
    was a literal nothing rewrote, so every supervisor reported it."""
    assert _version_with(monkeypatch, "2026.09.25-1") == "2026.09.25-1"
    assert _version_with(monkeypatch, " 1.0.0\n") == "1.0.0"


def test_an_unstamped_build_reports_dev(monkeypatch) -> None:
    """Not a release-shaped placeholder: the control plane's version gates
    must read an unstamped build as unknown, never as some old release."""
    assert _version_with(monkeypatch, None) == "dev"
    assert _version_with(monkeypatch, "") == "dev"


def test_config_defaults_from_empty_env(monkeypatch) -> None:
    for k in (
        "CONTROL_PLANE_URL",
        "APPLIANCE_HOSTNAME",
        "STATE_DIR",
        "BOOTSTRAP_PAIRING_CODE",
        "HEARTBEAT_INTERVAL_SECONDS",
    ):
        monkeypatch.delenv(k, raising=False)

    cfg = SupervisorConfig.from_env()
    assert cfg.control_plane_url == ""
    assert cfg.state_dir == Path("/var/lib/spatium-supervisor")
    assert cfg.bootstrap_pairing_code == ""
    # 30s default cadence — operator feedback that 60s felt sluggish on
    # role-swap (reconcile_node_labels only fires per heartbeat). See the
    # comment on SupervisorConfig.from_env.
    assert cfg.heartbeat_interval_seconds == 30
    assert cfg.hostname  # gethostname() always returns something


def test_config_reads_env(monkeypatch) -> None:
    monkeypatch.setenv("CONTROL_PLANE_URL", "https://ddi.example.com/")
    monkeypatch.setenv("APPLIANCE_HOSTNAME", "dns-east-1")
    monkeypatch.setenv("BOOTSTRAP_PAIRING_CODE", "12345678")
    monkeypatch.setenv("HEARTBEAT_INTERVAL_SECONDS", "30")
    monkeypatch.setenv("STATE_DIR", "/tmp/spatium-supervisor-test")

    cfg = SupervisorConfig.from_env()
    assert cfg.control_plane_url == "https://ddi.example.com"  # trailing slash stripped
    assert cfg.hostname == "dns-east-1"
    assert cfg.bootstrap_pairing_code == "12345678"
    assert cfg.heartbeat_interval_seconds == 30
    assert cfg.state_dir == Path("/tmp/spatium-supervisor-test")


def test_ensure_layout_creates_dirs(tmp_path: Path) -> None:
    target = tmp_path / "state"
    ensure_layout(target)
    assert target.is_dir()
    assert (target / "identity").is_dir()
    assert (target / "tls").is_dir()


def test_ensure_layout_is_idempotent(tmp_path: Path) -> None:
    target = tmp_path / "state"
    ensure_layout(target)
    ensure_layout(target)  # second call must not raise
    assert (target / "identity").is_dir()


def test_main_module_importable() -> None:
    # Just import — verifies the module is reachable + has no top-level
    # side effects beyond function definitions.
    import spatium_supervisor.__main__ as m

    assert callable(m.main)


def test_dockerfile_is_multi_arch_capable() -> None:
    df = Path(__file__).resolve().parents[1] / "images" / "supervisor" / "Dockerfile"
    text = df.read_text()
    # Non-negotiable #11 — multi-arch builds. The release workflow
    # passes ``--platform linux/amd64,linux/arm64``; the Dockerfile
    # must not hard-bind an arch.
    assert "FROM --platform" not in text, "Dockerfile should not pin --platform"
    assert "alpine:" in text


def test_entrypoint_drops_to_unprivileged_user() -> None:
    ep = Path(__file__).resolve().parents[1] / "images" / "supervisor" / "entrypoint.sh"
    text = ep.read_text()
    # The supervisor must not run as root in the container — only the
    # bind-mounted sockets/dirs we mount in get root-capable access,
    # not the Python entrypoint.
    assert "su-exec spatium /usr/local/bin/spatium-supervisor" in text
    # Must NOT pin an explicit ``:group``. ``su-exec spatium:spatium``
    # clears supplementary groups, which locks the unprivileged user out
    # of the host docker.sock (owned root:<docker-gid>); the entrypoint
    # instead adds spatium to a matching docker group and drops the
    # ``:group`` so initgroups() keeps it. Regressing this silently
    # re-breaks docker access — hence the negative assertion.
    assert "su-exec spatium:spatium" not in text
