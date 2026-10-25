"""A running control-plane supervisor re-registers when its Fleet row goes away (#2696).

The revoke recovery is ``_maybe_register``'s ``revoked_reregister`` branch: on a
control-plane node in ``approval-state=revoked`` it clears the stale identity and
registers again through the self-bootstrap. It ran at start-up and, in the main
loop, only while no appliance id was cached. A row that went away left the cached
id in place, so the running supervisor stayed revoked (its role services torn
down) until its pod restarted.

Each test drives the real ``main()`` loop in-process against a stub control plane
that answers as the api does: the heartbeat accepts an approved row and refuses
anything else (recording the strike exactly as ``heartbeat_once`` does), the
self-bootstrap mints a code only while no live appliance row exists (otherwise
409), and a pairing code registers once. The loop ends after a fixed number of
ticks.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable, Iterator, MutableMapping
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from structlog.testing import capture_logs

from spatium_supervisor import __main__ as main_mod
from spatium_supervisor import (
    appliance_state,
    approval_state,
    cp_tls,
    kmsg_reader,
    pcap_proxy,
    storage_proxy,
)
from spatium_supervisor.cert_auth import load_cert, save_cert
from spatium_supervisor.config import SupervisorConfig
from spatium_supervisor.identity import (
    load_appliance_id,
    load_session_token,
    save_appliance_id,
    save_session_token,
)
from spatium_supervisor.register import RegisterCodeRejected, RegisterResult
from spatium_supervisor.state import ensure_layout

STALE = uuid.UUID("777ca6ae-e1d1-48d6-a030-487878359796")
FRESH = uuid.UUID("e8bbe99a-3c3f-4d5e-9a41-2b7d0c6f1a20")
_API = "http://spatium-control-spatiumddi-api.spatium.svc.cluster.local:8000"


class _LoopDone(BaseException):
    """Ends ``main()``'s forever-loop. A ``BaseException`` so the loop's
    ``except Exception`` guards cannot swallow it and hang the test."""


class _ControlPlane:
    """The api as the supervisor sees it. One heartbeat per loop tick."""

    def __init__(self, new_ids: list[uuid.UUID]) -> None:
        self.rows: dict[uuid.UUID, str] = {}  # id -> "approved" | "revoked"
        self.registration_on = True
        self.heartbeats: list[tuple[uuid.UUID, str | None]] = []
        self.statuses: list[int] = []
        self.bootstrap_calls = 0
        # How many heartbeats had been sent when each self-bootstrap was asked.
        self.bootstrap_at: list[int] = []
        self.minted: list[str] = []
        self.presented: list[str] = []
        self._new_ids = iter(new_ids)
        self._spent: set[str] = set()

    # ``_self_bootstrap_or_skip``: 409 (cfg unchanged) while any live row exists.
    def self_bootstrap(self, cfg: SupervisorConfig, variant: str, log: Any) -> SupervisorConfig:
        self.bootstrap_calls += 1
        self.bootstrap_at.append(len(self.heartbeats))
        if self.rows:
            return cfg
        code = f"{len(self.minted) + 1:08d}"
        self.minted.append(code)
        return dataclasses.replace(cfg, bootstrap_pairing_code=code, control_plane_url=_API)

    # ``register``: a minted code registers once; anything else is a 403.
    def register(self, **kwargs: Any) -> RegisterResult:
        code = kwargs["pairing_code"]
        self.presented.append(code)
        if code not in self.minted or code in self._spent:
            raise RegisterCodeRejected("invalid / expired / already used")
        self._spent.add(code)
        new_id = next(self._new_ids)
        self.rows[new_id] = "approved"
        return RegisterResult(
            appliance_id=str(new_id),
            state="approved",
            public_key_fingerprint="fp",
            session_token=f"token-{new_id.hex[:8]}",
        )

    # ``heartbeat_once``: the api's answer, and the strike it records.
    def heartbeat(
        self,
        *,
        cfg: SupervisorConfig,
        appliance_id: uuid.UUID,
        session_token: str | None,
        **_kwargs: Any,
    ) -> bool:
        self.heartbeats.append((appliance_id, session_token))
        if not self.registration_on:
            status = 404
        elif self.rows.get(appliance_id) != "approved":
            status = 403
        else:
            status = 200
        self.statuses.append(status)
        if status == 200:
            approval_state.record_success(cfg.state_dir)
        else:
            approval_state.record_revocation_signal(cfg.state_dir)
        return False


@contextmanager
def _no_client(*_args: Any, **_kwargs: Any) -> Iterator[None]:
    yield None


def _run_main(
    monkeypatch: pytest.MonkeyPatch,
    state_dir: Path,
    cp: _ControlPlane,
    *,
    variant: str,
    ticks: int,
    events: dict[int, Callable[[_ControlPlane], None]],
    env: dict[str, str] | None = None,
) -> list[MutableMapping[str, Any]]:
    """Run ``main()`` for ``ticks`` loop iterations; ``events[n]`` runs on the
    control plane after tick ``n``. Returns the captured log events."""
    monkeypatch.setenv("STATE_DIR", str(state_dir))
    monkeypatch.setenv("HEARTBEAT_INTERVAL_SECONDS", "30")
    for name in ("CONTROL_PLANE_URL", "BOOTSTRAP_PAIRING_CODE", "K8S_PROXY_ENABLED"):
        monkeypatch.delenv(name, raising=False)
    for name, value in (env or {}).items():
        monkeypatch.setenv(name, value)

    monkeypatch.setattr(appliance_state, "detect_appliance_variant", lambda: variant)
    monkeypatch.setattr(
        appliance_state, "is_control_plane_member", lambda: variant == "control-plane"
    )
    monkeypatch.setattr(main_mod, "_self_bootstrap_or_skip", cp.self_bootstrap)
    monkeypatch.setattr(main_mod, "register", cp.register)
    monkeypatch.setattr(main_mod, "heartbeat_once", cp.heartbeat)
    monkeypatch.setattr(cp_tls, "client", _no_client)
    monkeypatch.setattr(cp_tls, "check_pin_vouched_once", lambda *_a, **_k: None)

    # Nothing but the loop: no logging setup, threads or signal handlers.
    monkeypatch.setattr(main_mod, "configure_logging", lambda **_k: None)
    monkeypatch.setattr(main_mod, "start_proxy_thread", lambda *_a, **_k: None)
    monkeypatch.setattr(main_mod, "start_nettool_thread", lambda *_a, **_k: None)
    monkeypatch.setattr(storage_proxy, "start_storage_thread", lambda *_a, **_k: None)
    monkeypatch.setattr(pcap_proxy, "start_pcap_thread", lambda *_a, **_k: None)
    monkeypatch.setattr(kmsg_reader, "start", lambda *_a, **_k: None)
    monkeypatch.setattr(main_mod.signal, "signal", lambda *_a, **_k: None)

    # One ``time.sleep`` per tick: a one-second budget, then the next tick.
    tick = 0

    def sleep(_seconds: float) -> None:
        nonlocal tick
        tick += 1
        if tick in events:
            events[tick](cp)
        if tick >= ticks:
            raise _LoopDone

    monkeypatch.setattr(main_mod, "next_heartbeat_delay", lambda *_a, **_k: 1.0)
    monkeypatch.setattr(main_mod, "time", SimpleNamespace(sleep=sleep))

    with capture_logs() as logs, pytest.raises(_LoopDone):
        main_mod.main()
    return logs


def _registered_before(state_dir: Path, cp: _ControlPlane) -> None:
    """A node that registered earlier and restarted since: cached id, session
    token and certificate, approved, and its row live on the control plane."""
    ensure_layout(state_dir)
    save_appliance_id(state_dir, STALE)
    save_session_token(state_dir, "token-stale")
    save_cert(state_dir, "STALE CERT", "CA")
    approval_state.record_success(state_dir)
    cp.rows[STALE] = "approved"


def _events(logs: list[MutableMapping[str, Any]], name: str) -> list[MutableMapping[str, Any]]:
    return [e for e in logs if e.get("event") == name]


def _row_goes_away(cp: _ControlPlane) -> None:
    del cp.rows[STALE]


@pytest.mark.parametrize("started", ["restarted", "first-boot"])
def test_running_supervisor_reregisters_when_its_row_goes_away(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, started: str
) -> None:
    state_dir = tmp_path / "state"
    if started == "restarted":
        cp = _ControlPlane(new_ids=[FRESH])
        _registered_before(state_dir, cp)
    else:
        # This process self-bootstrapped and registered at start-up, so the
        # loop's config still carries that (now spent) code.
        cp = _ControlPlane(new_ids=[STALE, FRESH])

    logs = _run_main(
        monkeypatch,
        state_dir,
        cp,
        variant="control-plane",
        ticks=8,
        events={1: _row_goes_away},
    )

    sent = [str(appliance_id) for appliance_id, _ in cp.heartbeats]
    assert load_appliance_id(state_dir) == FRESH, (
        "the running supervisor never re-registered after its Fleet row went away: "
        f"heartbeat answers {cp.statuses}, ids sent {sorted(set(sent))}, "
        f"approval-state {approval_state.read_state(state_dir)!r}, "
        f"revoked_reregister logged {len(_events(logs, 'supervisor.register.revoked_reregister'))} times"
    )
    reregister = _events(logs, "supervisor.register.revoked_reregister")
    assert len(reregister) == 1
    assert reregister[0]["stale_appliance_id"] == str(STALE)
    assert reregister[0]["via_self_bootstrap"] is True
    # A fresh code, never the spent one from the first registration.
    assert cp.presented == cp.minted
    assert len(set(cp.presented)) == len(cp.presented)
    # The new identity heartbeats, with its own session token, and is approved.
    assert cp.heartbeats[-1] == (FRESH, f"token-{FRESH.hex[:8]}")
    assert load_session_token(state_dir) == f"token-{FRESH.hex[:8]}"
    assert approval_state.read_state(state_dir) == "approved"
    if started == "restarted":
        assert load_cert(state_dir) is None  # the stale certificate went with it


def test_identity_kept_while_the_control_plane_still_holds_a_live_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Registration switched off makes every heartbeat 404, which revokes the
    node, but its row is still there and the self-bootstrap refuses (409). The
    node must keep its identity so it is approved again, on the same row, as
    soon as its heartbeats are accepted; discarding it first would leave it with
    no identity and no code."""
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)

    def switch_off(c: _ControlPlane) -> None:
        c.registration_on = False

    def switch_on(c: _ControlPlane) -> None:
        c.registration_on = True

    logs = _run_main(
        monkeypatch,
        state_dir,
        cp,
        variant="control-plane",
        ticks=9,
        events={1: switch_off, 6: switch_on},
    )

    assert cp.statuses[:3] == [200, 404, 404]
    # The recovery ran while revoked and was refused.
    assert cp.bootstrap_calls >= 1
    assert _events(logs, "supervisor.register.revoked_reregister_deferred")
    assert not _events(logs, "supervisor.register.revoked_reregister")
    assert cp.presented == []
    # Nothing was cleared, and the same row is approved again.
    assert load_appliance_id(state_dir) == STALE
    assert load_session_token(state_dir) == "token-stale"
    assert load_cert(state_dir) == "STALE CERT"
    assert approval_state.read_state(state_dir) == "approved"
    # Accepted again from the first heartbeat after the switch, and the
    # recovery stops asking from then on.
    accepted = cp.statuses.index(200, 1)
    assert all(s == 200 for s in cp.statuses[accepted:])
    assert max(cp.bootstrap_at) <= accepted


def test_restart_while_revoked_keeps_the_identity_when_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same recovery at start-up: a node that restarts while revoked, its
    row still live, keeps its identity rather than clearing it before the
    self-bootstrap refuses."""
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)
    cp.rows[STALE] = "revoked"
    approval_state.record_revocation_signal(state_dir)
    approval_state.record_revocation_signal(state_dir)
    assert approval_state.read_state(state_dir) == "revoked"

    def reauthorize(c: _ControlPlane) -> None:
        c.rows[STALE] = "approved"

    _run_main(
        monkeypatch,
        state_dir,
        cp,
        variant="control-plane",
        ticks=5,
        events={2: reauthorize},
    )

    assert cp.bootstrap_calls >= 1
    assert cp.presented == []
    assert load_appliance_id(state_dir) == STALE
    assert load_session_token(state_dir) == "token-stale"
    assert cp.statuses[-1] == 200
    assert approval_state.read_state(state_dir) == "approved"


def test_remote_appliance_keeps_its_identity_for_reauthorize(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A data-plane appliance revoked from the Fleet page is restored by
    Re-authorize on the same row, so the running loop leaves its identity
    alone even though its install-time pairing code is still in its config."""
    state_dir = tmp_path / "state"
    cp = _ControlPlane(new_ids=[FRESH])
    _registered_before(state_dir, cp)

    def revoke(c: _ControlPlane) -> None:
        c.rows[STALE] = "revoked"

    def reauthorize(c: _ControlPlane) -> None:
        c.rows[STALE] = "approved"

    _run_main(
        monkeypatch,
        state_dir,
        cp,
        variant="appliance",
        ticks=8,
        events={1: revoke, 6: reauthorize},
        env={"CONTROL_PLANE_URL": "https://cp.example", "BOOTSTRAP_PAIRING_CODE": "12345678"},
    )

    assert cp.statuses[:4] == [200, 403, 403, 403]
    assert cp.bootstrap_calls == 0
    assert cp.presented == []
    assert load_appliance_id(state_dir) == STALE
    assert cp.statuses[-1] == 200
    assert approval_state.read_state(state_dir) == "approved"
