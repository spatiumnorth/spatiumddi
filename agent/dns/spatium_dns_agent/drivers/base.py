"""Agent-side driver base class.

Mirrors the control-plane DNSDriverBase but on the container side — the agent
asks its driver to render configs, reload the daemon, and apply RFC 2136 /
RFC 2136 record ops over loopback.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, NamedTuple

from ..config_apply import (
    PHASE_RELOAD,
    PHASE_RENDER,
    PHASE_VALIDATE,
    ConfigApplyError,
)

# Record-op kinds that describe an RRset, and so can carry the complete
# desired ``record["rrset"]`` the control plane stamps on them (#773).
# Everything else on the queue is zone-level (the ``dnssec_*`` ops) and
# branches off before any of the record machinery runs.
RRSET_OP_KINDS = frozenset({"create", "update", "delete"})


class HeldZone(NamedTuple):
    """A zone the last apply left off the new config, and why (#1403)."""

    #: The zone's name as rendered, without the trailing dot.
    zone: str
    #: The view it was rendered into; ``None`` on a group without views.
    view: str | None
    #: The checker's own diagnostic, first line.
    reason: str
    #: True: the daemon keeps serving the zone's last good copy. False: the
    #: zone never loaded, so it is not served at all.
    served: bool


class DriverBase(ABC):
    #: PID of the daemon this driver spawned or adopted; ``None`` until then.
    #: Every driver sets it at its spawn / adopt points (``start_daemon`` and
    #: the system-wide look-up in ``daemon_running``) and never clears it, so
    #: it is also the "has the daemon been launched at all" fact that
    #: :meth:`daemon_launched` reports.
    daemon_pid: int | None = None

    #: Zones the last successful :meth:`apply_config` held back rather than
    #: failing the whole apply for them (#1403): the rest of the bundle is
    #: live, these are not. Set by every apply of a driver that holds zones
    #: back (the BIND9 driver's zone check); always empty for the others. The
    #: sync loop reports them and re-renders the next bundle while any remain.
    held_back: tuple[HeldZone, ...] = ()

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir

    @abstractmethod
    def render(self, bundle: dict[str, Any]) -> None:
        """Render config files (atomic to ``rendered.new``)."""

    @abstractmethod
    def validate(self) -> None:
        """Validate the rendered config. Raise on failure."""

    @abstractmethod
    def swap_and_reload(self) -> None:
        """Rename rendered.new → rendered, signal the daemon to reload."""

    @abstractmethod
    def apply_record_op(self, op: dict[str, Any]) -> dict[str, Any] | None:
        """Apply a RecordOp via loopback nsupdate via RFC 2136.

        Returns an optional dict carrying driver-specific result
        details — e.g. the PowerDNS driver returns DNSSEC state
        flags that ``sync.py`` propagates back to the control plane
        in the pending-op ACK. BIND9's driver returns ``None``
        (no extra signal to surface). Issue #251 — pre-fix the ABC
        declared ``-> None`` while powerdns.py already returned a
        dict; sync.py relied on the dict shape so the contract was
        already widened in practice.
        """

    @abstractmethod
    def start_daemon(self) -> None:
        """Spawn the DNS daemon. Called once at startup."""

    @abstractmethod
    def daemon_running(self) -> bool:
        ...

    def daemon_launched(self) -> bool:
        """True once this driver has spawned or adopted its daemon.

        ``start_daemon`` does not always start one: the BIND9 and PowerDNS
        drivers return WITHOUT a daemon when no config has been rendered yet
        (``named_conf_missing_startup_deferred`` /
        ``pdns_conf_missing_startup_deferred``) and leave the launch to
        ``swap_and_reload``, which the sync loop reaches once the control
        plane hands over the first bundle. A daemon that was never launched
        cannot have died, so the supervisor consults this before it reads
        ``daemon_running() == False`` as "exit and let the orchestrator
        restart us" (#1056).
        """
        return self.daemon_pid is not None

    def daemon_restarting(self) -> bool:
        """True while the driver is deliberately restarting its own daemon.

        An in-place restart (PowerDNS re-reading a changed ``pdns.conf``,
        #1353) runs on the sync thread and passes through moments the
        supervisor's 1 s liveness check would misread: the old daemon is
        stopping while ``daemon_pid`` still names it (read as a death, exit
        2), and ``daemon_pid`` is cleared before the new one is spawned (read
        as a deferred start). The supervisor gives no verdict while this is
        True. Drivers that never restart in place keep the default.
        """
        return False

    def daemon_version(self) -> str | None:
        """Version of the DNS daemon binary, e.g. ``"5.0.5"`` / ``"9.20.26"``.

        Reported on each heartbeat and persisted to ``dns_server.daemon_version``
        so the control plane can reason about what the fleet is actually
        running — the rolling-upgrade preflight needs it to tell an operator
        that crossing PowerDNS 4.x → 5.x performs a one-way LMDB schema
        migration (#638).

        ``None`` means "could not determine", which the control plane must
        treat as UNKNOWN — never as a specific version. Not abstract: a driver
        that has no cheap version probe simply doesn't report one.
        """
        return None

    def apply_config(self, bundle: dict[str, Any]) -> None:
        """Default orchestration: render → validate → swap+reload.

        Every failure is re-raised as :class:`ConfigApplyError` carrying the
        phase it happened in. The caller needs that to choose a recovery: a
        render or validate failure never reached the daemon, so nothing has
        to be undone beyond the staging tree, whereas a swap/reload failure
        means the live config directory has already been replaced and the
        previous bundle has to be re-rendered to get back to a known state
        (#882).
        """
        for phase, step in (
            (PHASE_RENDER, lambda: self.render(bundle)),
            (PHASE_VALIDATE, self.validate),
            (PHASE_RELOAD, self.swap_and_reload),
        ):
            try:
                step()
            except Exception as e:
                raise ConfigApplyError(phase, e) from e
