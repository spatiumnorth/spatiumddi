"""Background watcher that keeps Kea HA peer URLs in sync with DNS.

Kea's HA hook parses peer URLs via Boost asio, which only accepts IP
literals — hostnames aren't resolved by Kea itself. The agent does
one-time resolution inside ``render_kea._resolve_peer_url`` at render
time, which is fine until a peer container/pod gets a new IP
(``docker compose --force-recreate``, any k8s restart, bridge-IP
churn). After that, Kea's config points at a stale IP and the HA hook
silently drifts to ``communications-interrupted`` → ``partner-down``.

This watcher closes the loop: every ``CHECK_INTERVAL`` seconds it
re-resolves the hostnames from the last-seen bundle's failover block
and, if any peer's IP has changed, fires ``apply_bundle`` to re-render
and reload Kea with fresh URLs.

Resolution failures are treated as transient — we keep the cached IP
and try again next tick. That avoids thrashing during a brief DNS
outage.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
from collections.abc import Callable
from typing import Any
from urllib.parse import urlparse

import structlog

log = structlog.get_logger(__name__)

# 30s balances responsiveness vs noise. Peer restarts typically settle
# in <5s on compose and <10s on k8s, so we'll pick up new IPs within
# the first half-minute.
CHECK_INTERVAL = 30.0


class PeerResolveWatcher:
    """Re-resolves HA peer hostnames and triggers reload on IP change.

    ``apply_fn`` is called as ``apply_fn(bundle, reload_kea=True)``. The
    supervisor wires it to ``SyncLoop.reapply_current_bundle`` (#1247),
    which re-renders the bundle the sync loop has LIVE — the ``bundle``
    argument only says which one this watcher saw — under the sync loop's
    apply lock and through its revert path. It used to be
    ``SyncLoop._apply_bundle`` itself, so a render Kea refused was only
    logged here and left on disk for the next container start to boot
    into, and this thread could race the sync loop's own apply.
    """

    def __init__(
        self,
        apply_fn: Callable[..., None] | None = None,
        *,
        check_interval: float = CHECK_INTERVAL,
    ):
        # ``apply_fn`` may be deferred so the supervisor can construct
        # the watcher before the SyncLoop (which the apply_fn closes
        # over) exists — see ``set_apply_fn`` (issue #265).
        self._apply_fn = apply_fn
        self._check_interval = check_interval
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._bundle: dict[str, Any] | None = None
        # Maps hostname → last resolved IP. We only reload when the resolution
        # changes, not on every tick.
        #
        # This MUST be initialised in __init__, not in set_apply_fn: the #265
        # refactor made apply_fn deferrable, so set_apply_fn is called LATE (once
        # the SyncLoop exists) — but set_bundle() and _tick_once() both run before
        # that on the bootstrap-from-cache path and both touch _resolved. Leaving
        # it in set_apply_fn raised AttributeError on every set_bundle, which
        # sync.py swallowed as ``peer_watcher_set_bundle_failed`` — so the HA
        # peer-IP-drift self-healing this class exists to provide never ran.
        self._resolved: dict[str, str] = {}

    def set_apply_fn(self, apply_fn: Callable[..., None]) -> None:
        """Arm the watcher with the SyncLoop's bundle-apply callback.

        Called by the supervisor after the SyncLoop is constructed so
        the watcher's apply path can never fire against a partially-
        wired chain (issue #265).
        """
        self._apply_fn = apply_fn

    def set_bundle(self, bundle: dict[str, Any]) -> None:
        """Called by the sync loop after each successful bundle apply.

        Seeds the initial hostname→IP map so the first watcher tick
        doesn't spuriously fire "IP changed" on startup.
        """
        with self._lock:
            self._bundle = bundle
            hosts = self._peer_hosts(bundle)
            for host in hosts:
                try:
                    ipaddress.ip_address(host)
                    continue  # already an IP literal — nothing to watch
                except ValueError:
                    pass
                try:
                    self._resolved[host] = socket.gethostbyname(host)
                except OSError:
                    # Transient — next tick will try again
                    continue
            # Purge stale hostnames (e.g. a peer was removed from the
            # group) so we don't reload on a phantom DNS change.
            self._resolved = {h: ip for h, ip in self._resolved.items() if h in hosts}

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.wait(self._check_interval):
            self._tick_once()

    def _tick_once(self) -> None:
        with self._lock:
            bundle = self._bundle
        if bundle is None:
            return
        hosts = self._peer_hosts(bundle)
        if not hosts:
            return
        changed: list[tuple[str, str, str]] = []
        for host in hosts:
            try:
                ipaddress.ip_address(host)
                continue  # hostname is already a literal
            except ValueError:
                pass
            try:
                new_ip = socket.gethostbyname(host)
            except OSError as e:
                log.debug("ha_peer_resolve_transient_fail", host=host, error=str(e))
                continue
            old_ip = self._resolved.get(host)
            if old_ip is None:
                self._resolved[host] = new_ip
                continue
            if new_ip != old_ip:
                changed.append((host, old_ip, new_ip))
                self._resolved[host] = new_ip
        if not changed:
            return
        for host, old_ip, new_ip in changed:
            log.info("ha_peer_ip_changed", host=host, old=old_ip, new=new_ip)
        if self._apply_fn is None:
            # Supervisor hasn't armed the watcher yet — log and bail.
            # Caller will pick the change up on the next tick once the
            # SyncLoop wires in via ``set_apply_fn``.
            log.warning("ha_peer_reresolve_no_apply_fn", changes=len(changed))
            return
        try:
            result = self._apply_fn(bundle, reload_kea=True)
        except Exception:
            # Never let one failed reload kill the watcher thread.
            log.exception("ha_peer_reresolve_reload_failed")
            return
        # ``reapply_current_bundle`` answers False when Kea refused the
        # re-render (it has reverted and reported it) and None when there was
        # nothing to re-apply; a legacy apply_fn returns None on success.
        if result is False:
            log.warning("ha_peer_reresolve_rejected_reverted", changes=len(changed))
        else:
            log.info("ha_peer_reresolve_reloaded", changes=len(changed), applied=result)

    @staticmethod
    def _peer_hosts(bundle: dict[str, Any]) -> list[str]:
        """Extract peer hostnames from the bundle's failover block."""
        # Issue #260 — explicit narrowing matches sync._apply_bundle.
        # The inline-ternary form crashed on ``inner.get(...)`` when
        # ``bundle["bundle"]`` was a non-dict and the fallback was a
        # non-dict outer. New shape: only proceed if we land on a
        # dict; bail with an empty peer list otherwise.
        inner_candidate = bundle.get("bundle")
        if isinstance(inner_candidate, dict):
            inner = inner_candidate
        elif isinstance(bundle, dict):
            inner = bundle
        else:
            return []
        failover = inner.get("failover") or {}
        peers = failover.get("peers") or []
        hosts: list[str] = []
        for p in peers:
            try:
                host = urlparse(p.get("url", "")).hostname
            except Exception:  # noqa: BLE001 — malformed URL, skip quietly
                host = None
            if host:
                hosts.append(host)
        return hosts


__all__ = ["PeerResolveWatcher", "CHECK_INTERVAL"]
