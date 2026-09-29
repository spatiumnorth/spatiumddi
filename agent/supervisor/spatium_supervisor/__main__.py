"""CLI entrypoint — ``spatium-supervisor``.

Wave A2 supervisor loop:

1. Configure logging + state-dir layout.
2. Load (or first-boot generate) the Ed25519 identity.
3. If we already have a cached ``appliance_id``, skip register and
   idle (Wave A3+ will replace idle with a real /poll loop).
4. Otherwise: if a pairing code is present in env, call
   /supervisor/register. On success persist the appliance_id + idle.
   On disabled (404) idle + retry next boot. On fatal idle forever.
5. Idle = log heartbeat every ``heartbeat_interval_seconds`` until
   SIGTERM / SIGINT.

Wave A2 still doesn't drive any service containers, render any
firewall rules, or poll the control plane for instructions — those
are Waves C / D. This is the identity + registration foundation.
"""

from __future__ import annotations

import os
import signal
import ssl
import sys
import time

import httpx
import structlog

import dataclasses

from . import appliance_state, approval_state, cp_tls
from .cert_auth import clear_cert
from .config import SupervisorConfig
from .heartbeat import _effective_control_plane_url, heartbeat_once
from .k8s_proxy import start_proxy_thread
from .identity import (
    clear_appliance_id,
    clear_session_token,
    load_appliance_id,
    load_or_generate,
    load_session_token,
    save_appliance_id,
    save_session_token,
)
from .log import configure_logging
from .nettools_proxy import start_nettool_thread
from .register import RegisterDisabled, RegisterFatal, register
from .state import ensure_layout


def _self_bootstrap_or_skip(
    cfg: SupervisorConfig,
    variant: str,
    log: structlog.stdlib.BoundLogger,
) -> SupervisorConfig:
    """Mint a local pairing code via the in-cluster api Service and
    return a config carrying it.

    Only fires on the control-plane appliance where the
    installer wizard didn't capture a pairing code (the control plane
    IS local). The api gates the endpoint on (1) the host bind-mounted
    ``role-config:ROLE`` matching this claim and (2) no existing
    Appliance rows, so calling it from anywhere other than the local
    supervisor on a fresh install fails 403/409.

    On success we return a frozen copy of ``cfg`` with the new code +
    control-plane URL stamped in. On any failure (api not reachable,
    403, 409 because we're already registered, ...) we log + return
    the original cfg so the caller's normal "skipped" log paths fire.
    Idempotent — a transient 409 just means the existing register
    flow will kick in once the supervisor's cached_appliance_id is
    populated on the next loop iteration.
    """
    # In-cluster Service URL. The api Service is named
    # ``<release>-spatiumddi-api`` in the spatium namespace; the
    # appliance helm-chart release is ``spatium-control``.
    # Hardcoded here so the supervisor doesn't need an extra env var
    # for the discovery URL — multi-node HA (#272 later phases) can
    # generalise this when we add real promotion-flow plumbing.
    # Trailing dot is load-bearing (#777). Without it the name has 4 dots, which
    # is under the pod's ``ndots:5``, so the resolver walks its search list first —
    # and kubelet appends the NODE's own DHCP search domain to every pod's list. If
    # that domain's zone answers NOERROR/NODATA (rather than NXDOMAIN) for a
    # nonexistent name — Cloudflare-hosted zones do, among others — musl stops the
    # walk there and returns EAI_NODATA without ever trying the bare name. The
    # supervisor then never registers, on a network it has no control over. The dot
    # makes the name absolute and skips the search list entirely.
    api_url = "http://spatium-control-spatiumddi-api.spatium.svc.cluster.local.:8000"
    log.info("supervisor.self_bootstrap.attempting", variant=variant, api_url=api_url)
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(
                f"{api_url}/api/v1/appliance/self-register-bootstrap",
                json={"appliance_variant": variant},
            )
    except httpx.HTTPError as exc:
        log.warning(
            "supervisor.self_bootstrap.transport_failed",
            error=str(exc),
            hint="will retry on next register-loop tick",
        )
        return cfg
    if resp.status_code == 409:
        log.info("supervisor.self_bootstrap.already_registered")
        return cfg
    if resp.status_code != 200:
        log.warning(
            "supervisor.self_bootstrap.refused",
            status=resp.status_code,
            body=resp.text[:200],
        )
        return cfg
    try:
        payload = resp.json()
        code = payload["code"]
        control_plane_url = payload["control_plane_url"]
    except (ValueError, KeyError) as exc:
        log.warning("supervisor.self_bootstrap.malformed_response", error=str(exc))
        return cfg
    log.info(
        "supervisor.self_bootstrap.minted",
        variant=variant,
        code_last_two=code[-2:],
        control_plane_url=control_plane_url,
    )
    return dataclasses.replace(
        cfg,
        bootstrap_pairing_code=code,
        control_plane_url=control_plane_url,
    )


def _maybe_register(
    cfg: SupervisorConfig, log: structlog.stdlib.BoundLogger
) -> SupervisorConfig:
    """Run identity generation + register-if-needed in one shot. Logs
    its own status; never raises into the caller (the main loop
    falls back to idle on any failure).

    Returns the (possibly mutated) ``cfg`` — when the
    self-bootstrap path fires on the control-plane node,
    ``control_plane_url`` and ``bootstrap_pairing_code`` are
    refreshed in the returned config so the caller's heartbeat
    loop can use the new control-plane URL going forward.
    Otherwise returns the input verbatim.
    """
    identity, generated = load_or_generate(cfg.state_dir)
    if generated:
        log.info(
            "supervisor.identity.generated",
            fingerprint=identity.fingerprint,
        )
    else:
        log.info(
            "supervisor.identity.loaded",
            fingerprint=identity.fingerprint,
        )

    cached_appliance_id = load_appliance_id(cfg.state_dir)
    if cached_appliance_id is not None:
        # Issue #170 Wave E follow-up + #272 Phase 1 audit — revoke
        # recovery. If the supervisor flipped to
        # ``approval-state=revoked`` (control plane returning 403/404
        # for our cached identity) we need to clear the stale soft
        # state (appliance_id / session_token / cert.pem / approval-
        # state / strikes) so the register call below mints a fresh
        # identity. The Ed25519 keypair stays — it's stable across
        # re-pairs and the control plane creates a new appliance row
        # + cert against it on the next approve.
        #
        # Re-pair sources, in order of precedence:
        #   1. ``cfg.bootstrap_pairing_code`` — operator handed us a
        #      fresh code via spatium-pair (#170 Wave E flow).
        #   2. Self-bootstrap variant (control-plane) —
        #      #272 Phase 1; the supervisor mints its own pairing
        #      code against the in-cluster api on the recovery path.
        #
        # Without case 2 the supervisor would stay locked in revoked
        # after the operator deleted its row from the Fleet UI on a
        # control-plane appliance (no pairing code env present, no
        # human-mediated recovery path) — verified live on .199.
        variant = appliance_state.detect_appliance_variant()
        can_self_bootstrap = variant == "control-plane"
        if approval_state.read_state(cfg.state_dir) == "revoked" and (
            cfg.bootstrap_pairing_code or can_self_bootstrap
        ):
            log.info(
                "supervisor.register.revoked_reregister",
                stale_appliance_id=str(cached_appliance_id),
                via_self_bootstrap=can_self_bootstrap
                and not cfg.bootstrap_pairing_code,
            )
            clear_appliance_id(cfg.state_dir)
            clear_session_token(cfg.state_dir)
            clear_cert(cfg.state_dir)
            approval_state.clear(cfg.state_dir)
            # Fall through to the register call below.
        else:
            log.info(
                "supervisor.register.cached",
                appliance_id=str(cached_appliance_id),
            )
            return cfg

    # #272 — self-bootstrap on the control-plane node.
    # The installer wizard doesn't capture a pairing code for these
    # variants (the control plane is local), so on first boot both
    # control_plane_url and bootstrap_pairing_code are empty. Try
    # the in-cluster api's self-register-bootstrap endpoint first;
    # on success the resulting code is reused as a normal pairing
    # code through the standard register flow below.
    if not cfg.control_plane_url and not cfg.bootstrap_pairing_code:
        variant = appliance_state.detect_appliance_variant()
        if variant == "control-plane":
            cfg = _self_bootstrap_or_skip(cfg, variant, log)

    if not cfg.control_plane_url:
        log.warning("supervisor.register.skipped", reason="no control_plane_url")
        return cfg
    if not cfg.bootstrap_pairing_code:
        log.warning("supervisor.register.skipped", reason="no bootstrap_pairing_code")
        return cfg

    try:
        # #1219 — verified against the control plane's pinned certificate;
        # on first contact this is where the pin is taken.
        with cp_tls.client(cfg.state_dir, cfg.control_plane_url) as client:
            result = register(
                control_plane_url=cfg.control_plane_url,
                pairing_code=cfg.bootstrap_pairing_code,
                identity=identity,
                hostname=cfg.hostname,
                supervisor_version=_supervisor_version(),
                client=client,
                # #272 Phase 1 — let the control plane stamp the variant
                # + auto-assign fixed roles at register time instead of
                # waiting for the first heartbeat. None on docker / k8s
                # supervisors (no role-config bind mount).
                appliance_variant=appliance_state.detect_appliance_variant(),
            )
    except RegisterDisabled as exc:
        log.warning("supervisor.register.disabled", reason=str(exc))
        return cfg
    except RegisterFatal as exc:
        log.error("supervisor.register.fatal", reason=str(exc))
        # A certificate that changed before approval is re-pinned here, or
        # registration would retry against the old pin forever.
        if cp_tls.is_verification_failure(exc):
            cp_tls.try_repin(cfg.state_dir, cfg.control_plane_url)
        return cfg
    except (OSError, ssl.SSLError) as exc:
        # First contact could not reach the control plane to take a pin.
        log.warning("supervisor.register.unreachable", error=str(exc))
        return cfg

    import uuid

    save_appliance_id(cfg.state_dir, uuid.UUID(result.appliance_id))
    # Stash the cleartext session token alongside the appliance_id
    # so the heartbeat loop can authenticate without a fresh register
    # call across supervisor restarts. Cleared when mTLS lands.
    save_session_token(cfg.state_dir, result.session_token)
    log.info(
        "supervisor.register.persisted",
        appliance_id=result.appliance_id,
        state=result.state,
    )
    return cfg


def _supervisor_version() -> str:
    from . import __version__

    return __version__


def main() -> int:
    configure_logging(level=os.environ.get("LOG_LEVEL", "INFO"))
    log = structlog.get_logger()

    cfg = SupervisorConfig.from_env()
    ensure_layout(cfg.state_dir)

    log.info(
        "supervisor.start",
        phase="A2-identity-register",
        hostname=cfg.hostname,
        control_plane_url=cfg.control_plane_url or None,
        bootstrap_pairing_code_set=bool(cfg.bootstrap_pairing_code),
        state_dir=str(cfg.state_dir),
        heartbeat_interval_seconds=cfg.heartbeat_interval_seconds,
    )

    cfg = _maybe_register(cfg, log)

    # Issue #183 Phase 4 — k3s proxy thread. Daemon thread that
    # long-polls the control plane for queued kubeapi requests +
    # forwards them to the local k3s apiserver. Self-resilient
    # (no cert / no registration / no k3s → sleep + retry); safe
    # to spawn even on legacy compose deployments. The proxy is
    # net-new for #183; pre-#183 control planes don't enqueue
    # anything so the loop just sees empty polls.
    if cfg.k8s_proxy_enabled:
        identity_for_proxy, _ = load_or_generate(cfg.state_dir)
        start_proxy_thread(cfg, identity_for_proxy)
    else:
        log.info("supervisor.k8s_proxy.disabled_by_config")

    # dashboard-and-remote-nettools — agent-perspective network-tool
    # thread. Daemon thread that long-polls the control plane for queued
    # reachability-tool jobs (ping / traceroute / dig / port-test /
    # tls-cert) bound for this appliance + runs them against the local
    # vantage. Self-resilient (no cert / no registration → sleep +
    # retry; 404 against a pre-feature control plane → longer backoff),
    # so it's harmless + dormant on any appliance with no nettool work
    # queued — it just sees empty long-polls. Unlike the k8s-proxy
    # thread it isn't gated on the k3s runtime: a reachability tool runs
    # from ANY approved appliance vantage, remote DNS/DHCP agents
    # included.
    identity_for_nettool, _ = load_or_generate(cfg.state_dir)
    start_nettool_thread(cfg, identity_for_nettool)

    # #999 Part B — md / multipath management. Same shape as the nettool
    # thread (long-poll, act, reply) but the acting is delegated to the
    # host runner over the trigger-file plane, because every action needs
    # a root binary this container should not be executing directly.
    # Dormant on an appliance with no arrays: nothing is ever queued.
    from .storage_proxy import start_storage_thread  # noqa: PLC0415

    start_storage_thread(cfg, identity_for_nettool)

    # #59 Phase 2 — appliance-host packet capture. Daemon thread that
    # long-polls for queued appliance-vantage captures, drives the host
    # runner over the trigger-file pattern, and streams the finished
    # .pcap back. Self-resilient (no cert / registration / 404 → sleep +
    # retry); dormant when no capture is queued.
    from .pcap_proxy import start_pcap_thread  # noqa: PLC0415

    identity_for_pcap, _ = load_or_generate(cfg.state_dir)
    start_pcap_thread(cfg, identity_for_pcap)

    # #404 — tail /dev/kmsg for nftables drop logs so the firewall_logs
    # nettool can serve them to the Firewall → Logs viewer. Harmless if no
    # drops are ever logged (firewall logging off) — the buffer just stays
    # empty. Daemon thread; no-op if /dev/kmsg can't be opened.
    from .kmsg_reader import start as start_kmsg_reader  # noqa: PLC0415

    start_kmsg_reader()

    stop = False

    def _handle_signal(signum: int, _frame: object) -> None:
        nonlocal stop
        log.info("supervisor.signal", signal=signum)
        stop = True

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    # #170 Wave C1 — heartbeat loop replaces the A2 idle. Every
    # ``heartbeat_interval_seconds`` we POST appliance-host telemetry
    # to the control plane and read back the operator's desired state
    # (upgrade / reboot triggers). Only fires when register has
    # produced an appliance_id; otherwise we keep idling so a re-pair
    # from a fresh code can still land.
    # #170 Wave E — external watchdog liveness anchor. The host-side
    # ``spatiumddi-supervisor-watchdog.timer`` reads this file's
    # mtime every 2 min and force-restarts the supervisor container
    # if the loop hasn't ticked in >5 min. Stamped at the TOP of
    # every iteration (not just after a successful heartbeat) so a
    # transient control-plane outage doesn't trigger an unnecessary
    # restart — the loop is alive even when ``heartbeat_once`` fails.
    # ``touch`` semantics: open + close to update mtime; cheap on a
    # 1-CPU VM and a stuck loop simply stops doing it.
    liveness_path = cfg.state_dir / "last-loop-at"
    # #358 Phase 1b — floor between heartbeats when the control plane
    # long-poll-held the previous one. The hold already paced us
    # (~heartbeat_interval server-side); this only bounds the re-post rate
    # if a server ever returns held=True fast in a loop.
    held_rearm_floor_s = 2.0

    while not stop:
        try:
            liveness_path.touch()
        except OSError as exc:
            log.warning("supervisor.liveness.touch_failed", error=str(exc))
        appliance_id = load_appliance_id(cfg.state_dir)
        # #272 Phase 1 — retry the register path each loop iteration
        # while we haven't successfully registered. Catches the
        # control-plane self-bootstrap case where the
        # in-cluster api Service wasn't reachable on the supervisor's
        # first attempt at startup (api pod still coming up). Cheap
        # for the steady-state — cached_appliance_id short-circuits
        # ``_maybe_register`` on its first line.
        if appliance_id is None:
            cfg = _maybe_register(cfg, log)
            appliance_id = load_appliance_id(cfg.state_dir)
        # #272 — cluster members heartbeat the in-cluster api Service
        # (resolved here so the skip-gate matches what heartbeat_once
        # will actually POST to). A control-plane member always has a
        # target even if CONTROL_PLANE_URL was never set; a remote
        # agent only proceeds when its configured URL is present.
        effective_url = _effective_control_plane_url(cfg)
        # #358 Phase 1b — True when the control plane long-poll-held this
        # heartbeat (and thus already paced us ~heartbeat_interval).
        held = False
        if appliance_id is not None and effective_url:
            session_token = load_session_token(cfg.state_dir)
            identity, _ = load_or_generate(cfg.state_dir)
            try:
                with cp_tls.client(cfg.state_dir, effective_url) as client:
                    held = heartbeat_once(
                        cfg=cfg,
                        appliance_id=appliance_id,
                        session_token=session_token,
                        identity=identity,
                        client=client,
                        log=log,
                    )
            except Exception as exc:  # noqa: BLE001
                # Never let a heartbeat exception kill the supervisor —
                # the loop is the supervisor's sole liveness signal.
                log.warning("supervisor.heartbeat.crashed", error=str(exc))
            # #1219 — once approved (the CA has arrived), confirm the
            # certificate pinned at first contact is one the CA vouches for.
            try:
                cp_tls.check_pin_vouched_once(cfg.state_dir, effective_url)
            except Exception as exc:  # noqa: BLE001 — a diagnostic, never fatal
                log.warning("supervisor.tls.vouch_check_crashed", error=str(exc))
        else:
            log.info(
                "supervisor.heartbeat.skipped",
                reason=(
                    "no_appliance_id"
                    if appliance_id is None
                    else "no_control_plane_url"
                ),
                # effective_url is empty here only when this is a
                # remote agent with no configured CONTROL_PLANE_URL.
            )
        # #358 Phase 1b — when the control plane long-poll-held this
        # heartbeat it already blocked ~heartbeat_interval server-side, so
        # re-arm the hold after a short floor instead of sleeping the full
        # interval again (which would roughly halve hold coverage). Old
        # control planes / errors (held=False) keep the full interval.
        sleep_budget = (
            held_rearm_floor_s if held else float(cfg.heartbeat_interval_seconds)
        )
        waited = 0.0
        while waited < sleep_budget:
            if stop:
                break
            time.sleep(1)
            waited += 1.0

    log.info("supervisor.stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
