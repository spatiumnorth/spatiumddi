"""Bootstrap / registration loop for the DNS agent.

Attempts the cached JWT first; on 401 falls back to PSK registration
using ``cfg.dns_agent_key``.

Issue #246 — the pairing-code → PSK exchange via
``POST /api/v1/appliance/pair`` that this module used to do was
removed under #170 Wave A3 ("pairing-code admin surface no longer
owns a consume endpoint; all pairing flows through
``POST /api/v1/appliance/supervisor/register`` now"). Standalone
docker-compose / K8s DNS agents now require ``DNS_AGENT_KEY``
directly; Application appliances receive the key via the
supervisor's ``role-compose.env`` (#170 Wave C2).
"""

from __future__ import annotations

import hashlib
import random
import threading
import time

import httpx
import structlog

from . import __version__, features
from .cache import (
    load_or_create_agent_id,
    load_registered_host,
    load_token,
    save_registered_host,
    save_token,
)
from .config import AgentConfig
from .instance import (
    AGENT_INSTANCE,
    AGENT_INSTANCE_HEADER,
    DUPLICATE_INSTANCE_BACKOFF,
    DUPLICATE_INSTANCE_HEADER,
)

log = structlog.get_logger(__name__)


def _fingerprint(agent_id: str) -> str:
    """SHA-256 fingerprint derived from the agent id. In Phase 3 this becomes
    SHA-256 of a locally-generated ed25519 public key (see DNS_AGENT.md §2)."""
    return hashlib.sha256(agent_id.encode()).hexdigest()


def _client(cfg: AgentConfig) -> httpx.Client:
    verify = cfg.httpx_verify()
    return httpx.Client(
        base_url=cfg.control_plane_url,
        verify=verify,
        timeout=30.0,
        headers=features.headers(),
    )


class RegisterFailed(Exception):
    """``register`` gave up after its ``max_attempts`` (#3757)."""


def register(cfg: AgentConfig, *, max_attempts: int | None = None) -> tuple[str, str, dict]:
    """Perform PSK bootstrap. Returns (agent_id, token, response_body).

    Requires ``DNS_AGENT_KEY`` set in the environment (validated in
    ``AgentConfig.from_env``). Retries until the control plane answers, unless
    ``max_attempts`` is given: then it raises :class:`RegisterFailed` after
    that many failed attempts, without the wait that would follow the last.
    """
    agent_id = load_or_create_agent_id(cfg.state_dir)
    bootstrap_key = cfg.dns_agent_key
    body = {
        "hostname": cfg.server_name,
        "driver": cfg.driver,
        "roles": cfg.roles,
        "group_name": cfg.group_name,
        "fingerprint": _fingerprint(agent_id),
        "agent_id": agent_id,
        "version": __version__,
    }
    if cfg.server_host:
        body["host"] = cfg.server_host
    backoff = 2.0
    attempts = 0
    while True:
        attempts += 1
        try:
            with _client(cfg) as c:
                resp = c.post(
                    "/api/v1/dns/agents/register",
                    json=body,
                    headers={
                        "X-DNS-Agent-Key": bootstrap_key,
                        # #2219 — so the control plane can refuse the
                        # duplicate half of a pair instead of minting it a
                        # token that stales the owner's.
                        AGENT_INSTANCE_HEADER: AGENT_INSTANCE,
                    },
                )
            if resp.status_code == 200:
                data = resp.json()
                save_token(cfg.state_dir, data["agent_token"])
                _note_host_outcome(cfg, data)
                log.info(
                    "dns_agent_registered",
                    server_id=data["server_id"],
                    pending_approval=data.get("pending_approval", False),
                )
                return agent_id, data["agent_token"], data
            if resp.status_code == 409 and resp.headers.get(DUPLICATE_INSTANCE_HEADER):
                # #2219 — another live process owns this server identity; no
                # token was minted, so the owner's stays valid. Ask again at
                # the poll's steady pace rather than the doubling one: the
                # refusal ends the moment the owner stops, and each retry
                # keeps the operator's "Duplicate agent" chip current.
                log.error(
                    "register_duplicate_agent_instance",
                    instance=AGENT_INSTANCE,
                    body=resp.text[:400],
                    retry_in_seconds=DUPLICATE_INSTANCE_BACKOFF,
                )
                if max_attempts is not None and attempts >= max_attempts:
                    raise RegisterFailed("duplicate agent instance")
                time.sleep(DUPLICATE_INSTANCE_BACKOFF + random.uniform(0, 2))
                continue
            log.warning("register_failed", status=resp.status_code, body=resp.text[:400])
        except httpx.HTTPError as e:
            log.warning("register_http_error", error=str(e))
        if max_attempts is not None and attempts >= max_attempts:
            raise RegisterFailed("control plane did not accept the registration")
        # jittered backoff, cap 5 min
        sleep_for = min(backoff + random.uniform(0, 2), 300.0)
        time.sleep(sleep_for)
        backoff = min(backoff * 2, 300.0)


#: #3757 — when a registration carrying SERVER_HOST is answered by a control
#: plane that does not echo ``host`` (a release before #3757: a rolling upgrade
#: restarts this agent and the api together, so it can register against the
#: old api pod), the host is not recorded and the registration is repeated in
#: process every ``HOST_RETRY_INTERVAL_SECONDS`` for up to
#: ``HOST_RETRY_WINDOW_SECONDS``, so the rollout heals without another restart.
HOST_RETRY_INTERVAL_SECONDS = 300.0
HOST_RETRY_WINDOW_SECONDS = 3600.0
_host_retry_at: float | None = None
_host_retry_until: float | None = None


def _arm_host_retry() -> None:
    global _host_retry_at, _host_retry_until
    now = time.monotonic()
    if _host_retry_until is None:
        _host_retry_until = now + HOST_RETRY_WINDOW_SECONDS
    _host_retry_at = now + HOST_RETRY_INTERVAL_SECONDS


def _disarm_host_retry() -> None:
    global _host_retry_at, _host_retry_until
    _host_retry_at = None
    _host_retry_until = None


def _note_host_outcome(cfg: AgentConfig, data: dict) -> None:
    """Record the SERVER_HOST a successful registration carried (#3757), but
    only when the control plane says it read it: the response echoes the row's
    stored ``host``. A different stored value is still recorded (an operator
    edit or the vetting rule decided, on a server that knows the field). No
    echo means an older control plane dropped the field, so the host stays
    unrecorded and a later in-process retry is armed."""
    if not cfg.server_host:
        save_registered_host(cfg.state_dir, None)
        return
    if "host" in data:
        save_registered_host(cfg.state_dir, cfg.server_host)
        _disarm_host_retry()
        return
    log.warning("dns_agent_host_not_acknowledged", host=cfg.server_host)
    _arm_host_retry()


def retry_host_register(cfg: AgentConfig, token_ref: list[str]) -> None:
    """Repeat an unacknowledged host registration once it is due (#3757).

    Called from the heartbeat loop; a no-op unless a retry is armed and due,
    so it does not register on every heartbeat. One attempt per call, never a
    wait: serving never depends on it (non-negotiable #5).
    """
    if _host_retry_at is None:
        return
    now = time.monotonic()
    if now < _host_retry_at:
        return
    if _host_retry_until is not None and now >= _host_retry_until:
        log.warning("dns_agent_host_register_gave_up", host=cfg.server_host)
        _disarm_host_retry()
        return
    with _reauth_lock:
        if not _host_needs_registering(cfg):
            _disarm_host_retry()
            return
        try:
            _agent_id, token, _ = register(cfg, max_attempts=1)
        except RegisterFailed as exc:
            log.warning("dns_agent_host_register_deferred", host=cfg.server_host, reason=str(exc))
            _arm_host_retry()
            return
        token_ref[0] = token


def _host_needs_registering(cfg: AgentConfig) -> bool:
    """Whether ``SERVER_HOST`` is set and differs from the host this agent last
    registered (#3757). Unset never forces a registration: it sends no host, so
    the server row could not change."""
    return bool(cfg.server_host) and load_registered_host(cfg.state_dir) != cfg.server_host


def ensure_token(cfg: AgentConfig) -> tuple[str, str]:
    """Load cached token or re-register. Returns (agent_id, token)."""
    agent_id = load_or_create_agent_id(cfg.state_dir)
    token = load_token(cfg.state_dir)
    if token and _host_needs_registering(cfg):
        # #3757 — a cached token means /register never runs, so a SERVER_HOST
        # this agent has not registered yet (a chart upgrade from a release
        # that set none) would never reach the server row. Register once to
        # carry it; the control plane decides whether the row's host moves.
        # One attempt only: an unreachable control plane must not keep the
        # daemon from starting on its cached config (non-negotiable #5). The
        # cached token stays valid and the heartbeat loop retries later.
        try:
            agent_id, token, _ = register(cfg, max_attempts=1)
        except RegisterFailed as exc:
            log.warning("dns_agent_host_register_deferred", host=cfg.server_host, reason=str(exc))
            _arm_host_retry()
        return agent_id, token
    if token:
        return agent_id, token
    agent_id, token, _ = register(cfg)
    return agent_id, token


# #2052 — one re-bootstrap at a time. The sync loop and the heartbeat both see
# the same 401/404 within moments of each other; the second must find the
# token already replaced rather than register a second row.
_reauth_lock = threading.Lock()

#: A re-registration within this many seconds of the previous one counts as a
#: repeat, and waits before registering. A 401/404 is answered by registering,
#: and a successful register returns at once, so a token the control plane
#: keeps refusing straight after minting it (two agents sharing one agent id
#: off a cloned state dir overwrite each other's token hash; replicas that
#: disagree on the signing key) would otherwise loop register → poll → 401 as
#: fast as the network allows. The container restart this replaced was paced
#: by the orchestrator's restart back-off; this is that pacing.
REAUTH_REPEAT_WINDOW_SECONDS = 60.0
REAUTH_REPEAT_MAX_DELAY_SECONDS = 300.0
_last_reauth_at: float | None = None
_reauth_streak = 0
_reauth_generation = 0


def reauth_generation() -> int:
    """How many times this process has re-registered (#2052).

    A re-registration after a 404 lands on a NEW server row, which has seen
    none of the per-server reports a fresh process sends at startup. Workers
    that send such reports compare this counter with the value they last saw
    and resend them when it moves — whichever thread happened to register.
    """
    return _reauth_generation


def _repeat_delay(now: float) -> float:
    """Seconds to wait before this re-registration; 0 for the first in a while."""
    global _reauth_streak
    if _last_reauth_at is None or now - _last_reauth_at >= REAUTH_REPEAT_WINDOW_SECONDS:
        _reauth_streak = 0
        return 0.0
    _reauth_streak += 1
    base = min(5.0 * 2 ** (_reauth_streak - 1), REAUTH_REPEAT_MAX_DELAY_SECONDS)
    return base + random.uniform(0, 2)


def reauthenticate(cfg: AgentConfig, token_ref: list[str], stale_token: str) -> str:
    """Replace a rejected token in place, from the PSK. Returns the live token.

    Called from the sync / heartbeat threads on a 401 or 404 (token expired,
    or the server row was deleted). It drops the cached token and registers
    again WITHOUT ending the calling thread, so the supervisor's dead-thread
    watch never fires and the daemon keeps serving from its cached config
    (non-negotiable #5) — the previous behaviour stopped the thread, which
    made the supervisor exit the container and took the daemon down with it.

    ``register`` retries with jittered backoff (cap 5 min) until the control
    plane answers, so an unreachable control plane or a wrong PSK waits and
    retries instead of spinning or exiting. A re-registration repeated within
    ``REAUTH_REPEAT_WINDOW_SECONDS`` of the last one waits first, doubling up
    to 5 min. Another thread may have refreshed the token while this one
    waited for the lock; then nothing is registered.
    """
    global _last_reauth_at, _reauth_generation
    with _reauth_lock:
        if token_ref[0] != stale_token:
            return token_ref[0]
        delay = _repeat_delay(time.monotonic())
        if delay:
            log.warning(
                "reauthenticate_repeated_backoff", delay_s=round(delay, 1), streak=_reauth_streak
            )
            time.sleep(delay)
        save_token(cfg.state_dir, "")
        _agent_id, token, _ = register(cfg)
        token_ref[0] = token
        _last_reauth_at = time.monotonic()
        _reauth_generation += 1
        return token


def _reset_reauth_state() -> None:
    """Tests only: forget earlier re-registrations."""
    global _last_reauth_at, _reauth_streak, _reauth_generation
    _last_reauth_at = None
    _reauth_streak = 0
    _reauth_generation = 0
    _disarm_host_retry()
