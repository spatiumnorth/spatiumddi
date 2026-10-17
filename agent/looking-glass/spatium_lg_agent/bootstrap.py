"""Bootstrap / registration loop for the BGP Looking Glass collector agent.

Tries the cached JWT first; on missing/expired token falls back to PSK
registration against ``POST /api/v1/looking-glass/agents/register`` using
``cfg.lg_agent_key``.

There is NO pairing-code ``/pair`` endpoint here — that flow was removed
under #170 Wave A3 for every DNS/DHCP-style agent kind, and the Looking
Glass collector is a new agent kind, not a re-use of the supervisor's own
pairing-code registration. Standalone docker-compose / K8s collectors
require ``LG_AGENT_KEY`` directly; Application appliances receive the key
via the supervisor's ``role-compose.env`` (#170 Wave C2).
"""

from __future__ import annotations

import hashlib
import random
import threading
import time

import httpx
import structlog

from . import __version__
from .cache import load_or_create_agent_id, load_token, save_token
from .config import AgentConfig

log = structlog.get_logger(__name__)


def _fingerprint(agent_id: str) -> str:
    """SHA-256 fingerprint derived from the agent id."""
    return hashlib.sha256(agent_id.encode()).hexdigest()


def _client(cfg: AgentConfig) -> httpx.Client:
    return httpx.Client(
        base_url=cfg.control_plane_url,
        verify=cfg.httpx_verify(),
        timeout=30.0,
    )


def register(cfg: AgentConfig) -> tuple[str, str, dict]:
    """Perform PSK bootstrap. Returns (agent_id, token, response_body).

    Requires ``LG_AGENT_KEY`` set in the environment (validated in
    ``AgentConfig.from_env``).

    Request/response shape matches
    ``backend/app/api/v1/looking_glass/agents.py``'s
    ``AgentRegisterRequest``/``AgentRegisterResponse`` exactly — the
    ``LookingGlassCollector`` row has no server-group concept (unlike
    DNS/DHCP servers), so there is no ``roles``/``group_name`` field to
    send.
    """
    agent_id = load_or_create_agent_id(cfg.state_dir)
    bootstrap_key = cfg.lg_agent_key
    body = {
        "hostname": cfg.server_name,
        "version": __version__,
        "fingerprint": _fingerprint(agent_id),
        "agent_id": agent_id,
    }
    backoff = 2.0
    while True:
        try:
            with _client(cfg) as c:
                resp = c.post(
                    "/api/v1/looking-glass/agents/register",
                    json=body,
                    headers={"X-LG-Agent-Key": bootstrap_key},
                )
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("agent_token")
                if not token:
                    log.error("register_response_missing_token", body=str(data)[:400])
                else:
                    save_token(cfg.state_dir, token)
                    log.info(
                        "lg_agent_registered",
                        collector_id=data.get("collector_id"),
                    )
                    return agent_id, token, data
            else:
                log.warning(
                    "register_failed", status=resp.status_code, body=resp.text[:400]
                )
        except httpx.HTTPError as e:
            log.warning("register_http_error", error=str(e))
        # jittered exponential backoff, cap 5 min
        sleep_for = min(backoff + random.uniform(0, 2), 300.0)
        time.sleep(sleep_for)
        backoff = min(backoff * 2, 300.0)


def ensure_token(cfg: AgentConfig) -> tuple[str, str]:
    """Load cached token or re-register. Returns (agent_id, token)."""
    agent_id = load_or_create_agent_id(cfg.state_dir)
    token = load_token(cfg.state_dir)
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
