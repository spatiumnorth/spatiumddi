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
import time

import httpx
import structlog

from . import features
from .cache import load_or_create_agent_id, load_token, save_token
from .config import AgentConfig

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


def register(cfg: AgentConfig) -> tuple[str, str, dict]:
    """Perform PSK bootstrap. Returns (agent_id, token, response_body).

    Requires ``DNS_AGENT_KEY`` set in the environment (validated in
    ``AgentConfig.from_env``).
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
        "version": "2026.04.14.1",
    }
    backoff = 2.0
    while True:
        try:
            with _client(cfg) as c:
                resp = c.post(
                    "/api/v1/dns/agents/register",
                    json=body,
                    headers={"X-DNS-Agent-Key": bootstrap_key},
                )
            if resp.status_code == 200:
                data = resp.json()
                save_token(cfg.state_dir, data["agent_token"])
                log.info(
                    "dns_agent_registered",
                    server_id=data["server_id"],
                    pending_approval=data.get("pending_approval", False),
                )
                return agent_id, data["agent_token"], data
            log.warning(
                "register_failed", status=resp.status_code, body=resp.text[:400]
            )
        except httpx.HTTPError as e:
            log.warning("register_http_error", error=str(e))
        # jittered backoff, cap 5 min
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
