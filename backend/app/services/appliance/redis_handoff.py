"""Move the Redis master off the members a demote removes (#1860).

A control-plane cluster runs Redis as a StatefulSet with a Sentinel beside
each pod (``charts/spatiumddi/templates/redis-sentinel.yaml``). Sentinel
moves the master on its own, so after any failover it can sit on any node.
A Sentinel fails over only with the agreement of a majority of ALL the
Sentinels it knows, and it never forgets one it has seen until a
``SENTINEL RESET``.

The one demote three members allow takes both non-seed members out at
once. When the master was on one of them, the seed's Sentinel was left
alone, one of the three it knew. It could not reach a majority, so the
master stayed a pod that no longer ran. Nothing could fix that later.
Shrinking the set to one replica re-renders the seed's Sentinel, but the
seed's supervisor only learns the new size through the api, and the api
has no Redis master, so it answered 502 for good.

So the demote moves the master first, while all three Sentinels are still
up. Every Redis pod on a leaving node gets ``replica-priority 0`` (Sentinel
never promotes such a replica), and when the master itself is on a leaving
node a ``SENTINEL FAILOVER`` hands it to a replica on a node that stays.
The demote goes ahead only once a Sentinel names that replica and it
answers ``ROLE`` as master. If that cannot be done, the priorities are put
back and the demote is refused, because going ahead would take the api
down. The leaving pods keep priority 0 once the demote goes ahead: they
are about to stop, and a pod restart renders its config afresh.

Nothing is done when Redis is not behind Sentinel (a single node, compose)
or when there is no kubeapi to say which node each Redis pod runs on.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, cast

import redis as redis_sync
import structlog
from redis.sentinel import MasterNotFoundError
from redis.sentinel import Sentinel as SentinelSync

from app.config import settings
from app.core.redis_client import _parse_sentinel_url, _sentinel_kwargs, is_sentinel_url
from app.services.appliance import k8s

logger = structlog.get_logger(__name__)

#: How long the demote waits for Sentinel to promote a replica on a node
#: that stays. A forced failover to a healthy replica takes a few seconds:
#: the chosen replica is promoted and the others are pointed at it.
HANDOFF_TIMEOUT_S = 30.0
POLL_S = 1.0
#: Every Redis and Sentinel call is bounded (#925): a pod on a node that is
#: going away must cost its timeout, not minutes.
_TIMEOUTS: dict[str, Any] = {"socket_connect_timeout": 2.0, "socket_timeout": 5.0}
#: The StatefulSet's pods are ``<release>-redis-<ordinal>``.
_REDIS_POD = re.compile(r"-redis-\d+$")
_REDIS_PORT = 6379
#: Redis's own default, for a pod whose priority could not be read.
_DEFAULT_PRIORITY = "100"


class RedisHandoffError(RuntimeError):
    """The master runs on a leaving node and could not be moved off it."""


@dataclass(frozen=True)
class RedisPod:
    name: str
    node: str
    ip: str


@dataclass
class Handoff:
    """What the hand-off did.

    ``outcome`` is ``skipped`` (nothing to do here), ``kept`` (the master
    already ran on a node that stays) or ``moved``."""

    outcome: str
    detail: str
    master_before: str = ""
    master_after: str = ""
    deprioritised: list[str] = field(default_factory=list)


def redis_pods(pods: list[dict[str, Any]]) -> dict[str, RedisPod]:
    """The Redis StatefulSet's pods among ``pods``, by name: a
    ``<release>-redis-<n>`` pod that runs a ``sentinel`` container."""
    out: dict[str, RedisPod] = {}
    for pod in pods:
        name = str((pod.get("metadata") or {}).get("name") or "")
        spec = pod.get("spec") or {}
        if not _REDIS_POD.search(name):
            continue
        if not any(c.get("name") == "sentinel" for c in spec.get("containers") or []):
            continue
        out[name] = RedisPod(
            name=name,
            node=str(spec.get("nodeName") or ""),
            ip=str((pod.get("status") or {}).get("podIP") or ""),
        )
    return out


def pod_for(address: str, pods: dict[str, RedisPod]) -> str:
    """The pod a Sentinel's master address names: the first label of the
    pod's stable FQDN, which the chart's Sentinels announce, or its IP."""
    first = address.split(".", 1)[0]
    if first in pods:
        return first
    for name, pod in pods.items():
        if pod.ip and pod.ip == address:
            return name
    return ""


def _sentinel() -> SentinelSync:
    """A Sentinel client built the way ``core.redis_client`` builds one."""
    hosts, _db, url_password = _parse_sentinel_url(settings.redis_url)
    sentinel_password = settings.redis_sentinel_password or url_password
    return SentinelSync(
        hosts,
        sentinel_kwargs=_sentinel_kwargs(sentinel_password, _TIMEOUTS),
        password=url_password,
        **_TIMEOUTS,
    )


def _redis_at(host: str) -> redis_sync.Redis:
    """A client for one Redis pod, with the password the api's clients use."""
    _hosts, _db, url_password = _parse_sentinel_url(settings.redis_url)
    return redis_sync.Redis(
        host=host,
        port=_REDIS_PORT,
        password=url_password,
        decode_responses=True,
        **_TIMEOUTS,
    )


def _address(pod: RedisPod, master_address: str, pods: dict[str, RedisPod]) -> str:
    """Where to reach ``pod``: its IP, else its FQDN, built from the
    master's when the master's address is one."""
    if pod.ip:
        return pod.ip
    master = pod_for(master_address, pods)
    if master and master_address.startswith(f"{master}."):
        return pod.name + master_address[len(master) :]
    return ""


def hand_off(
    leaving_nodes: set[str],
    *,
    timeout_s: float = HANDOFF_TIMEOUT_S,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> Handoff:
    """Make sure no Redis pod on ``leaving_nodes`` is, or can become, the
    master. Raises :class:`RedisHandoffError` when the master runs on a
    leaving node and could not be moved, and
    :class:`k8s.KubeapiUnavailableError` when the pods could not be listed.
    Blocking: call it in a thread."""
    if not is_sentinel_url(settings.redis_url):
        return Handoff("skipped", "Redis is not behind Sentinel")
    if k8s.get_config() is None:
        return Handoff("skipped", "no kubeapi to say which node each Redis pod runs on")
    pods = redis_pods(k8s.list_pods())
    leaving = sorted(name for name, pod in pods.items() if pod.node in leaving_nodes)
    if not leaving:
        return Handoff("kept", "no Redis pod runs on a node this demote removes")

    name = settings.redis_sentinel_master
    sentinel = _sentinel()
    try:
        master_address, _port = sentinel.discover_master(name)
    except (MasterNotFoundError, redis_sync.RedisError) as exc:
        raise RedisHandoffError(f"no Sentinel names a Redis master ({exc})") from exc
    master = pod_for(str(master_address), pods)
    if not master:
        # Not knowing where the master runs is not knowing whether this
        # demote takes it: refuse rather than guess.
        raise RedisHandoffError(
            f"Sentinel names {master_address} as the Redis master, which is none of the "
            f"Redis pods ({', '.join(sorted(pods)) or 'none listed'})"
        )
    where = f"{master} on {pods[master].node}"
    master_leaves = master in leaving

    # Never promote a pod that is leaving: replica-priority 0 on each one,
    # the master too, so a later failover cannot hand it back.
    previous: dict[str, str] = {}
    failed: dict[str, str] = {}
    for pod_name in leaving:
        address = _address(pods[pod_name], str(master_address), pods)
        try:
            if not address:
                raise redis_sync.ConnectionError("the pod has no address")
            client = _redis_at(address)
            got = cast(dict[str, Any], client.config_get("replica-priority"))
            previous[pod_name] = str(got.get("replica-priority") or _DEFAULT_PRIORITY)
            client.config_set("replica-priority", 0)
        except redis_sync.RedisError as exc:
            failed[pod_name] = f"{type(exc).__name__}: {exc}"

    def _restore() -> None:
        for pod_name, value in previous.items():
            try:
                _redis_at(_address(pods[pod_name], str(master_address), pods)).config_set(
                    "replica-priority", value
                )
            except redis_sync.RedisError as exc:
                logger.warning("redis_handoff_restore_failed", pod=pod_name, error=str(exc))

    if not master_leaves:
        if failed:
            # The master stays where it is; a leaving replica that kept its
            # priority can only matter if the master fails during the leave.
            logger.warning("redis_handoff_deprioritise_failed", pods=failed)
        return Handoff(
            "kept",
            f"the Redis master ({where}) runs on a node that stays",
            master_before=master,
            master_after=master,
            deprioritised=sorted(previous),
        )

    if failed:
        _restore()
        raise RedisHandoffError(
            f"the Redis master ({where}) runs on a node this demote removes, and "
            "the replicas there could not be kept from being promoted in its place ("
            + "; ".join(f"{p}: {e}" for p, e in sorted(failed.items()))
            + ")"
        )

    last = ""
    for client in sentinel.sentinels:
        try:
            client.sentinel_failover(name)
            break
        except redis_sync.RedisError as exc:
            last = f"{type(exc).__name__}: {exc}"
    else:
        _restore()
        raise RedisHandoffError(
            f"the Redis master ({where}) runs on a node this demote removes, and no "
            f"Sentinel would fail it over to a node that stays ({last or 'no Sentinel'})"
        )

    deadline = clock() + timeout_s
    while True:
        try:
            address, _port = sentinel.discover_master(name)
            now_on = pod_for(str(address), pods)
            if now_on and now_on not in leaving:
                role = _redis_at(_address(pods[now_on], str(address), pods)).role()
                if role and str(role[0]) == "master":
                    logger.info(
                        "redis_handoff_moved",
                        before=master,
                        after=now_on,
                        node=pods[now_on].node,
                    )
                    return Handoff(
                        "moved",
                        f"the Redis master moved from {where} to {now_on} on {pods[now_on].node}",
                        master_before=master,
                        master_after=now_on,
                        deprioritised=sorted(previous),
                    )
                last = f"{now_on} answers ROLE {role[0] if role else '?'}"
            else:
                last = f"Sentinel still names {now_on or address}"
        except (MasterNotFoundError, redis_sync.RedisError) as exc:
            last = f"{type(exc).__name__}: {exc}"
        if clock() >= deadline:
            _restore()
            raise RedisHandoffError(
                f"the Redis master ({where}) runs on a node this demote removes, and "
                f"Sentinel did not move it to a node that stays within {timeout_s:.0f}s "
                f"({last})"
            )
        sleep(POLL_S)
