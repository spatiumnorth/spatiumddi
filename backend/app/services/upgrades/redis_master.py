"""Move the Redis master off a node before the rolling upgrade drains it (#2815).

On a multi-node control plane Redis runs behind Sentinel (#272 Phase 3), and
the master is whichever pod Sentinel last promoted. Draining the node that
holds it used to leave the failover to Sentinel's own election, and on a
three-node cluster that election can split: the two surviving Sentinels each
vote for themselves, the attempt aborts with ``-failover-abort-not-elected``,
and Sentinel waits twice ``failover-timeout`` (2 x 60 s) before trying again.
The broker had no master for ~128 s on the walk that found it, and the worker
driving the upgrade failed its broker-round-trip liveness probe and was
restarted with the drive inside it.

``SENTINEL FAILOVER`` is the manual path: the Sentinel that receives it
promotes a replica on its own authority, without asking the others for
agreement, so there is no vote to split. Issued while the master is still
healthy, the switch takes a few seconds and the drain that follows evicts a
replica, which costs the broker nothing.

Sentinel picks the replica, but it can be steered (#2870): it prefers the
replica with the lowest non-zero ``replica-priority``. Left alone it may pick
the replica on the NEXT node to drain, whose own turn then fails the master
over a second time (a second broker drop, and another re-queue of the running
drive). So when the roll order is known, the replica on the node that drains
last (or on one the roll has already finished) gets ``replica-priority 1``
with ``CONFIG SET`` for the length of the failover and is restored in a
``finally``. Sentinel only reads a replica's priority from its periodic
``INFO``, so the step waits until Sentinel reports the new value. Any problem
steering falls back to a plain ``SENTINEL FAILOVER``. Priority 0 ("never
promote") is never written, so the steering cannot leave no eligible replica.
Every replica runs on another node (the StatefulSet's anti-affinity is
``required`` at two or more replicas), and the wait below confirms where the
master landed rather than assuming it, the way ``_step_verify_primary_moved``
confirms the CNPG primary.

Failure policy: never fail the node. Everything here is an optimisation of a
failover Sentinel performs anyway once the drain evicts the master; the worst
outcome of skipping it is the pre-#2815 behaviour, which the worker's liveness
probe now rides out (``app.worker_liveness``). Failing the node instead would
block every upgrade on a Sentinel that will not answer, which is a worse
outcome than a two-minute broker blip. So every problem is a ``warning`` in
the result and a log line, and the drain goes ahead.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import time
from dataclasses import dataclass, field
from typing import Any

import redis.asyncio as aioredis
import structlog

from app.config import settings
from app.core.redis_client import _parse_sentinel_url, is_sentinel_url, make_async_redis
from app.services.appliance import k8s

logger = structlog.get_logger(__name__)

# Long enough for a manual failover (a few seconds: promote, reconfigure the
# other replicas, publish the new config) plus the Sentinels' hello interval
# (2 s) for every one of them to report the new master.
DEFAULT_REDIS_SWITCH_TIMEOUT_S = 60.0
_POLL_INTERVAL_S = 2.0
# One Sentinel round trip. A Sentinel on a node that is going away must not
# hold the drive for the OS connect timeout (#590 / #925).
_SENTINEL_TIMEOUT_S = 2.0
# Sentinel refreshes a replica's INFO (where it reads ``replica-priority``)
# every 10 s, so a new priority takes that long to be seen.
_PRIORITY_SEEN_TIMEOUT_S = 15.0
_STEER_PRIORITY = 1
# Originals of every priority the steering changed, written BEFORE the change
# so a drive that died before its ``finally`` can be cleaned up by the next
# run of this step.
PRIORITY_ORIGINALS_KEY = "spatium:upgrade:redis-replica-priority-originals"


@dataclass
class MoveOutcome:
    """What ``move_master_off_node`` found and did. ``warning`` set means the
    master may still be on the node; the caller drains anyway."""

    skipped: bool = False
    reason: str | None = None
    warning: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


def sentinel_configured(url: str | None = None) -> bool:
    """True when the app reaches Redis through Sentinel."""
    return is_sentinel_url(url if url is not None else settings.redis_url)


def _endpoints(url: str) -> tuple[list[tuple[str, int]], str | None]:
    hosts, _db, url_password = _parse_sentinel_url(url)
    return hosts, settings.redis_sentinel_password or url_password


async def _sentinel_command(host: str, port: int, password: str | None, *args: Any) -> Any:
    """One command to one Sentinel, raw reply. ``SENTINEL`` as the command name
    has no redis-py response callback, so the reply comes back unparsed."""
    client = aioredis.Redis(
        host=host,
        port=port,
        password=password or None,
        socket_connect_timeout=_SENTINEL_TIMEOUT_S,
        socket_timeout=_SENTINEL_TIMEOUT_S,
        decode_responses=True,
    )
    try:
        return await client.execute_command(*args)
    finally:
        await client.aclose()


async def _sentinel_masters(url: str, master_name: str) -> list[str | None]:
    """The master host each Sentinel that answered reports; None for one that
    answered without knowing a master. Sentinels that did not answer are
    absent, so an empty list means none answered."""
    hosts, password = _endpoints(url)

    async def _ask(host: str, port: int) -> tuple[bool, str | None]:
        try:
            reply = await _sentinel_command(
                host, port, password, "SENTINEL", "GET-MASTER-ADDR-BY-NAME", master_name
            )
        except Exception as exc:  # noqa: BLE001 — an unreachable Sentinel is just absent
            logger.debug("upgrade_redis_sentinel_unreachable", sentinel=host, error=str(exc))
            return False, None
        if isinstance(reply, (list, tuple)) and reply:
            return True, str(reply[0])
        return True, None

    answers = await asyncio.gather(*(_ask(h, p) for h, p in hosts))
    return [master for answered, master in answers if answered]


async def _sentinel_healthy_replicas(url: str, master_name: str) -> int | None:
    """How many replicas the first Sentinel to answer considers usable (not
    subjectively / objectively down, not disconnected). None: none answered."""
    hosts, password = _endpoints(url)
    for host, port in hosts:
        try:
            reply = await _sentinel_command(
                host, port, password, "SENTINEL", "REPLICAS", master_name
            )
        except Exception as exc:  # noqa: BLE001 — try the next Sentinel
            logger.debug("upgrade_redis_sentinel_unreachable", sentinel=host, error=str(exc))
            continue
        healthy = 0
        for entry in reply or []:
            fields = dict(zip(entry[::2], entry[1::2], strict=False)) if entry else {}
            flags = set(str(fields.get("flags", "")).split(","))
            if not flags & {"s_down", "o_down", "disconnected"}:
                healthy += 1
        return healthy
    return None


async def _sentinel_failover(url: str, master_name: str) -> str | None:
    """Ask one Sentinel to fail the master over. None on success (or a failover
    already in progress, which is what we wanted); otherwise the last error."""
    hosts, password = _endpoints(url)
    last_error = "no Sentinel answered"
    for host, port in hosts:
        try:
            await _sentinel_command(host, port, password, "SENTINEL", "FAILOVER", master_name)
            return None
        except Exception as exc:  # noqa: BLE001 — classify, then try the next Sentinel
            text = str(exc)
            if "INPROG" in text:
                return None
            last_error = f"{host}: {text}"
            # NOGOODSLAVE is the cluster's answer, not this Sentinel's; asking
            # another one gets the same reply.
            if "NOGOODSLAVE" in text:
                return last_error
    return last_error


async def _sentinel_replicas(url: str, master_name: str) -> list[dict[str, str]] | None:
    """The replicas the first Sentinel to answer lists, as field dicts (``ip``,
    ``port``, ``flags``, ``slave-priority`` ...). None: no Sentinel answered."""
    hosts, password = _endpoints(url)
    for host, port in hosts:
        try:
            reply = await _sentinel_command(
                host, port, password, "SENTINEL", "REPLICAS", master_name
            )
        except Exception as exc:  # noqa: BLE001 — try the next Sentinel
            logger.debug("upgrade_redis_sentinel_unreachable", sentinel=host, error=str(exc))
            continue
        out: list[dict[str, str]] = []
        for entry in reply or []:
            if entry:
                out.append({str(k): str(v) for k, v in zip(entry[::2], entry[1::2], strict=False)})
        return out
    return None


async def _data_command(url: str, host: str, port: int, *args: Any) -> Any:
    """One command straight to a Redis data node (not a Sentinel)."""
    password = _parse_sentinel_url(url)[2]
    client = aioredis.Redis(
        host=host,
        port=port,
        password=password or None,
        socket_connect_timeout=_SENTINEL_TIMEOUT_S,
        socket_timeout=_SENTINEL_TIMEOUT_S,
        decode_responses=True,
    )
    try:
        return await client.execute_command(*args)
    finally:
        await client.aclose()


async def _set_priority(url: str, host: str, port: int, value: int) -> None:
    await _data_command(url, host, port, "CONFIG", "SET", "replica-priority", str(value))


async def _store_originals(url: str, entries: list[dict[str, Any]]) -> None:
    client = make_async_redis(url)
    try:
        await client.set(PRIORITY_ORIGINALS_KEY, json.dumps(entries))
    finally:
        await client.aclose()


async def _clear_originals(url: str) -> None:
    client = make_async_redis(url)
    try:
        await client.delete(PRIORITY_ORIGINALS_KEY)
    finally:
        await client.aclose()


async def restore_priorities(url: str, entries: list[dict[str, Any]]) -> bool:
    """Put every recorded priority back. True when all of them went back and
    the record is cleared. Best-effort: a failure is logged, never raised."""
    ok = True
    for e in entries:
        try:
            await _set_priority(url, e["host"], int(e["port"]), int(e["priority"]))
        except Exception as exc:  # noqa: BLE001 — restore the rest regardless
            ok = False
            logger.warning(
                "upgrade_redis_priority_restore_failed", replica=e.get("host"), error=str(exc)
            )
    if ok:
        try:
            await _clear_originals(url)
        except Exception as exc:  # noqa: BLE001 — a stale record is re-applied harmlessly
            logger.debug("upgrade_redis_priority_record_not_cleared", error=str(exc))
    return ok


async def _restore_leftover(url: str) -> None:
    """Undo steering a drive that died before its ``finally`` left behind."""
    try:
        client = make_async_redis(url)
        try:
            raw = await client.get(PRIORITY_ORIGINALS_KEY)
        finally:
            await client.aclose()
        if not raw:
            return
        entries = json.loads(raw)
    except Exception as exc:  # noqa: BLE001 — nothing to restore, or Redis unreachable
        logger.debug("upgrade_redis_priority_leftover_unreadable", error=str(exc))
        return
    logger.info("upgrade_redis_priority_leftover_restoring", replicas=len(entries))
    await restore_priorities(url, entries)


@dataclass
class _Steering:
    """The ``replica-priority`` changes made for one failover, to be undone."""

    changed: list[dict[str, Any]] = field(default_factory=list)

    async def restore(self, url: str) -> None:
        if self.changed:
            entries, self.changed = self.changed, []
            await restore_priorities(url, entries)


def _drain_position(node: str | None, remaining: list[str]) -> int:
    """Higher = drains later. A node the roll has finished with never drains
    again, so it ranks above every node still to come."""
    if node in remaining:
        return remaining.index(node)
    return len(remaining)


async def _steer_replicas(
    url: str,
    master_name: str,
    node_name: str,
    remaining: list[str],
    namespace: str | None,
    out: MoveOutcome,
    steering: _Steering,
) -> None:
    """Lower ``replica-priority`` on the replica Sentinel should promote: the
    one on the node that drains last. Leaves ``steering.changed`` holding what
    to restore. Never raises; any problem is a log line and an unsteered
    failover."""
    try:
        replicas = await _sentinel_replicas(url, master_name)
        if replicas is None:
            logger.info("upgrade_redis_steer_skipped", reason="no Sentinel listed the replicas")
            return
        candidates: list[tuple[str, int, int, str]] = []  # host, port, priority, node
        for r in replicas:
            flags = set(r.get("flags", "").split(","))
            prio = int(r.get("slave-priority", "100"))
            if flags & {"s_down", "o_down", "disconnected"} or prio == 0:
                continue
            host = r.get("ip", "")
            node = redis_host_node(host, namespace)
            if node is None or node == node_name:
                continue
            candidates.append((host, int(r.get("port", "6379")), prio, node))
        if len(candidates) < 2:
            logger.info(
                "upgrade_redis_steer_skipped",
                reason="fewer than two eligible replicas, nothing to choose between",
            )
            return
        target = max(candidates, key=lambda c: _drain_position(c[3], remaining))
        t_pos = _drain_position(target[3], remaining)
        worse = [c for c in candidates if _drain_position(c[3], remaining) < t_pos]
        if not worse:
            return  # every eligible replica drains no earlier than the target
        lowest_worse = min(c[2] for c in worse)
        if target[2] < lowest_worse:
            out.detail["steered_to"] = target[3]  # already preferred, nothing to change
            return
        if lowest_worse <= _STEER_PRIORITY:
            logger.info(
                "upgrade_redis_steer_skipped",
                reason="a replica that drains sooner already has the lowest priority",
            )
            return
        host, port, original, node = target
        record = [{"host": host, "port": port, "priority": original}]
        await _store_originals(url, record)
        steering.changed = list(record)  # from here a failure still restores
        await _set_priority(url, host, port, _STEER_PRIORITY)
        out.detail.update(steered_to=node, replica_priority_set=_STEER_PRIORITY)
        deadline = time.monotonic() + _PRIORITY_SEEN_TIMEOUT_S
        while True:
            seen = await _sentinel_replicas(url, master_name) or []
            if any(
                r.get("ip") == host and r.get("slave-priority") == str(_STEER_PRIORITY)
                for r in seen
            ):
                return
            if time.monotonic() >= deadline:
                logger.warning(
                    "upgrade_redis_steer_not_seen", replica=host, waited_s=_PRIORITY_SEEN_TIMEOUT_S
                )
                return
            await asyncio.sleep(_POLL_INTERVAL_S)
    except Exception as exc:  # noqa: BLE001 — steering is an optimisation; fall back
        logger.warning("upgrade_redis_steer_failed", error=str(exc))


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def redis_host_node(host: str, namespace: str | None) -> str | None:
    """The node the Redis pod announcing ``host`` runs on, or None.

    The chart has every pod announce its stable StatefulSet FQDN
    (``<pod>.<headless>.<namespace>.svc…``, #590), so the first label is the
    pod and the third its namespace. An IP (an install predating that) is
    matched against the pods' IPs in ``namespace`` instead."""
    if _is_ip(host):
        try:
            pods = k8s.list_pods(namespace)
        except k8s.KubeapiUnavailableError:
            return None
        for pod in pods:
            status = pod.get("status") or {}
            ips = {status.get("podIP")} | {(p or {}).get("ip") for p in status.get("podIPs") or []}
            if host in ips:
                return ((pod.get("spec") or {}).get("nodeName")) or None
        return None
    labels = host.split(".")
    pod_name = labels[0]
    pod_ns = labels[2] if len(labels) >= 3 and labels[2] else namespace
    try:
        status, pod = k8s.get_pod(pod_name, namespace=pod_ns)
    except k8s.KubeapiUnavailableError:
        return None
    if status != 200 or pod is None:
        return None
    return ((pod.get("spec") or {}).get("nodeName")) or None


async def _agreed_master(url: str, master_name: str) -> tuple[str | None, list[str | None]]:
    """The master every answering Sentinel names, or None while they disagree,
    none knows one, or none answered."""
    reported = await _sentinel_masters(url, master_name)
    distinct = set(reported)
    if len(distinct) == 1 and None not in distinct:
        return reported[0], reported
    return None, reported


async def move_master_off_node(
    node_name: str,
    *,
    namespace: str | None = None,
    timeout_s: float = DEFAULT_REDIS_SWITCH_TIMEOUT_S,
    url: str | None = None,
    remaining_nodes: list[str] | None = None,
) -> MoveOutcome:
    """``_move_loop`` plus the replica-priority steering (#2870): the priority
    changed for the failover is restored whatever the loop does."""
    url = url if url is not None else settings.redis_url
    if not sentinel_configured(url):
        return await _move_loop(node_name, namespace, timeout_s, url, remaining_nodes, _Steering())
    await _restore_leftover(url)
    steering = _Steering()
    try:
        return await _move_loop(node_name, namespace, timeout_s, url, remaining_nodes, steering)
    finally:
        await steering.restore(url)


async def _move_loop(
    node_name: str,
    namespace: str | None,
    timeout_s: float,
    url: str,
    remaining_nodes: list[str] | None,
    steering: _Steering,
) -> MoveOutcome:
    """Make sure the Redis master is not on ``node_name``, failing it over if
    it is, and wait (up to ``timeout_s``) until every answering Sentinel names
    a master on another node.

    Idempotent, so a resumed drive simply runs it again: a master already
    elsewhere is a no-op, and a failover the earlier drive started answers the
    new request with ``INPROG``, which is waited on like a fresh one."""
    master_name = settings.redis_sentinel_master
    out = MoveOutcome(detail={"node": node_name})
    if not sentinel_configured(url):
        out.skipped, out.reason = True, "Redis is not behind Sentinel"
        return out

    deadline = time.monotonic() + timeout_s
    failover_requested = False
    last_master: str | None = None
    last_reported: list[str | None] = []
    while True:
        master, reported = await _agreed_master(url, master_name)
        last_reported = reported
        if master is not None:
            last_master = master
            master_node = redis_host_node(master, namespace)
            out.detail.update(master=master, master_node=master_node)
            if master_node is not None and master_node != node_name:
                if failover_requested:
                    out.detail["moved"] = True
                return out
            if master_node is None and not failover_requested:
                out.warning = f"could not find the node of the Redis master {master}"
                return out
            if master_node == node_name and not failover_requested:
                replicas = await _sentinel_healthy_replicas(url, master_name)
                out.detail["healthy_replicas"] = replicas
                if replicas == 0:
                    out.skipped = True
                    out.reason = "the Redis master has no healthy replica to fail over to"
                    return out
                if remaining_nodes and (replicas is None or replicas > 1):
                    await _steer_replicas(
                        url, master_name, node_name, list(remaining_nodes), namespace, out, steering
                    )
                error = await _sentinel_failover(url, master_name)
                if error is not None:
                    out.warning = f"SENTINEL FAILOVER refused: {error}"
                    return out
                failover_requested = True
                out.detail["failover_requested"] = True
                logger.info("upgrade_redis_failover_requested", node=node_name, master=master)
        elif not reported and not failover_requested:
            out.warning = "no Redis Sentinel answered"
            return out
        if time.monotonic() >= deadline:
            break
        await asyncio.sleep(_POLL_INTERVAL_S)

    if failover_requested:
        out.warning = (
            f"Redis master not confirmed off {node_name} after {timeout_s:.0f}s "
            f"(last agreed master: {last_master}; Sentinels reported: {last_reported})"
        )
    else:
        out.warning = (
            f"Redis Sentinels did not agree on a master within {timeout_s:.0f}s "
            f"(reported: {last_reported})"
        )
    return out
