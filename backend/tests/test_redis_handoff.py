"""#1860 — a demote moves the Redis master off the nodes it removes.

Two non-seed members of three leave in one demote. When the master was on
one of them, the seed's lone Sentinel could never move it (a failover needs
a majority of the three Sentinels it knew), and the api answered 502 for
good. ``redis_handoff.hand_off`` runs before the demote changes anything:
it keeps every Redis pod on a leaving node from being promoted, and moves
the master to a node that stays when it runs on one that leaves.
"""

from __future__ import annotations

import pytest
import redis as redis_sync
from redis.sentinel import MasterNotFoundError

from app.services.appliance import k8s, redis_handoff

SUFFIX = ".spatium-redis-headless.spatium.svc.cluster.local"
SENTINEL_URL = (
    "sentinel://:pw@" + ",".join(f"spatium-redis-{i}{SUFFIX}:26379" for i in range(3)) + "/0"
)
#: pod -> (node, ip)
PODS = {
    "spatium-redis-0": ("seed", "10.42.0.10"),
    "spatium-redis-1": ("m1", "10.42.1.10"),
    "spatium-redis-2": ("m2", "10.42.2.10"),
}


def _pod(name: str, node: str, ip: str, containers=("redis", "sentinel")) -> dict:
    return {
        "metadata": {"name": name},
        "spec": {"nodeName": node, "containers": [{"name": c} for c in containers]},
        "status": {"podIP": ip},
    }


class Cluster:
    """Three Redis pods with a Sentinel each. ``failover()`` promotes the
    first replica whose priority is not 0, as Sentinel would."""

    def __init__(self, master: str = "spatium-redis-0") -> None:
        self.master: str | None = master
        self.priority = {ip: "100" for _node, ip in PODS.values()}
        self.down: set[str] = set()
        self.calls: list[tuple] = []
        self.failover_error = ""
        self.stall = False
        self.named = ""  # an address Sentinel names instead of a pod's

    def ip(self, pod: str) -> str:
        return PODS[pod][1]

    def failover(self) -> None:
        if self.stall:
            return
        for pod in sorted(PODS):
            if pod != self.master and self.priority[self.ip(pod)] != "0":
                self.master = pod
                return


class FakeRedis:
    def __init__(self, cluster: Cluster, host: str) -> None:
        self.cluster, self.host = cluster, host

    def _up(self) -> None:
        if self.host in self.cluster.down:
            raise redis_sync.ConnectionError(f"Error connecting to {self.host}:6379")

    def config_get(self, key: str) -> dict:
        self._up()
        return {key: self.cluster.priority[self.host]}

    def config_set(self, key: str, value) -> bool:
        self._up()
        self.cluster.priority[self.host] = str(value)
        self.cluster.calls.append(("priority", self.host, str(value)))
        return True

    def role(self) -> list:
        self._up()
        master = self.cluster.master
        return ["master" if master and self.cluster.ip(master) == self.host else "slave", 0, []]


class FakeSentinelClient:
    def __init__(self, cluster: Cluster) -> None:
        self.cluster = cluster

    def sentinel_failover(self, name: str) -> bool:
        self.cluster.calls.append(("failover", name))
        if self.cluster.failover_error:
            raise redis_sync.ResponseError(self.cluster.failover_error)
        self.cluster.failover()
        return True


class FakeSentinel:
    def __init__(self, cluster: Cluster) -> None:
        self.cluster = cluster
        self.sentinels = [FakeSentinelClient(cluster)]

    def discover_master(self, name: str):
        if self.cluster.named:
            return self.cluster.named, 6379
        if self.cluster.master is None:
            raise MasterNotFoundError(f"No master found for {name!r}")
        return f"{self.cluster.master}{SUFFIX}", 6379


class Clock:
    def __init__(self) -> None:
        self.t = 0.0

    def __call__(self) -> float:
        return self.t

    def sleep(self, s: float) -> None:
        self.t += s


@pytest.fixture
def cluster(monkeypatch) -> Cluster:
    c = Cluster()
    pods = [_pod(name, node, ip) for name, (node, ip) in PODS.items()]
    pods.append(_pod("spatium-api-7d9f-x2", "m1", "10.42.1.20", containers=("api",)))
    pods.append(_pod("other-redis-0", "m1", "10.42.1.30", containers=("redis",)))
    monkeypatch.setattr(redis_handoff.settings, "redis_url", SENTINEL_URL)
    monkeypatch.setattr(redis_handoff.settings, "redis_sentinel_master", "mymaster")
    monkeypatch.setattr(k8s, "get_config", object)
    monkeypatch.setattr(k8s, "list_pods", lambda namespace=None: pods)
    monkeypatch.setattr(redis_handoff, "_sentinel", lambda: FakeSentinel(c))
    monkeypatch.setattr(redis_handoff, "_redis_at", lambda host: FakeRedis(c, host))
    return c


def _hand_off(leaving: set[str], clock: Clock | None = None):
    clock = clock or Clock()
    return redis_handoff.hand_off(leaving, sleep=clock.sleep, clock=clock)


def test_the_redis_pods_are_the_statefulsets_with_a_sentinel() -> None:
    pods = redis_handoff.redis_pods(
        [
            _pod("spatium-redis-0", "seed", "10.42.0.10"),
            _pod("other-redis-0", "m1", "x", ("redis",)),
        ]
    )
    assert list(pods) == ["spatium-redis-0"]
    assert redis_handoff.pod_for(f"spatium-redis-0{SUFFIX}", pods) == "spatium-redis-0"
    assert redis_handoff.pod_for("10.42.0.10", pods) == "spatium-redis-0"
    assert redis_handoff.pod_for("10.9.9.9", pods) == ""


def test_nothing_is_done_when_redis_is_not_behind_sentinel(monkeypatch) -> None:
    monkeypatch.setattr(redis_handoff.settings, "redis_url", "redis://redis:6379/0")

    def _never(*_a, **_kw):
        raise AssertionError("listed pods for a plain Redis")

    monkeypatch.setattr(k8s, "list_pods", _never)
    assert _hand_off({"m1", "m2"}).outcome == "skipped"


def test_nothing_is_done_without_a_kubeapi(monkeypatch, cluster: Cluster) -> None:
    monkeypatch.setattr(k8s, "get_config", lambda: None)
    got = _hand_off({"m1", "m2"})
    assert got.outcome == "skipped"
    assert cluster.calls == []


def test_a_demote_of_nodes_without_redis_pods_keeps_everything(cluster: Cluster) -> None:
    got = _hand_off({"m9"})
    assert got.outcome == "kept"
    assert cluster.calls == []


def test_a_master_on_a_node_that_stays_is_kept_and_the_leavers_never_promoted(
    cluster: Cluster,
) -> None:
    got = _hand_off({"m1", "m2"})
    assert got.outcome == "kept", got
    assert got.master_before == got.master_after == "spatium-redis-0"
    assert got.deprioritised == ["spatium-redis-1", "spatium-redis-2"]
    assert ("failover", "mymaster") not in cluster.calls
    assert cluster.priority["10.42.1.10"] == cluster.priority["10.42.2.10"] == "0"
    assert cluster.priority["10.42.0.10"] == "100"


def test_a_master_on_a_leaving_node_moves_to_the_node_that_stays(cluster: Cluster) -> None:
    """The walk's case: the master on member-1 when both members leave."""
    cluster.master = "spatium-redis-1"
    got = _hand_off({"m1", "m2"})
    assert got.outcome == "moved", got
    assert got.master_before == "spatium-redis-1" and got.master_after == "spatium-redis-0"
    assert "to spatium-redis-0 on seed" in got.detail
    # Both leavers are kept from promotion before the failover is asked:
    # otherwise Sentinel could hand the master to the other leaving member.
    assert cluster.calls == [
        ("priority", "10.42.1.10", "0"),
        ("priority", "10.42.2.10", "0"),
        ("failover", "mymaster"),
    ]


def test_a_failover_that_never_lands_refuses_and_puts_the_priorities_back(
    cluster: Cluster,
) -> None:
    cluster.master = "spatium-redis-2"
    cluster.stall = True
    clock = Clock()
    with pytest.raises(redis_handoff.RedisHandoffError) as err:
        _hand_off({"m1", "m2"}, clock)
    assert "did not move it to a node that stays within 30s" in str(err.value)
    assert "spatium-redis-2 on m2" in str(err.value)
    assert cluster.priority["10.42.1.10"] == cluster.priority["10.42.2.10"] == "100"
    assert clock.t >= redis_handoff.HANDOFF_TIMEOUT_S


def test_a_failover_sentinel_refuses_is_a_refusal(cluster: Cluster) -> None:
    cluster.master = "spatium-redis-1"
    cluster.failover_error = "NOGOODSLAVE No suitable replica to promote"
    with pytest.raises(redis_handoff.RedisHandoffError) as err:
        _hand_off({"m1", "m2"})
    assert "NOGOODSLAVE" in str(err.value)
    assert cluster.priority["10.42.1.10"] == cluster.priority["10.42.2.10"] == "100"


def test_an_unreachable_leaving_replica_refuses_when_the_master_leaves(cluster: Cluster) -> None:
    cluster.master = "spatium-redis-1"
    cluster.down = {"10.42.2.10"}
    with pytest.raises(redis_handoff.RedisHandoffError) as err:
        _hand_off({"m1", "m2"})
    assert "could not be kept from being promoted" in str(err.value)
    assert "spatium-redis-2" in str(err.value)
    assert ("failover", "mymaster") not in cluster.calls
    assert cluster.priority["10.42.1.10"] == "100"


def test_an_unreachable_leaving_replica_does_not_refuse_when_the_master_stays(
    cluster: Cluster,
) -> None:
    cluster.down = {"10.42.2.10"}
    got = _hand_off({"m1", "m2"})
    assert got.outcome == "kept"
    assert got.deprioritised == ["spatium-redis-1"]


def test_a_master_that_is_no_redis_pod_is_a_refusal(cluster: Cluster) -> None:
    cluster.named = "10.9.9.9"
    with pytest.raises(redis_handoff.RedisHandoffError) as err:
        _hand_off({"m1", "m2"})
    assert "10.9.9.9" in str(err.value) and "none of the Redis pods" in str(err.value)
    assert cluster.calls == []


def test_no_master_at_all_is_a_refusal(cluster: Cluster) -> None:
    cluster.master = None
    with pytest.raises(redis_handoff.RedisHandoffError) as err:
        _hand_off({"m1", "m2"})
    assert "no Sentinel names a Redis master" in str(err.value)
