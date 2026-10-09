"""The Redis pods' init script takes each pod's role from Sentinel (#1442).

``charts/spatiumddi/files/redis-sentinel-render-config.sh`` is what the
``render-config`` init container of the Sentinel StatefulSet runs on every pod
start. It used to write a fixed topology: redis-0 the master, every other pod
``replicaof redis-0``, every sentinel monitoring redis-0. A master pod
re-created before Sentinel failed over then came back as a replica of redis-0
while redis-0 was still its replica, so no pod was master and Sentinel aborted
every failover ``no-good-slave`` for good.

These tests run the real script under ``sh``, with a fake ``redis-cli`` on PATH
playing the peer sentinels, and read what it wrote into the data directory.

Lives in ``appliance/tests`` because that is the hermetic pytest job that runs
on every PR (the Charts job renders the template but has no pytest).

HOW TO RUN (from the repo root):
    python3 -m pytest appliance/tests/test_redis_sentinel_render_config.py -v
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "charts" / "spatiumddi" / "files" / "redis-sentinel-render-config.sh"
TEMPLATE = ROOT / "charts" / "spatiumddi" / "templates" / "redis-sentinel.yaml"

STS = "spatium-control-spatiumddi-redis"
HEADLESS = "spatium-control-spatiumddi-redis-headless"


def fqdn(i: int) -> str:
    return f"{STS}-{i}.{HEADLESS}.spatium.svc.cluster.local"


# Plays every peer sentinel. $FAKE/answers/<host> holds "<master> <epoch> [<first
# call that answers>]"; a host with no file does not resolve. Every call is logged.
FAKE_REDIS_CLI = r"""#!/bin/sh
echo "$*" >> "$FAKE/calls"
n=$(( $(cat "$FAKE/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$FAKE/count"
host="$2"; sub="$6"
if [ ! -f "$FAKE/answers/$host" ]; then
    echo "Could not connect to Redis at $host:26379: Name does not resolve" >&2
    exit 1
fi
read -r master epoch from < "$FAKE/answers/$host"
if [ -n "${from:-}" ] && [ "$n" -lt "$from" ]; then
    echo "Could not connect to Redis at $host:26379: Try again" >&2
    exit 1
fi
case "$sub" in
    get-master-addr-by-name) printf '%s\n6379\n' "$master" ;;
    MASTER) printf 'name\nmymaster\nip\n%s\nport\n6379\nflags\nmaster\nconfig-epoch\n%s\nquorum\n2\n' "$master" "$epoch" ;;
esac
"""


@pytest.fixture
def pod(tmp_path):
    """Run the script as one pod of a three-pod set; returns a runner."""
    tmpl, data, fake, fakebin = (tmp_path / d for d in ("tmpl", "data", "fake", "bin"))
    for d in (tmpl, data, fake / "answers", fakebin):
        d.mkdir(parents=True)
    (tmpl / "redis.conf.tmpl").write_text(
        "appendonly yes\nreplica-announce-ip __POD_FQDN__\nrequirepass __PASSWORD__\n")
    (tmpl / "sentinel.conf.tmpl").write_text(
        "sentinel resolve-hostnames yes\nsentinel announce-ip __POD_FQDN__\n"
        "sentinel monitor mymaster __MASTER_HOST__ 6379 2\n"
        "sentinel auth-pass mymaster __PASSWORD__\n")
    (tmpl / "replicas").write_text("3")
    cli = fakebin / "redis-cli"
    cli.write_text(FAKE_REDIS_CLI)
    cli.chmod(0o755)
    # the retry loop's pause, made instant
    sleep = fakebin / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)

    def answer(peer: int, master: int | str, epoch: int = 3, from_call: int | None = None):
        host = fqdn(master) if isinstance(master, int) else master
        line = f"{host} {epoch}" + (f" {from_call}" if from_call else "")
        (fake / "answers" / fqdn(peer)).write_text(line + "\n")

    def run(ordinal: int, wait: str = "0", password: str = "", replicas: str = "3"):
        (tmpl / "replicas").write_text(replicas)
        env = {
            "PATH": f"{fakebin}{os.pathsep}{os.environ['PATH']}",
            "HOSTNAME": f"{STS}-{ordinal}", "REDIS_STS": STS, "REDIS_HEADLESS": HEADLESS,
            "REDIS_NAMESPACE": "spatium", "REDIS_MASTER_SET": "mymaster",
            "REDIS_PASSWORD": password, "REDIS_DISCOVERY_SECONDS": wait,
            "TMPL_DIR": str(tmpl), "DATA_DIR": str(data), "FAKE": str(fake),
        }
        r = subprocess.run(["sh", str(SCRIPT)], env=env, capture_output=True, text=True,
                           timeout=60)
        assert r.returncode == 0, r.stderr
        calls = (fake / "calls").read_text().splitlines() if (fake / "calls").exists() else []
        return {"redis": (data / "redis.conf").read_text(),
                "sentinel": (data / "sentinel.conf").read_text(),
                "log": r.stdout, "calls": calls}

    run.answer = answer
    return run


def replicaof(conf: str) -> str | None:
    lines = [ln for ln in conf.splitlines() if ln.startswith("replicaof ")]
    assert len(lines) <= 1, conf
    return lines[0].split()[1] if lines else None


def monitored(conf: str) -> str:
    return next(ln.split()[3] for ln in conf.splitlines() if ln.startswith("sentinel monitor"))


def test_the_master_pod_that_comes_back_before_a_failover_starts_as_master(pod):
    # #1442 itself: redis-1 held the master and its node rebooted before
    # Sentinel failed over. The peers still name redis-1, so it must come back
    # as master, not as a replica of redis-0 (which is ITS replica).
    pod.answer(0, master=1, epoch=4)
    pod.answer(2, master=1, epoch=4)
    out = pod(1)
    assert replicaof(out["redis"]) is None
    assert monitored(out["sentinel"]) == fqdn(1)
    assert "starts as master (the sentinels name it)" in out["log"]


def test_a_pod_follows_the_master_the_sentinels_name(pod):
    pod.answer(0, master=2, epoch=5)
    pod.answer(2, master=2, epoch=5)
    out = pod(1)
    assert replicaof(out["redis"]) == fqdn(2)
    assert monitored(out["sentinel"]) == fqdn(2)
    assert f"starts as a replica of {fqdn(2)}" in out["log"]


def test_redis_0_follows_a_promoted_master_instead_of_claiming_it(pod):
    # The fixed rule made redis-0 a master on every start, whoever the
    # sentinels had promoted: a second master until Sentinel demoted it.
    pod.answer(1, master=1, epoch=2)
    pod.answer(2, master=1, epoch=2)
    out = pod(0)
    assert replicaof(out["redis"]) == fqdn(1)
    assert monitored(out["sentinel"]) == fqdn(1)


def test_the_highest_config_epoch_wins_over_a_peer_that_just_restarted(pod):
    # redis-0's sentinel restarted a moment ago from the cold-start rule and
    # still says redis-0 (epoch 0); redis-2's saw the failover to redis-1.
    pod.answer(0, master=0, epoch=0)
    pod.answer(2, master=1, epoch=7)
    out = pod(1)
    assert replicaof(out["redis"]) is None
    assert monitored(out["sentinel"]) == fqdn(1)


def test_no_sentinel_answering_falls_back_to_the_ordinal_rule(pod):
    out = pod(1)
    assert replicaof(out["redis"]) == fqdn(0)
    assert monitored(out["sentinel"]) == fqdn(0)
    assert "no sentinel answered within 0s, so the ordinal rule" in out["log"]
    out = pod(0)
    assert replicaof(out["redis"]) is None
    assert monitored(out["sentinel"]) == fqdn(0)


def test_a_lookup_that_fails_at_first_is_retried_not_taken_for_a_cold_start(pod):
    # The node's return is when CoreDNS moves: a first lookup that fails must
    # not send the master's pod back to the ordinal rule (the cycle again).
    pod.answer(0, master=1, epoch=4, from_call=5)
    pod.answer(2, master=1, epoch=4, from_call=5)
    out = pod(1, wait="30")
    assert replicaof(out["redis"]) is None
    assert monitored(out["sentinel"]) == fqdn(1)
    assert len(out["calls"]) >= 5


def test_a_single_replica_asks_nobody(pod):
    out = pod(0, replicas="1")
    assert out["calls"] == []
    assert replicaof(out["redis"]) is None
    assert monitored(out["sentinel"]) == fqdn(0)
    assert "starts as master (a single replica)" in out["log"]


def test_an_answer_that_is_not_an_address_is_ignored(pod):
    pod.answer(0, master="ERR No such master with that name", epoch=9)
    pod.answer(2, master=2, epoch=1)
    out = pod(1)
    assert replicaof(out["redis"]) == fqdn(2)


def test_the_password_and_identity_still_render(pod):
    pod.answer(0, master=0, epoch=1)
    out = pod(1, password="a/b&c\\d")
    assert "requirepass a/b&c\\d" in out["redis"]
    assert "sentinel auth-pass mymaster a/b&c\\d" in out["sentinel"]
    assert f"replica-announce-ip {fqdn(1)}" in out["redis"]
    assert f"sentinel announce-ip {fqdn(1)}" in out["sentinel"]


def test_the_chart_runs_this_script_and_renders_no_fixed_topology():
    text = TEMPLATE.read_text()
    assert '.Files.Get "files/redis-sentinel-render-config.sh"' in text
    assert "sentinel monitor {{ $master }} __MASTER_HOST__ 6379 {{ $quorum }}" in text
    assert 'echo "replicaof' not in text
    assert "replicas: {{ $replicas | quote }}" in text
    assert SCRIPT.read_text().startswith("#!/bin/sh\n")
