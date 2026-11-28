"""Incremental subnet apply (#3790): planner, command order, fallbacks."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from spatium_dhcp_agent import incremental
from spatium_dhcp_agent import sync as sync_mod
from spatium_dhcp_agent.cache import ensure_layout
from spatium_dhcp_agent.config import AgentConfig
from spatium_dhcp_agent.config_apply import ApplyStatus
from spatium_dhcp_agent.kea_ctrl import KeaCtrlError
from spatium_dhcp_agent.render_kea import _stable_subnet_id
from spatium_dhcp_agent.sync import SyncLoop

HOST_A = {"hw-address": "aa:bb:cc:dd:ee:01", "ip-address": "192.0.2.5"}
HOST_B = {"hw-address": "aa:bb:cc:dd:ee:02", "ip-address": "192.0.2.6"}


def sn(sid: int, pool: str = "a", hosts: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    s: dict[str, Any] = {"id": sid, "subnet": f"10.{sid}.0.0/24", "pools": [{"pool": pool}]}
    if hosts:
        s["reservations"] = hosts
    return s


def doc(*subnets: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {"valid-lifetime": 3600, "subnet4": list(subnets), **extra}


def names(plan: incremental.Plan) -> list[str]:
    return [c for c, _ in plan.commands]


# ── planner ─────────────────────────────────────────────────────────────────


def test_non_subnet_change_is_not_incremental() -> None:
    assert incremental.plan_subnet_diff(doc(sn(1)), doc(sn(1), **{"valid-lifetime": 7})) is None
    hooks = {"hooks-libraries": [{"library": "x"}]}
    assert incremental.plan_subnet_diff(doc(sn(1)), doc(sn(1), **hooks)) is None


def test_identical_docs_give_empty_plan() -> None:
    plan = incremental.plan_subnet_diff(doc(sn(1)), doc(sn(1)))
    assert plan is not None and plan.empty


def test_command_order_and_bodies() -> None:
    old = doc(sn(1), sn(2, hosts=[HOST_A]), sn(3, hosts=[HOST_A]), sn(4, hosts=[HOST_A]))
    new = doc(
        sn(2, hosts=[HOST_B]),  # reservation swap only
        sn(3, pool="b", hosts=[HOST_A]),  # body change
        sn(4, hosts=[HOST_A]),
        sn(5, hosts=[HOST_B]),  # new
    )
    plan = incremental.plan_subnet_diff(old, new)
    assert plan is not None
    assert names(plan) == [
        "subnet4-del",
        "reservation-del",
        "subnet4-update",
        "subnet4-add",
        "reservation-add",
        "reservation-add",
    ]
    cmds = dict((c, a) for c, a in plan.commands if c != "reservation-add")
    assert cmds["subnet4-del"] == {"id": 1}
    assert cmds["reservation-del"] == {
        "subnet-id": 2,
        "identifier-type": "hw-address",
        "identifier": HOST_A["hw-address"],
        "operation-target": "memory",
    }
    # Kea refuses reservations inside subnet4-add / subnet4-update bodies.
    assert "reservations" not in cmds["subnet4-update"]["subnet4"][0]
    assert "reservations" not in cmds["subnet4-add"]["subnet4"][0]
    adds = [a for c, a in plan.commands if c == "reservation-add"]
    assert {a["reservation"]["subnet-id"] for a in adds} == {2, 5}
    assert all(a["operation-target"] == "memory" for a in adds)
    assert plan.expected_ids == [2, 3, 4, 5]


def test_changed_reservation_is_replaced() -> None:
    changed = {**HOST_A, "ip-address": "192.0.2.99"}
    plan = incremental.plan_subnet_diff(doc(sn(1, hosts=[HOST_A])), doc(sn(1, hosts=[changed])))
    assert plan is not None
    assert names(plan) == ["reservation-del", "reservation-add"]


def test_unkeyable_reservation_raises() -> None:
    with pytest.raises(incremental.PlanError):
        incremental.plan_subnet_diff(doc(sn(1)), doc(sn(1, hosts=[{"ip-address": "10.1.0.5"}])))


# ── ordering rule ───────────────────────────────────────────────────────────


def perm(role: str, partner: list[int] | None) -> dict[str, Any]:
    return {"ok": True, "role": role, "partner_applied_subnet_ids": partner}


def ids(subnets: list[dict[str, Any]]) -> list[int]:
    return sorted(s["id"] for s in subnets)


def test_standby_adds_first_and_keeps_deleted_until_primary_drops() -> None:
    known = [sn(1), sn(2)]
    # add 3: standby takes it at once
    assert ids(incremental.apply_ordering([sn(1), sn(2), sn(3)], known, perm("standby", [1, 2]))) == [1, 2, 3]
    # delete 2: the primary still has it, so the standby keeps it
    assert ids(incremental.apply_ordering([sn(1)], known, perm("standby", [1, 2]))) == [1, 2]
    # primary dropped it: the standby follows
    assert ids(incremental.apply_ordering([sn(1)], known, perm("standby", [1]))) == [1]


def test_primary_waits_for_standby_to_add() -> None:
    assert ids(incremental.apply_ordering([sn(1), sn(3)], [sn(1)], perm("primary", [1]))) == [1]
    assert ids(incremental.apply_ordering([sn(1), sn(3)], [sn(1)], perm("primary", [1, 3]))) == [1, 3]
    # a delete reaches the primary at once
    assert ids(incremental.apply_ordering([sn(1)], [sn(1), sn(3)], perm("primary", [1, 3]))) == [1]


@pytest.mark.parametrize(
    "inc",
    [None, {}, {"ok": False, "role": "primary", "partner_applied_subnet_ids": [1]},
     perm("primary", None), perm("standalone", [1])],
)
def test_no_ordering_without_permission_or_partner_set(inc: dict[str, Any] | None) -> None:
    assert ids(incremental.apply_ordering([sn(1), sn(2)], [sn(9)], inc)) == [1, 2]


# ── hooks in the render / capability ────────────────────────────────────────


def test_hook_libraries_follow_the_image(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    sub, host = tmp_path / "libdhcp_subnet_cmds.so", tmp_path / "libdhcp_host_cmds.so"
    monkeypatch.setattr(incremental, "SUBNET_CMDS_LIB", sub)
    monkeypatch.setattr(incremental, "HOST_CMDS_LIB", host)
    assert incremental.hook_libraries() == []
    assert not incremental.hooks_installed()
    from spatium_dhcp_agent.ha_tls import current_capabilities

    assert incremental.CAPABILITY not in current_capabilities()
    sub.touch()
    host.touch()
    assert [h["library"] for h in incremental.hook_libraries()] == [str(sub), str(host)]
    assert incremental.CAPABILITY in current_capabilities()


# ── sync integration ────────────────────────────────────────────────────────


class _FakeHeartbeat:
    def __init__(self) -> None:
        self.daemon_status: dict[str, Any] = {}
        self.pending_acks: list[dict[str, Any]] = []
        self.config_apply = ApplyStatus()
        self.applied_subnet_ids: list[int] | None = None


def scope(cidr: str, pool: tuple[str, str] = ("10.0.0.10", "10.0.0.20"), hw: str | None = None):
    s: dict[str, Any] = {
        "subnet_cidr": cidr,
        "lease_time": 3600,
        "address_family": "ipv4",
        "pools": [{"start_ip": pool[0], "end_ip": pool[1], "pool_type": "dynamic"}],
        "statics": [],
    }
    if hw:
        s["statics"] = [{"ip_address": cidr.replace(".0/24", ".5"), "mac_address": hw}]
    return s


def bundle(*scopes: dict[str, Any], incremental_: dict[str, Any] | None = None, **extra: Any):
    b: dict[str, Any] = {"etag": "x", "scopes": list(scopes), **extra}
    if incremental_ is not None:
        b["incremental"] = incremental_
    return b


class _Kea:
    """Fake daemon: subnets in memory, a command log, scripted failures."""

    def __init__(self) -> None:
        self.mem: set[int] = set()
        self.log: list[str] = []
        self.reloads = 0
        self.fail_on: str | None = None
        self.hooks = True
        self.disk_at_command: list[dict[str, Any]] = []
        self.cfg: AgentConfig | None = None

    def reload(self, sock: Path) -> None:
        assert self.cfg is not None
        if sock != self.cfg.kea_control_socket:
            return  # kea-dhcp6: not what this file is about
        self.reloads += 1
        d = json.loads(self.cfg.kea_config_path.read_text())["Dhcp4"]
        self.mem = {s["id"] for s in d["subnet4"]}

    def send(self, _sock: Path, command: str, args: Any = None, *, accept_results=(0,), **_: Any):
        if command == "list-commands":
            cmds = list(incremental.REQUIRED_COMMANDS) if self.hooks else ["list-commands"]
            return {"result": 0, "arguments": cmds}
        if command == "subnet4-list":
            return {"result": 0, "arguments": {"subnets": [{"id": i} for i in sorted(self.mem)]}}
        self.log.append(command)
        assert self.cfg is not None
        self.disk_at_command.append(json.loads(self.cfg.kea_config_path.read_text())["Dhcp4"])
        if command == self.fail_on:
            raise KeaCtrlError(f"{command} failed")
        if command == "subnet4-del":
            self.mem.discard(args["id"])
        elif command == "subnet4-add":
            self.mem.add(args["subnet4"][0]["id"])
        return {"result": 0}


@pytest.fixture
def env(agent_cfg: AgentConfig, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    kea = _Kea()
    kea.cfg = agent_cfg
    sub, host = tmp_path / "libdhcp_subnet_cmds.so", tmp_path / "libdhcp_host_cmds.so"
    sub.touch()
    host.touch()
    monkeypatch.setattr(incremental, "SUBNET_CMDS_LIB", sub)
    monkeypatch.setattr(incremental, "HOST_CMDS_LIB", host)
    monkeypatch.setattr(sync_mod, "config_check", lambda d, p: None)
    monkeypatch.setattr(sync_mod, "config_reload", kea.reload)
    monkeypatch.setattr(sync_mod, "config_hash_get", lambda s: f"h{len(kea.log)}{kea.reloads}")
    monkeypatch.setattr(sync_mod, "send_command", kea.send)
    ensure_layout(agent_cfg.state_dir)
    loop = SyncLoop(agent_cfg, token_ref=[""], heartbeat=_FakeHeartbeat())
    return loop, kea


OK = {"ok": True, "role": "standalone", "partner_applied_subnet_ids": None}


def apply(loop: SyncLoop, b: dict[str, Any], *, inc: bool = True) -> None:
    loop._apply_bundle(b, reload_kea=True, allow_incremental=inc)


def on_disk(loop: SyncLoop) -> list[int]:
    d = json.loads(loop.cfg.kea_config_path.read_text())["Dhcp4"]
    return sorted(s["id"] for s in d["subnet4"])


A, B, C = "10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24"
ID = _stable_subnet_id


def test_first_apply_reloads_and_reports_ids(env) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A), incremental_=OK))
    assert kea.reloads == 1
    assert loop.heartbeat.applied_subnet_ids == [ID(A)]
    # the hooks are in the document Kea is told to load
    d = json.loads(loop.cfg.kea_config_path.read_text())["Dhcp4"]
    assert any("subnet_cmds" in h["library"] for h in d["hooks-libraries"])


def test_scope_create_delete_uses_commands_not_reload(env) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A), scope(B), incremental_=OK))
    kea.log.clear()
    apply(loop, bundle(scope(A), scope(C), incremental_=OK))
    assert kea.reloads == 1  # only the first apply
    assert kea.log == ["subnet4-del", "subnet4-add"]
    assert kea.mem == {ID(A), ID(C)}
    assert on_disk(loop) == sorted([ID(A), ID(C)])
    assert loop.heartbeat.applied_subnet_ids == sorted([ID(A), ID(C)])
    # the file was already written when the first command ran
    assert all(sorted(s["id"] for s in d["subnet4"]) == on_disk(loop) for d in kea.disk_at_command)


def test_reservation_only_change(env) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A, hw="aa:bb:cc:dd:ee:01"), incremental_=OK))
    kea.log.clear()
    apply(loop, bundle(scope(A, hw="aa:bb:cc:dd:ee:02"), incremental_=OK))
    assert kea.log == ["reservation-del", "reservation-add"]
    assert kea.reloads == 1


def test_non_subnet_change_reloads(env) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A), incremental_=OK))
    apply(loop, bundle(scope(A), incremental_=OK, global_options={"lease_time": 99}))
    assert kea.reloads == 2
    assert kea.log == []


def test_without_permission_reloads(env) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A)))
    apply(loop, bundle(scope(A), scope(B)))
    assert kea.reloads == 2 and kea.log == []


def test_not_allowed_for_revert_path_reloads(env) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A), incremental_=OK))
    apply(loop, bundle(scope(A), scope(B), incremental_=OK), inc=False)
    assert kea.reloads == 2 and kea.log == []


@pytest.mark.parametrize("failing", ["subnet4-add", "subnet4-del"])
def test_command_failure_falls_back_to_reload(env, failing: str) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A), scope(B), incremental_=OK))
    kea.fail_on = failing
    apply(loop, bundle(scope(A), scope(C), incremental_=OK))
    assert kea.reloads == 2
    # the reload read the full document the apply wrote: nothing half-applied
    assert kea.mem == {ID(A), ID(C)}
    assert on_disk(loop) == sorted([ID(A), ID(C)])
    assert loop._last_reload_results["dhcp4"] == "ok"


def test_hooks_not_loaded_in_daemon_falls_back(env) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A), incremental_=OK))
    kea.hooks = False
    apply(loop, bundle(scope(A), scope(B), incremental_=OK))
    assert kea.reloads == 2 and kea.log == []


def test_hook_files_absent_never_goes_incremental(env, monkeypatch: pytest.MonkeyPatch) -> None:
    loop, kea = env
    monkeypatch.setattr(incremental, "hooks_installed", lambda: False)
    monkeypatch.setattr(incremental, "hook_libraries", lambda: [])
    apply(loop, bundle(scope(A), incremental_=OK))
    apply(loop, bundle(scope(A), scope(B), incremental_=OK))
    assert kea.reloads == 2 and kea.log == []
    d = json.loads(loop.cfg.kea_config_path.read_text())["Dhcp4"]
    assert not any("subnet_cmds" in h["library"] for h in d["hooks-libraries"])
    assert loop.heartbeat.applied_subnet_ids is None


def test_daemon_drift_detected_by_subnet_list(env) -> None:
    loop, kea = env
    apply(loop, bundle(scope(A), incremental_=OK))
    kea.mem = set()  # daemon restarted into something else
    apply(loop, bundle(scope(A), scope(B), incremental_=OK))
    assert kea.reloads == 2 and kea.log == []


def test_ha_standby_then_primary_ordering(env) -> None:
    loop, kea = env
    # primary: desired adds B but the standby only has A
    apply(loop, bundle(scope(A), incremental_=perm("primary", [ID(A)])))
    apply(loop, bundle(scope(A), scope(B), incremental_=perm("primary", [ID(A)])))
    assert on_disk(loop) == [ID(A)]
    assert kea.log == []
    # standby reported B: the primary now adds it, without a reload
    apply(loop, bundle(scope(A), scope(B), incremental_=perm("primary", [ID(A), ID(B)])))
    assert on_disk(loop) == sorted([ID(A), ID(B)])
    assert kea.log == ["subnet4-add"]
    assert kea.reloads == 1
