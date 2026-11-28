"""Incremental subnet apply for kea-dhcp4 (#3790).

A ``config-reload`` re-initialises Kea's HA hook, which on a hot-standby pair
means seconds with no service on a primary and, if the two members disagree
about their subnets, lease-update rejections that end with both TERMINATED.
When ONLY ``subnet4`` entries changed the agent instead edits the running
daemon through the ``subnet_cmds`` and ``host_cmds`` hooks, which touches no
HA state, and writes the same document to disk so a restart loads what the
daemon is running.

This module is pure planning + a command runner; ``sync.py`` decides when to
use it and falls back to a full reload on any failure.

Facts measured on Kea 3.0.3 that shape the plan:

* ``subnet4-add`` / ``subnet4-update`` REFUSE a subnet body that carries
  ``reservations``; hosts go through ``reservation-add`` / ``reservation-del``
  (``operation-target: memory``).
* ``subnet4-update`` keeps the subnet's existing hosts; ``subnet4-del`` drops
  them.
* ``subnet4-del`` / ``reservation-del`` of something absent answer result 3,
  which is already the wanted state. Any other refusal is a failure.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import structlog

log = structlog.get_logger(__name__)

HOOKS_DIR = Path("/usr/lib/kea/hooks")
SUBNET_CMDS_LIB = HOOKS_DIR / "libdhcp_subnet_cmds.so"
HOST_CMDS_LIB = HOOKS_DIR / "libdhcp_host_cmds.so"
# Advertised to the control plane only when both hook libraries are present.
CAPABILITY = "kea-incremental-subnets"

REQUIRED_COMMANDS = (
    "subnet4-add",
    "subnet4-del",
    "subnet4-update",
    "subnet4-list",
    "reservation-add",
    "reservation-del",
)
# Kea answers these for "already gone".
_ABSENT_OK = (0, 3)
_IDENTIFIERS = ("hw-address", "client-id")


def hooks_installed() -> bool:
    return SUBNET_CMDS_LIB.exists() and HOST_CMDS_LIB.exists()


def hook_libraries() -> list[dict[str, str]]:
    """The ``hooks-libraries`` entries to add, for the ones the image has."""
    return [{"library": str(p)} for p in (SUBNET_CMDS_LIB, HOST_CMDS_LIB) if p.exists()]


class PlanError(Exception):
    """The diff cannot be expressed as incremental commands."""


def subnet_ids(doc: dict[str, Any]) -> list[int]:
    return sorted(int(s["id"]) for s in doc.get("subnet4") or [])


def apply_ordering(
    desired: list[dict[str, Any]],
    known: list[dict[str, Any]],
    incremental: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    """The subnets this member may carry given its partner's applied set (#3790).

    A member only ever carries subnets its partner also has, or the partner
    rejects its lease updates (after ``max-rejected-lease-updates`` both
    members go to TERMINATED).

    * standby: desired + whatever the primary still has (kept from ``known``,
      the subnets this member already runs), so a delete reaches the primary
      first.
    * primary: desired limited to what the standby has, so an add reaches the
      standby first.
    * standalone, an unknown partner set, or no permission: ``desired``.
    """
    if not incremental or not incremental.get("ok"):
        return desired
    partner = incremental.get("partner_applied_subnet_ids")
    role = incremental.get("role")
    if partner is None or role not in ("primary", "standby"):
        return desired
    partner_ids = {int(i) for i in partner}
    if role == "primary":
        return [s for s in desired if int(s["id"]) in partner_ids]
    wanted = {int(s["id"]) for s in desired}
    kept = [s for s in known if int(s["id"]) in partner_ids and int(s["id"]) not in wanted]
    return [*desired, *kept]


def _split(subnet: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    body = copy.deepcopy(subnet)
    hosts = body.pop("reservations", None) or []
    return body, hosts


def _host_key(host: dict[str, Any]) -> tuple[str, str]:
    for ident in _IDENTIFIERS:
        if host.get(ident):
            return ident, str(host[ident])
    raise PlanError("reservation without a hw-address or client-id")


def _hosts_by_key(hosts: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for h in hosts:
        key = _host_key(h)
        if key in out:
            raise PlanError(f"duplicate reservation {key}")
        out[key] = h
    return out


Command = tuple[str, dict[str, Any]]


@dataclass
class Plan:
    commands: list[Command] = field(default_factory=list)
    expected_ids: list[int] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.commands


def plan_subnet_diff(old: dict[str, Any], new: dict[str, Any]) -> Plan | None:
    """Commands that turn ``old`` into ``new``, or None when something other
    than ``subnet4`` differs (the caller then reloads).

    Order: subnet4-del, reservation-del, subnet4-update, subnet4-add,
    reservation-add. Raises :class:`PlanError` for a shape the commands cannot
    express; the caller reloads for that too.
    """
    strip = lambda d: {k: v for k, v in d.items() if k != "subnet4"}  # noqa: E731
    if strip(old) != strip(new):
        return None
    old_by = {int(s["id"]): s for s in old.get("subnet4") or []}
    new_by = {int(s["id"]): s for s in new.get("subnet4") or []}

    subnet_del: list[Command] = []
    res_del: list[Command] = []
    subnet_update: list[Command] = []
    subnet_add: list[Command] = []
    res_add: list[Command] = []

    def host_cmd(sid: int, host: dict[str, Any]) -> Command:
        return (
            "reservation-add",
            {
                "reservation": {"subnet-id": sid, **host},
                "operation-target": "memory",
            },
        )

    for sid in sorted(old_by.keys() - new_by.keys()):
        subnet_del.append(("subnet4-del", {"id": sid}))
    for sid in sorted(new_by.keys() - old_by.keys()):
        body, hosts = _split(new_by[sid])
        _hosts_by_key(hosts)
        subnet_add.append(("subnet4-add", {"subnet4": [body]}))
        res_add.extend(host_cmd(sid, h) for h in hosts)
    for sid in sorted(old_by.keys() & new_by.keys()):
        if old_by[sid] == new_by[sid]:
            continue
        old_body, old_hosts = _split(old_by[sid])
        new_body, new_hosts = _split(new_by[sid])
        if old_body != new_body:
            subnet_update.append(("subnet4-update", {"subnet4": [new_body]}))
        oh, nh = _hosts_by_key(old_hosts), _hosts_by_key(new_hosts)
        for key in sorted(oh.keys() - nh.keys()):
            res_del.append(_host_del(sid, key))
        for key in sorted(nh.keys()):
            if key not in oh:
                res_add.append(host_cmd(sid, nh[key]))
            elif oh[key] != nh[key]:
                # A changed reservation is replaced; reservation-add of an
                # existing host is refused.
                res_del.append(_host_del(sid, key))
                res_add.append(host_cmd(sid, nh[key]))

    return Plan(
        commands=[*subnet_del, *res_del, *subnet_update, *subnet_add, *res_add],
        expected_ids=sorted(new_by),
    )


def _host_del(sid: int, key: tuple[str, str]) -> Command:
    return (
        "reservation-del",
        {
            "subnet-id": sid,
            "identifier-type": key[0],
            "identifier": key[1],
            "operation-target": "memory",
        },
    )


# ``send(command, arguments, accept_results)`` returns the decoded response.
Send = Callable[[str, "dict[str, Any] | None", "tuple[int, ...]"], dict[str, Any]]


def live_subnet_ids(send: Send) -> list[int]:
    resp = send("subnet4-list", None, (0, 3))
    subnets = (resp.get("arguments") or {}).get("subnets") or []
    return sorted(int(s["id"]) for s in subnets)


def hooks_loaded(send: Send) -> bool:
    resp = send("list-commands", None, (0,))
    available = set(resp.get("arguments") or [])
    return all(c in available for c in REQUIRED_COMMANDS)


def execute(plan: Plan, send: Send) -> None:
    """Run ``plan`` and verify the daemon ends on the planned subnet ids.

    Raises on any refusal or on a mismatch; the caller reloads from the file.
    """
    for command, args in plan.commands:
        accept = _ABSENT_OK if command in ("subnet4-del", "reservation-del") else (0,)
        send(command, args, accept)
    live = live_subnet_ids(send)
    if live != plan.expected_ids:
        raise RuntimeError(f"subnet4-list {live} != expected {plan.expected_ids}")
