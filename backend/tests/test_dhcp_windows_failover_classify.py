"""#1110 — ``classify_serving``: how a group's Windows members serve a scope.

Pure: no DB, no WinRM. The write-through feeds it a live probe and the
views feed it stored observations, so the verdict a refusal is based on and
the verdict a badge shows come from this one function.

The two outcomes it exists to tell apart look identical to scope
enumeration: two servers holding one scope inside a failover relationship
(safe — the relationship divides the free pool), and two servers holding
one scope with no relationship (two DHCP servers handing out the same
addresses). A third, the pre-2012 split scope, is also two holders and no
relationship, and is safe because their ranges do not overlap.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.services.dhcp.windows_failover import (
    Holder,
    Member,
    Verdict,
    classify_serving,
    effective_ranges,
    scope_config_hash,
)

A = Member(server_id=uuid.UUID(int=1), name="dhcp1", host="dhcp1.corp.example")
B = Member(server_id=uuid.UUID(int=2), name="dhcp2", host="10.0.0.2")
C = Member(server_id=uuid.UUID(int=3), name="dhcp3", host="dhcp3.corp.example")
MEMBERS = [A, B, C]

FULL = effective_ranges("10.1.2.10", "10.1.2.200", [])
LOW_HALF = effective_ranges("10.1.2.10", "10.1.2.200", [("10.1.2.101", "10.1.2.200")])
HIGH_HALF = effective_ranges("10.1.2.10", "10.1.2.200", [("10.1.2.10", "10.1.2.100")])


def rel(name: str = "dhcp1-dhcp2", partner: str = "dhcp2", **kw: Any) -> dict[str, Any]:
    out = {
        "name": name,
        "partner_server": partner,
        "mode": "LoadBalance",
        "load_balance_percent": 50,
        "scope_ids": ["10.1.2.0"],
    }
    out.update(kw)
    return out


def holder(member: Member, relationship: dict | None = None, **kw: Any) -> Holder:
    defaults: dict[str, Any] = {
        "is_active": True,
        "failover_known": True,
        "ranges": FULL,
        "config_hash": "h",
    }
    defaults.update(kw)
    return Holder(member=member, relationship=relationship, **defaults)


def test_no_holder() -> None:
    s = classify_serving([], MEMBERS)
    assert s.verdict is Verdict.NOT_ON_WINDOWS
    assert s.safe


def test_one_holder_outside_any_relationship() -> None:
    s = classify_serving([holder(A)], MEMBERS)
    assert s.verdict is Verdict.SINGLE
    assert s.safe
    assert "dhcp1 only" in s.detail


def test_a_failover_pair_is_one_coordinated_unit() -> None:
    s = classify_serving(
        [holder(A, rel(partner="dhcp2.corp.example")), holder(B, rel(partner="dhcp1"))],
        MEMBERS,
    )
    assert s.verdict is Verdict.FAILOVER
    assert s.safe
    assert len(s.units) == 1 and len(s.units[0]) == 2
    assert s.relationship and s.relationship["name"] == "dhcp1-dhcp2"
    assert s.drift is False
    # The operator-facing sentence says why both partners are written.
    assert "not configuration" in s.detail


def test_pairing_does_not_need_the_partner_spelled_like_our_host() -> None:
    """``PartnerServer`` is whatever the relationship was created with; the
    shared relationship NAME is the evidence, so an FQDN-vs-IP mismatch
    between Windows' spelling and ours must not split a real pair."""
    # dhcp1 knows its partner by an address SpatiumDDI has never heard of;
    # dhcp2 spells dhcp1 in upper case with a trailing dot.
    s = classify_serving(
        [holder(A, rel(partner="192.0.2.77")), holder(B, rel(partner="DHCP1.corp.example."))],
        MEMBERS,
    )
    assert s.verdict is Verdict.FAILOVER


def test_failover_partners_with_different_config_hashes_have_drifted() -> None:
    s = classify_serving(
        [holder(A, rel(), config_hash="aaa"), holder(B, rel(), config_hash="bbb")], MEMBERS
    )
    assert s.verdict is Verdict.FAILOVER
    assert s.drift is True
    assert "Invoke-DhcpServerv4FailoverReplication" in s.detail


def test_two_holders_no_relationship_overlapping_ranges_is_the_outage() -> None:
    s = classify_serving([holder(A), holder(B)], MEMBERS)
    assert s.verdict is Verdict.UNCOORDINATED
    assert not s.safe
    assert "same address" in s.detail


def test_two_holders_in_different_relationships_are_not_a_pair() -> None:
    s = classify_serving(
        [holder(A, rel(name="a-x", partner="x")), holder(B, rel(name="b-y", partner="y"))],
        MEMBERS,
    )
    assert s.verdict is Verdict.UNCOORDINATED


def test_same_relationship_name_pointing_at_a_third_member_is_not_a_pair() -> None:
    """Two different pairs in one group can share a relationship name
    ('failover' is a popular one). A side that positively names a THIRD
    member as its partner is not paired with the holder next to it."""
    s = classify_serving(
        [holder(A, rel(name="failover", partner="dhcp3")), holder(B, rel(name="failover"))],
        MEMBERS,
    )
    assert s.verdict is Verdict.UNCOORDINATED


def test_split_scope_disjoint_ranges_is_safe_but_named() -> None:
    s = classify_serving([holder(A, ranges=LOW_HALF), holder(B, ranges=HIGH_HALF)], MEMBERS)
    assert s.verdict is Verdict.SPLIT_SCOPE
    assert s.safe
    assert "own server group" in s.detail


def test_split_scope_needs_known_ranges_to_be_proven() -> None:
    s = classify_serving([holder(A, ranges=LOW_HALF), holder(B, ranges=None)], MEMBERS)
    assert s.verdict is Verdict.UNCOORDINATED


def test_unreadable_failover_makes_multi_holder_unknown_not_uncovered() -> None:
    s = classify_serving(
        [
            holder(A, failover_known=False, failover_error="Access is denied."),
            holder(B, rel()),
        ],
        MEMBERS,
    )
    assert s.verdict is Verdict.UNKNOWN
    assert not s.safe
    assert "Access is denied." in s.detail


def test_unreadable_failover_does_not_matter_for_a_single_holder() -> None:
    s = classify_serving([holder(A, failover_known=False)], MEMBERS)
    assert s.verdict is Verdict.SINGLE


def test_one_holder_whose_partner_is_not_in_the_group() -> None:
    s = classify_serving([holder(A, rel(partner="dhcp9.elsewhere"))], MEMBERS)
    assert s.verdict is Verdict.FAILOVER_ONE_SIDED
    assert "not a member of this group" in s.detail
    assert "reach dhcp1 only" in s.detail


def test_one_holder_whose_partner_is_in_the_group_but_lacks_the_scope() -> None:
    s = classify_serving([holder(A, rel(partner="dhcp2"))], MEMBERS)
    assert s.verdict is Verdict.FAILOVER_ONE_SIDED
    assert "dhcp2 is in this group but does not report the scope" in s.detail


def test_a_pair_plus_an_uncoordinated_third_holder() -> None:
    s = classify_serving([holder(A, rel()), holder(B, rel()), holder(C)], MEMBERS)
    assert s.verdict is Verdict.UNCOORDINATED
    assert sorted(len(u) for u in s.units) == [1, 2]


def test_a_pair_plus_a_disjoint_third_holder_is_a_split() -> None:
    s = classify_serving(
        [
            holder(A, rel(), ranges=LOW_HALF),
            holder(B, rel(), ranges=LOW_HALF),
            holder(C, ranges=HIGH_HALF),
        ],
        MEMBERS,
    )
    assert s.verdict is Verdict.SPLIT_SCOPE


def test_three_holders_claiming_one_relationship_are_not_one_unit() -> None:
    s = classify_serving([holder(A, rel()), holder(B, rel()), holder(C, rel())], MEMBERS)
    assert s.verdict is Verdict.UNCOORDINATED


# ── building blocks ───────────────────────────────────────────────────


def test_effective_ranges_subtracts_exclusions() -> None:
    import ipaddress

    def ip(s: str) -> int:
        return int(ipaddress.ip_address(s))

    got = effective_ranges(
        "10.0.0.10", "10.0.0.100", [("10.0.0.20", "10.0.0.29"), ("10.0.0.90", "10.0.0.120")]
    )
    assert got == ((ip("10.0.0.10"), ip("10.0.0.19")), (ip("10.0.0.30"), ip("10.0.0.89")))
    assert effective_ranges(None, "10.0.0.1", []) is None
    assert effective_ranges("10.0.0.9", "10.0.0.1", []) is None


def _wire(**kw: Any) -> dict[str, Any]:
    base = {
        "subnet_cidr": "10.1.2.0/24",
        "name": "office",
        "description": "d",
        "lease_time": 86400,
        "is_active": True,
        "options": {"routers": ["10.1.2.1"], "dns-servers": ["10.0.0.53", "10.0.0.54"]},
        "pools": [
            {"start_ip": "10.1.2.10", "end_ip": "10.1.2.200", "pool_type": "dynamic"},
            {"start_ip": "10.1.2.50", "end_ip": "10.1.2.60", "pool_type": "excluded"},
        ],
        "statics": [
            {"ip_address": "10.1.2.5", "mac_address": "aa:bb:cc:00:00:01", "hostname": "p"}
        ],
    }
    base.update(kw)
    return base


def test_config_hash_ignores_cosmetics_but_sees_what_clients_get() -> None:
    base = scope_config_hash(_wire())
    # Names, descriptions, MAC spelling and list order are not drift.
    assert scope_config_hash(_wire(name="other", description="x")) == base
    assert (
        scope_config_hash(
            _wire(
                statics=[
                    {"ip_address": "10.1.2.5", "mac_address": "AA-BB-CC-00-00-01", "hostname": "q"}
                ]
            )
        )
        == base
    )
    # A missing reservation, a moved exclusion, reordered DNS servers, a
    # different lease time or state are all things a client would notice.
    assert scope_config_hash(_wire(statics=[])) != base
    assert (
        scope_config_hash(
            _wire(
                pools=[
                    {"start_ip": "10.1.2.10", "end_ip": "10.1.2.200", "pool_type": "dynamic"},
                    {"start_ip": "10.1.2.50", "end_ip": "10.1.2.61", "pool_type": "excluded"},
                ]
            )
        )
        != base
    )
    assert (
        scope_config_hash(
            _wire(options={"routers": ["10.1.2.1"], "dns-servers": ["10.0.0.54", "10.0.0.53"]})
        )
        != base
    )
    assert scope_config_hash(_wire(lease_time=3600)) != base
    assert scope_config_hash(_wire(is_active=False)) != base
