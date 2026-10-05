"""Whole-RRset record ops across all three agent drivers (issue #773).

A record op carries ONE record, but each driver turned that into a
whole-RRset write — so a name holding several values (round-robin A, a
backup MX, SPF beside a verification TXT) collapsed to whichever op landed
last. The fix has the control plane — the only place the complete desired
state is known — stamp the full set onto the op::

    "rrset": {"ttl": 3600, "members": [{"value": "10.20.7.22"},
                                       {"value": "10.20.7.21"}]}

``members`` is the desired set for that ``(name, type)`` AFTER the op, so a
delete ships the survivors and an empty list means "this RRset should not
exist". When ``rrset`` is absent entirely the drivers keep their previous
``rrset_action`` behaviour, because an op enqueued before the control plane
was upgraded is still sitting in the queue when the agent restarts.

The three drivers express the same semantics in three different
vocabularies, and each has a different way to get it wrong, so each is
pinned against its own wire:

* **BIND9** — RFC 2136. One ``dns.update.Update`` message carrying a
  delete-RRset followed by N adds. Asserted against the message's UPDATE
  section, not a rendered string.
* **Technitium** — one record per REST call, so an RRset write is N calls:
  member 0 with ``overwrite=true`` (which clears), the rest ``false``.
* **PowerDNS** — one ``changetype: REPLACE`` PATCH, and critically no zone
  GET: the merge the fallback needs is pointless once the desired set is
  known.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import dns.query
import dns.rdataclass
import dns.rdatatype
import pytest

from spatium_dns_agent.drivers import powerdns as powerdns_mod
from spatium_dns_agent.drivers.bind9 import Bind9Driver
from spatium_dns_agent.drivers.powerdns import PowerDNSDriver
from spatium_dns_agent.drivers.technitium import TechnitiumDriver

# The Technitium fakes already exist and are the established idiom for this
# driver (see the module they live in); re-declaring them here would let the
# two copies drift.
from tests.test_technitium_render import _install_fake_request, _seed_token

# ── BIND9: RFC 2136 wire interception ───────────────────────────────────────


class _FakeDnsResponse:
    """Stand-in for the ``dns.message.Message`` ``dns.query.tcp`` returns —
    the driver only ever calls ``.rcode()`` on it.

    Always NOERROR: these tests are about what the driver SENDS. How it
    reacts to a refusal is a separate concern and has its own path.
    """

    def rcode(self) -> int:
        return 0


def _send(
    monkeypatch: pytest.MonkeyPatch,
    driver: Bind9Driver,
    op: dict[str, Any],
) -> list[tuple[Any, str]]:
    """Apply ``op`` with the RFC 2136 wire intercepted.

    Returns the ``(update_message, destination)`` pairs the driver handed to
    ``dns.query.tcp`` — one entry per DNS message actually sent, which is
    itself part of what these tests assert (a whole-RRset write must be ONE
    message, or it is not atomic).
    """
    sent: list[tuple[Any, str]] = []

    def _fake_tcp(q: Any, where: str, timeout: float | None = None, **kw: Any):
        sent.append((q, where))
        return _FakeDnsResponse()

    monkeypatch.setattr(dns.query, "tcp", _fake_tcp)
    driver.apply_record_op(op)
    return sent


def _wire_sections(update: Any) -> list[tuple[str, str, str, int, list[str]]]:
    """Flatten an Update's UPDATE section into readable tuples.

    ``(kind, name, rdtype, ttl, values)`` where kind is one of:

    * ``delete-rrset``  — RFC 2136 §2.5.2, class ANY: drop every RR at
      ``(name, type)``.
    * ``delete-value``  — §2.5.4, class NONE: drop one specific RR,
      siblings survive.
    * ``add``           — §2.5.1.

    dnspython builds each add as its own RRset object (``force_unique``), so
    the order here is the order the driver asked for.

    Names and rdata are derelativized against the message origin. dnspython
    stores both relative to the zone internally and absolutizes them only
    when it renders the wire, so reading them raw would show ``10 mail1``
    for an MX and make a correct payload look truncated.
    """
    origin = update.origin
    out: list[tuple[str, str, str, int, list[str]]] = []
    for rrset in update.update:
        if rrset.deleting == dns.rdataclass.ANY:
            kind = "delete-rrset"
        elif rrset.deleting == dns.rdataclass.NONE:
            kind = "delete-value"
        else:
            kind = "add"
        out.append(
            (
                kind,
                rrset.name.derelativize(origin).to_text(),
                dns.rdatatype.to_text(rrset.rdtype),
                rrset.ttl,
                [rd.to_text(origin=origin, relativize=False) for rd in rrset],
            )
        )
    return out


def test_bind9_multi_value_a_survives_a_single_record_op(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test for #773 — the exact repro.

    ``app`` holds two A records. Editing/creating either one used to send a
    bare ``upd.replace(name, ttl, "A", <this one value>)``, whose
    delete-RRset wiped the sibling that the op never mentioned: the zone
    ended up answering with a single address and nothing self-healed,
    because record CRUD bumps the bundle ``etag`` but not its
    ``structural_etag``, so the full-zone reconcile never fires.

    With the desired set on the op, ONE message carries a delete of the
    whole RRset plus an add for BOTH values — RFC 2136 §3.4.2.6 applies an
    update section in order, so the deletion and the re-adds land together
    and no client ever observes the name half-populated.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 3600,
                "rrset": {
                    "ttl": 3600,
                    "members": [{"value": "10.20.7.22"}, {"value": "10.20.7.21"}],
                },
            },
        },
    )

    # One message, to the loopback daemon. Splitting the delete and the adds
    # across two messages would reintroduce a window where ``app`` resolves
    # to nothing.
    assert len(sent) == 1
    assert sent[0][1] == "127.0.0.1"

    assert _wire_sections(sent[0][0]) == [
        ("delete-rrset", "app.example.com.", "A", 0, []),
        ("add", "app.example.com.", "A", 3600, ["10.20.7.22"]),
        ("add", "app.example.com.", "A", 3600, ["10.20.7.21"]),
    ]


def test_bind9_empty_members_deletes_the_whole_rrset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An empty member list is the control plane saying "this RRset should
    not exist" — the op removed its last value. That has to become a
    delete of ``(name, type)`` with no adds; emitting a zero-value
    ``replace`` would leave the name intact, and adding anything back would
    resurrect the record the operator just deleted.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {
                "name": "gone",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 3600,
                "rrset": {"ttl": 3600, "members": []},
            },
        },
    )

    assert _wire_sections(sent[0][0]) == [
        ("delete-rrset", "gone.example.com.", "A", 0, [])
    ]


def test_bind9_delete_with_survivors_reinstalls_the_siblings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Deleting one member of a multi-value RRset must keep the rest.

    This is the destructive half of #773: the old delete path ran
    ``upd.delete(name, rtype)`` — delete the whole RRset, by (name, type),
    with no re-add — so removing one address from a three-address
    round-robin took the other two down with it. The survivors the control
    plane ships are re-installed in the same message.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 3600,
                "rrset": {
                    "ttl": 3600,
                    "members": [{"value": "10.20.7.22"}, {"value": "10.20.7.23"}],
                },
            },
        },
    )

    sections = _wire_sections(sent[0][0])
    assert sections[0] == ("delete-rrset", "app.example.com.", "A", 0, [])
    assert [s[4] for s in sections[1:]] == [["10.20.7.22"], ["10.20.7.23"]]
    # The deleted value must not come back.
    assert all("10.20.7.21" not in s[4] for s in sections)


def test_bind9_rrset_ttl_wins_over_the_ops_own_record_ttl(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RFC 2181 §5.2: every RR in an RRset carries the same TTL, and a
    resolver receiving a mismatched set is entitled to pick any of them.

    So the TTL that lands on the wire is the RRset's, not the individual
    op record's — the op record is one member's row and its TTL may be
    mid-edit or simply stale relative to its siblings. All members share it.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "update",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 30,  # the op's own row — deliberately different
                "rrset": {
                    "ttl": 600,
                    "members": [{"value": "10.20.7.21"}, {"value": "10.20.7.22"}],
                },
            },
        },
    )

    adds = [s for s in _wire_sections(sent[0][0]) if s[0] == "add"]
    assert len(adds) == 2
    assert {s[3] for s in adds} == {600}


def test_bind9_rrset_ttl_of_zero_is_honoured_not_treated_as_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A TTL of 0 is legal (RFC 2181 §8) and is how "do not cache this"
    is expressed — DDNS-driven names are the usual reason to want it.

    The natural way to write the fallback, ``rrset["ttl"] or ttl``, quietly
    turns that into the op record's TTL instead, and the resulting bug is
    invisible until someone wonders why a record that must not be cached
    is being cached. The test exists because the correct spelling is the
    less obvious one.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "update",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 300,
                "rrset": {"ttl": 0, "members": [{"value": "10.20.7.21"}]},
            },
        },
    )

    adds = [s for s in _wire_sections(sent[0][0]) if s[0] == "add"]
    assert [s[3] for s in adds] == [0]


def test_bind9_multi_member_mx_composes_priority_per_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``_wire_value`` must be applied to every member, not just to the op's
    own record.

    MX presentation format puts the preference inline before the exchange,
    and the control plane stores it in a separate column — so a member whose
    priority was left as a bare field would be handed to dnspython as
    ``mail2.example.com.`` and raise, or (worse, on a driver that doesn't
    parse) install a mail route with the wrong preference. Each member
    carries its own priority and each must be composed from it.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "@",
                "type": "MX",
                "value": "mail2.example.com.",
                "priority": 20,
                "ttl": 3600,
                "rrset": {
                    "ttl": 3600,
                    "members": [
                        {"value": "mail1.example.com.", "priority": 10},
                        {"value": "mail2.example.com.", "priority": 20},
                    ],
                },
            },
        },
    )

    sections = _wire_sections(sent[0][0])
    # Apex: ``@`` resolves to the zone itself, which is where a multi-MX
    # RRset actually lives.
    assert sections[0] == ("delete-rrset", "example.com.", "MX", 0, [])
    assert [s[4] for s in sections[1:]] == [
        ["10 mail1.example.com."],
        ["20 mail2.example.com."],
    ]


def test_bind9_multi_member_srv_composes_priority_weight_port_per_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Same rule as MX, with three inline fields instead of one.

    A pair of SRV records at ``_sip._tcp`` is the normal shape (primary +
    backup), which is exactly the case #773 destroyed, so the composition
    has to survive the RRset path rather than only the single-record one.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "_sip._tcp",
                "type": "SRV",
                "value": "sip2.example.com.",
                "priority": 20,
                "weight": 10,
                "port": 5060,
                "ttl": 3600,
                "rrset": {
                    "ttl": 3600,
                    "members": [
                        {
                            "value": "sip1.example.com.",
                            "priority": 10,
                            "weight": 60,
                            "port": 5060,
                        },
                        {
                            "value": "sip2.example.com.",
                            "priority": 20,
                            "weight": 10,
                            "port": 5060,
                        },
                    ],
                },
            },
        },
    )

    sections = _wire_sections(sent[0][0])
    assert [s[4] for s in sections[1:]] == [
        ["10 60 5060 sip1.example.com."],
        ["20 10 5060 sip2.example.com."],
    ]


def test_bind9_without_rrset_falls_back_to_replace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No ``rrset`` key ⇒ the pre-#773 behaviour, byte-identical.

    Ops enqueued by an older control plane are still in the queue when the
    agent picks up the new code, so the old semantics have to keep working
    exactly as they did — a value edit replaces the RRset with the single
    new value.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "update",
            "record": {"name": "www", "type": "A", "value": "10.0.0.2", "ttl": 300},
        },
    )

    assert _wire_sections(sent[0][0]) == [
        ("delete-rrset", "www.example.com.", "A", 0, []),
        ("add", "www.example.com.", "A", 300, ["10.0.0.2"]),
    ]


def test_bind9_without_rrset_honours_rrset_action_add(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``rrset_action="add"`` is the older per-op override, set by DNS pools
    because N A records share one name there and a bare replace clobbers
    the siblings on every member add. On the fallback path it must still
    append — no delete-RRset at all.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "pool",
                "type": "A",
                "value": "10.0.0.7",
                "ttl": 60,
                "rrset_action": "add",
            },
        },
    )

    assert _wire_sections(sent[0][0]) == [
        ("add", "pool.example.com.", "A", 60, ["10.0.0.7"])
    ]


def test_bind9_without_rrset_delete_value_keeps_siblings(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``rrset_action="delete_value"`` is the pool-member-removal override:
    drop this one RR (RFC 2136 class NONE) and leave the rest of the RRset
    standing. The value has to ride along in the delete, since that is what
    identifies which RR to remove.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {
                "name": "pool",
                "type": "A",
                "value": "10.0.0.7",
                "rrset_action": "delete_value",
            },
        },
    )

    assert _wire_sections(sent[0][0]) == [
        ("delete-value", "pool.example.com.", "A", 0, ["10.0.0.7"])
    ]


def test_bind9_without_rrset_delete_drops_whole_rrset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plain delete with no override clears by ``(name, type)``.

    Deliberately value-blind: BIND rejects the RR-specific delete form when
    the running daemon has drifted from the zone file, and this form is
    idempotent, so a replayed op finds the state it asks for rather than an
    error.
    """
    driver = Bind9Driver(state_dir=tmp_path)
    sent = _send(
        monkeypatch,
        driver,
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {"name": "www", "type": "A", "value": "10.0.0.1"},
        },
    )

    assert _wire_sections(sent[0][0]) == [
        ("delete-rrset", "www.example.com.", "A", 0, [])
    ]


def test_bind9_dnssec_op_never_reaches_the_record_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """DNSSEC ops ride the same queue but are zone-level, not RRset-shaped.

    BIND9 signs from the rendered config (inline-signing), so sign/unsign
    need no per-op action — and their synthetic ``DNSSEC_OP`` record type
    would raise inside ``dns.rdatatype`` if it ever reached the update
    builder. The branch must return before any of the RRset machinery,
    including the new ``rrset`` lookup, runs.
    """
    driver = Bind9Driver(state_dir=tmp_path)

    def _fake_tcp(q: Any, where: str, timeout: float | None = None, **kw: Any):
        raise AssertionError("a DNSSEC op must not send an RFC 2136 update")

    monkeypatch.setattr(dns.query, "tcp", _fake_tcp)

    result = driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "dnssec_sign",
            "record": {"name": "@", "type": "DNSSEC_OP"},
        }
    )

    assert result is None


# ── Technitium: N REST calls, first one clears ──────────────────────────────


def test_technitium_rrset_writes_every_member_first_one_overwriting(
    tmp_path: Path,
) -> None:
    """Technitium's REST API is one record per call, so a whole-RRset write
    is N calls and the ordering carries the semantics: member 0 with
    ``overwrite=true`` wipes the existing RRset and installs itself, and
    every later member appends with ``overwrite=false``.

    Get it backwards — all ``true`` — and the set collapses to the last
    member, which is the #773 bug wearing a different hat. All members
    share the RRset TTL (RFC 2181 §5.2).
    """
    driver = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(driver)
    calls = _install_fake_request(driver, lambda *_: {"status": "ok"})

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 60,
                "rrset": {
                    "ttl": 3600,
                    "members": [
                        {"value": "10.20.7.21"},
                        {"value": "10.20.7.22"},
                        {"value": "10.20.7.23"},
                    ],
                },
            },
        }
    )

    assert len(calls) == 3
    assert {path for (_, _, path, _) in calls} == {"zones/records/add"}
    assert [params["overwrite"] for (_, _, _, params) in calls] == [
        "true",
        "false",
        "false",
    ]
    assert [params["ipAddress"] for (_, _, _, params) in calls] == [
        "10.20.7.21",
        "10.20.7.22",
        "10.20.7.23",
    ]
    # The RRset TTL, not the op record's own 60.
    assert {params["ttl"] for (_, _, _, params) in calls} == {3600}
    assert {params["domain"] for (_, _, _, params) in calls} == {"app.example.com"}


def test_technitium_rrset_members_compose_their_own_structured_fields(
    tmp_path: Path,
) -> None:
    """Each member goes through ``_record_params`` in its own right, so a
    multi-MX RRset carries a per-member ``preference``.

    This driver rebuilds the param dict inside the loop rather than reusing
    the op's own — reading ``rec`` instead of ``member`` for the priority
    would give every member the op record's preference and silently rewrite
    the operator's mail routing.
    """
    driver = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(driver)
    calls = _install_fake_request(driver, lambda *_: {"status": "ok"})

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "@",
                "type": "MX",
                "value": "mail1.example.com.",
                "priority": 10,
                "rrset": {
                    "ttl": 3600,
                    "members": [
                        {"value": "mail1.example.com.", "priority": 10},
                        {"value": "mail2.example.com.", "priority": 20},
                    ],
                },
            },
        }
    )

    assert [
        (params["exchange"], params["preference"]) for (_, _, _, params) in calls
    ] == [("mail1.example.com", 10), ("mail2.example.com", 20)]


def test_technitium_delete_with_survivors_is_one_surgical_call(
    tmp_path: Path,
) -> None:
    """A delete removes ONLY its own value — it does not wipe and rebuild.

    The survivors in ``members`` are already on the server. Clearing the
    RRset to re-add them would open a window, one HTTP call wide, where the
    name serves less than it should, and a failure inside that window would
    leave it truncated until the retry budget ran out. This API has a
    value-scoped delete; there is no reason to reach past it.
    """
    driver = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(driver)
    calls = _install_fake_request(driver, lambda *_: {"status": "ok"})

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {
                "name": "pool",
                "type": "A",
                "value": "10.20.7.21",
                "rrset": {
                    "ttl": 3600,
                    "members": [{"value": "10.20.7.22"}, {"value": "10.20.7.23"}],
                },
            },
        }
    )

    assert len(calls) == 1
    _, _, path, params = calls[0]
    assert path == "zones/records/delete"
    assert params["ipAddress"] == "10.20.7.21"


def test_technitium_rrset_ttl_of_zero_is_honoured_not_treated_as_missing(
    tmp_path: Path,
) -> None:
    """Same "absence, not falsiness" rule as the BIND9 driver — each of the
    three drivers spells the fallback out separately, so each one can
    independently regress to ``rrset["ttl"] or ttl``."""
    driver = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(driver)
    calls = _install_fake_request(driver, lambda *_: {"status": "ok"})

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "update",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 300,
                "rrset": {"ttl": 0, "members": [{"value": "10.20.7.21"}]},
            },
        }
    )

    assert [params["ttl"] for (_, _, _, params) in calls] == [0]


def test_technitium_empty_members_calls_the_delete_endpoint(
    tmp_path: Path,
) -> None:
    """Last value gone ⇒ delete the record, don't add anything.

    ``zones/records/delete`` needs the exact value params to identify what
    it is removing, which is why the op's own record payload (not the empty
    member list) supplies them.
    """
    driver = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(driver)
    calls = _install_fake_request(driver, lambda *_: {"status": "ok"})

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {
                "name": "gone",
                "type": "A",
                "value": "10.20.7.21",
                "rrset": {"ttl": 3600, "members": []},
            },
        }
    )

    assert len(calls) == 1
    _, _, path, params = calls[0]
    assert path == "zones/records/delete"
    assert params["ipAddress"] == "10.20.7.21"
    assert "overwrite" not in params


def test_technitium_idempotent_noop_does_not_abandon_later_members(
    tmp_path: Path,
) -> None:
    """An "already exists" answer mid-sequence must not end the write.

    Technitium answers HTTP 200 with ``{"status": "error"}`` for a record
    that is already present, and a replayed op hits that on any member that
    landed before the retry. The pre-fix code returned early on it, which
    on a multi-member RRset means every member after the first duplicate is
    silently never written — a partially-applied set that looks like a
    success. Every remaining member must still be attempted.
    """
    driver = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(driver)

    def _responder(path: str, params: dict[str, Any], n: int) -> dict[str, Any]:
        if n == 2:
            return {"status": "error", "errorMessage": "Record already exists."}
        return {"status": "ok"}

    calls = _install_fake_request(driver, _responder)

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 3600,
                "rrset": {
                    "ttl": 3600,
                    "members": [
                        {"value": "10.20.7.21"},
                        {"value": "10.20.7.22"},
                        {"value": "10.20.7.23"},
                    ],
                },
            },
        }
    )

    assert [params["ipAddress"] for (_, _, _, params) in calls] == [
        "10.20.7.21",
        "10.20.7.22",
        "10.20.7.23",
    ]


def test_technitium_without_rrset_falls_back_to_single_overwriting_add(
    tmp_path: Path,
) -> None:
    """No ``rrset`` ⇒ exactly one call, the pre-#773 REPLACE.

    The count matters as much as the flag: an op from an older control
    plane must not accidentally engage the multi-call RRset path with a
    one-element set it never declared.
    """
    driver = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(driver)
    calls = _install_fake_request(driver, lambda *_: {"status": "ok"})

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "update",
            "record": {"name": "www", "type": "A", "value": "10.0.0.2", "ttl": 300},
        }
    )

    assert len(calls) == 1
    _, _, path, params = calls[0]
    assert path == "zones/records/add"
    assert params["overwrite"] == "true"
    assert params["ttl"] == 300


def test_technitium_without_rrset_honours_rrset_action_add(tmp_path: Path) -> None:
    """The older per-op override still appends on the fallback path — DNS
    pools depend on it, and they are exactly the multi-value RRsets that
    would otherwise lose siblings on every member add."""
    driver = TechnitiumDriver(state_dir=tmp_path)
    _seed_token(driver)
    calls = _install_fake_request(driver, lambda *_: {"status": "ok"})

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "pool",
                "type": "A",
                "value": "10.0.0.7",
                "ttl": 60,
                "rrset_action": "add",
            },
        }
    )

    assert len(calls) == 1
    assert calls[0][3]["overwrite"] == "false"


# ── PowerDNS: one REPLACE PATCH, no zone GET ────────────────────────────────


class _FakePdnsResponse:
    def __init__(self, status_code: int = 200, body: Any = None) -> None:
        self.status_code = status_code
        self.text = ""
        self._body = body if body is not None else {}

    def json(self) -> Any:
        return self._body


class _FakePdnsClient:
    """Context-manager stand-in for ``httpx.Client``, recording every call
    as ``(method, url, json_body)``."""

    def __init__(self, calls: list[tuple[str, str, Any]], zone_doc: Any) -> None:
        self._calls = calls
        self._zone_doc = zone_doc

    def __enter__(self) -> _FakePdnsClient:
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def get(self, url: str, headers: Any = None) -> _FakePdnsResponse:
        self._calls.append(("GET", url, None))
        return _FakePdnsResponse(200, self._zone_doc)

    def patch(
        self, url: str, headers: Any = None, json: Any = None
    ) -> _FakePdnsResponse:
        self._calls.append(("PATCH", url, json))
        return _FakePdnsResponse(200, {})


def _install_fake_pdns_client(
    monkeypatch: pytest.MonkeyPatch, zone_doc: Any = None
) -> list[tuple[str, str, Any]]:
    """Swap the driver module's ``httpx`` for a namespace exposing only the
    fake ``Client``.

    Scoped to the powerdns module rather than patching ``httpx.Client``
    itself, so the fake can't leak into any other module that imports httpx.
    """
    calls: list[tuple[str, str, Any]] = []
    monkeypatch.setattr(
        powerdns_mod,
        "httpx",
        SimpleNamespace(
            Client=lambda **kw: _FakePdnsClient(calls, zone_doc or {"rrsets": []})
        ),
    )
    return calls


def test_powerdns_rrset_sends_one_replace_patch_and_no_zone_get(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The desired set makes the read-merge-write cycle unnecessary.

    PowerDNS has no INSERT/REMOVE-MEMBER granularity — ``REPLACE`` swaps
    the whole RRset — so before #773 the driver had to GET the zone, splice
    the op's value into whatever it found, and PATCH the merge back. That
    read is both a per-op round trip against the full zone document and a
    lost-update race between two concurrent ops. With the complete set on
    the op it is one PATCH and no GET, which is what this pins: the absence
    of the GET is the point, not an incidental detail.
    """
    driver = PowerDNSDriver(state_dir=tmp_path)
    calls = _install_fake_pdns_client(monkeypatch)

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "update",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 60,
                "rrset": {
                    "ttl": 3600,
                    "members": [{"value": "10.20.7.22"}, {"value": "10.20.7.21"}],
                },
            },
        }
    )

    assert [method for (method, _, _) in calls] == ["PATCH"]
    _, url, body = calls[0]
    assert url.endswith("/zones/example.com.")
    assert body["rrsets"] == [
        {
            "name": "app.example.com.",
            "type": "A",
            "ttl": 3600,  # the RRset's TTL, not the op record's 60
            "changetype": "REPLACE",
            "records": [
                {"content": "10.20.7.22", "disabled": False},
                {"content": "10.20.7.21", "disabled": False},
            ],
        }
    ]


def test_powerdns_rrset_ttl_of_zero_is_honoured_not_treated_as_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Third copy of the "absence, not falsiness" TTL rule — see the BIND9
    test of the same name for why 0 is the value that gets lost."""
    driver = PowerDNSDriver(state_dir=tmp_path)
    calls = _install_fake_pdns_client(monkeypatch)

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "update",
            "record": {
                "name": "app",
                "type": "A",
                "value": "10.20.7.21",
                "ttl": 300,
                "rrset": {"ttl": 0, "members": [{"value": "10.20.7.21"}]},
            },
        }
    )

    assert calls[0][2]["rrsets"][0]["ttl"] == 0


def test_powerdns_multi_member_mx_composes_content_per_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each member's content is stitched from its own fields.

    PowerDNS stores MX preference inline in ``content``, and the member
    dicts carry the priority as a separate key — so the driver has to run
    every member through the content builder, not just the op's own record.
    A member handed through raw would install ``mail1.example.com.`` with
    no preference and PowerDNS would reject the PATCH.
    """
    driver = PowerDNSDriver(state_dir=tmp_path)
    calls = _install_fake_pdns_client(monkeypatch)

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {
                "name": "@",
                "type": "MX",
                "value": "mail2.example.com.",
                "priority": 20,
                "ttl": 3600,
                "rrset": {
                    "ttl": 3600,
                    "members": [
                        {"value": "mail1.example.com.", "priority": 10},
                        {"value": "mail2.example.com.", "priority": 20},
                    ],
                },
            },
        }
    )

    _, _, body = calls[0]
    rrset = body["rrsets"][0]
    assert rrset["name"] == "example.com."  # apex
    assert [r["content"] for r in rrset["records"]] == [
        "10 mail1.example.com.",
        "20 mail2.example.com.",
    ]


def test_powerdns_empty_members_sends_a_delete_changetype(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Empty set ⇒ ``changetype: DELETE`` and nothing else.

    A ``REPLACE`` with an empty ``records`` list is not the same request —
    PowerDNS treats it as a malformed replace rather than a removal — so
    the empty case has to switch changetype, not just ship zero records.
    Still no zone GET: there is nothing to merge with.
    """
    driver = PowerDNSDriver(state_dir=tmp_path)
    calls = _install_fake_pdns_client(monkeypatch)

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {
                "name": "gone",
                "type": "A",
                "value": "10.20.7.21",
                "rrset": {"ttl": 3600, "members": []},
            },
        }
    )

    assert [method for (method, _, _) in calls] == ["PATCH"]
    assert calls[0][2]["rrsets"] == [
        {"name": "gone.example.com.", "type": "A", "changetype": "DELETE"}
    ]


def test_powerdns_without_rrset_still_does_the_get_merge_patch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No ``rrset`` ⇒ the pre-#773 read-merge-write survives unchanged.

    It is the only thing standing between an op from an older control plane
    and a clobbered sibling: two consecutive ``create www A`` calls would
    otherwise have the second overwrite the first, which is how GSLB pool
    fan-out broke. The merge de-duplicates the incoming content and appends
    it to whatever the zone already holds.
    """
    driver = PowerDNSDriver(state_dir=tmp_path)
    calls = _install_fake_pdns_client(
        monkeypatch,
        zone_doc={
            "rrsets": [
                {
                    "name": "www.example.com.",
                    "type": "A",
                    "records": [{"content": "10.0.0.1", "disabled": False}],
                }
            ]
        },
    )

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "create",
            "record": {"name": "www", "type": "A", "value": "10.0.0.2", "ttl": 300},
        }
    )

    assert [method for (method, _, _) in calls] == ["GET", "PATCH"]
    assert calls[1][2]["rrsets"] == [
        {
            "name": "www.example.com.",
            "type": "A",
            "ttl": 300,
            "changetype": "REPLACE",
            "records": [
                {"content": "10.0.0.1", "disabled": False},
                {"content": "10.0.0.2", "disabled": False},
            ],
        }
    ]


def _pool_zone_doc() -> dict[str, Any]:
    return {
        "rrsets": [
            {
                "name": "pool.example.com.",
                "type": "A",
                "records": [
                    {"content": "10.0.0.1", "disabled": False},
                    {"content": "10.0.0.2", "disabled": False},
                ],
            }
        ]
    }


def test_powerdns_without_rrset_delete_value_removes_only_that_member(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pool member removal actually removes the member (#1520).

    Pool ops carry ``rrset_action="delete_value"`` and no ``rrset``
    payload, so they always take the read-merge-PATCH fallback. The
    fallback computed the content to remove as ``None`` and filtered on
    it, which kept every record: the PATCH sent the unchanged set back
    and the op was acked as applied, so a removed / unhealthy pool
    member kept receiving round-robin traffic.
    """
    driver = PowerDNSDriver(state_dir=tmp_path)
    calls = _install_fake_pdns_client(monkeypatch, zone_doc=_pool_zone_doc())

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {
                "name": "pool",
                "type": "A",
                "value": "10.0.0.1",
                "ttl": 300,
                "rrset_action": "delete_value",
            },
        }
    )

    assert [method for (method, _, _) in calls] == ["GET", "PATCH"]
    assert calls[1][2]["rrsets"] == [
        {
            "name": "pool.example.com.",
            "type": "A",
            "ttl": 300,
            "changetype": "REPLACE",
            "records": [{"content": "10.0.0.2", "disabled": False}],
        }
    ]


def test_powerdns_without_rrset_delete_value_last_member_deletes_rrset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Removing the last pool member deletes the rrset (#1520)."""
    driver = PowerDNSDriver(state_dir=tmp_path)
    calls = _install_fake_pdns_client(
        monkeypatch,
        zone_doc={
            "rrsets": [
                {
                    "name": "pool.example.com.",
                    "type": "A",
                    "records": [{"content": "10.0.0.1", "disabled": False}],
                }
            ]
        },
    )

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {
                "name": "pool",
                "type": "A",
                "value": "10.0.0.1",
                "ttl": 300,
                "rrset_action": "delete_value",
            },
        }
    )

    assert calls[1][2]["rrsets"] == [
        {"name": "pool.example.com.", "type": "A", "changetype": "DELETE"}
    ]


def test_powerdns_without_rrset_plain_delete_drops_whole_rrset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A delete with no ``delete_value`` override clears (name, type).

    Matches the BIND9 driver's plain-delete semantics; before #1520 the
    fallback REPLACEd the rrset with its own unchanged contents.
    """
    driver = PowerDNSDriver(state_dir=tmp_path)
    calls = _install_fake_pdns_client(monkeypatch, zone_doc=_pool_zone_doc())

    driver.apply_record_op(
        {
            "zone_name": "example.com.",
            "op": "delete",
            "record": {"name": "pool", "type": "A", "value": "10.0.0.1", "ttl": 300},
        }
    )

    assert calls[1][2]["rrsets"] == [
        {"name": "pool.example.com.", "type": "A", "changetype": "DELETE"}
    ]
