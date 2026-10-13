"""#1059 — the CloudNativePG size hold a dead-node replace arms (heartbeat._ReplaceHold).

An eviction tick that names a Replace (``replace_node_names``; #1541 — a
demote's cleanup eviction never arms it, see ``test_cnpg_demote_shrink``) is a
replace tick. From it the seed must not scale CNPG down until
the committed count is back at the size CNPG has, or the operator shrinks the
control plane below the count the eviction carried. The backend settles the
evicted row before it answers the next heartbeat, so only the eviction tick
itself carries the name: the hold has to outlive it by the whole install.
"""

from __future__ import annotations

from spatium_supervisor.heartbeat import _ReplaceHold

M1, M2 = "ddipg-member-1", "ddipg-member-2"


def _armed_replace_of(node: str = M2, cp_size: int = 2, spec: int = 3) -> _ReplaceHold:
    h = _ReplaceHold()
    h.reason([node], cp_size)
    h.settle(cp_size, spec)
    return h


def test_the_eviction_tick_arms_the_hold_and_names_the_node() -> None:
    h = _ReplaceHold()

    why = h.reason([M2], 2)

    assert why == ("replacing ['ddipg-member-2']: the committed count 2 is short until the "
                   "replacement is promoted")
    assert h.armed and h.cp_size == 2 and h.nodes == [M2]


def test_the_hold_outlives_the_eviction_tick_for_the_whole_install() -> None:
    """Ticks N+1 onward carry no evict names (the backend settled the row to
    ``left`` before answering) and the count stays 2 for ~10 min of ticks."""
    h = _armed_replace_of()

    for _ in range(24):
        assert h.reason([], 2).startswith("replacing ['ddipg-member-2']")
        h.settle(2, 3)

    assert h.armed


def test_the_count_coming_back_releases_it() -> None:
    """The replacement settles ``member``: the tick reads count 3 against spec
    3 — nothing to hold, and the next demote is free to scale down."""
    h = _armed_replace_of()

    assert h.reason([], 3) != ""     # judged before the tick's CR read
    h.settle(3, 3)

    assert not h.armed
    assert h.reason([], 3) == ""
    assert h.reason([], 1) == ""


def test_a_deliberate_shrink_below_the_evicted_count_releases_it() -> None:
    """The operator gives up on the slot and demotes the surviving member
    (3 -> 1) instead of replacing: below the count the eviction left."""
    h = _armed_replace_of()

    assert h.reason([], 1) == ""
    assert not h.armed


def test_a_second_death_re_arms_at_the_lower_count() -> None:
    h = _armed_replace_of()

    why = h.reason([M1], 1)

    assert why.startswith("replacing ['ddipg-member-1']") and h.cp_size == 1
    # the first replacement settles: 2 is still short of 3
    assert h.reason([], 2) != ""
    h.settle(2, 3)
    assert h.armed
    # the second: whole again
    assert h.reason([], 3) != ""
    h.settle(3, 3)
    assert not h.armed


def test_a_failed_joiner_replace_leaves_nothing_to_hold() -> None:
    """``/replace`` on a joiner whose join failed: the committed count never
    included it, so the count already equals the spec on the eviction tick."""
    h = _ReplaceHold()
    h.reason([M2], 2)

    h.settle(2, 2)

    assert not h.armed
    assert h.reason([], 2) == ""


def test_an_unreadable_cluster_keeps_the_hold() -> None:
    h = _ReplaceHold()
    h.reason([M2], 2)

    h.settle(2, None)

    assert h.armed


def test_a_quiet_tick_holds_nothing() -> None:
    assert _ReplaceHold().reason([], 3) == ""


def test_blank_names_are_ignored() -> None:
    h = _ReplaceHold()

    assert h.reason(["", None], 3) == ""
    assert not h.armed
