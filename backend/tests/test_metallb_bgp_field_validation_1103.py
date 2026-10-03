"""BGP fields MetalLB's webhooks used to refuse are checked by the API (#1103).

#1103 makes MetalLB's validating webhooks fail open while the controller
starts, so an install no longer loops on them. The cost is that a value the
webhook would have refused now installs, and MetalLB marks the config stale
and leaves the VIP unadvertised, with no error anywhere. So the API refuses
those values itself.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.api.v1.appliance.supervisor import (
    MetalLBBgpAdvertisement,
    MetalLBBgpPeer,
    _go_duration_seconds,
)


def _peer(**kw: object) -> MetalLBBgpPeer:
    return MetalLBBgpPeer(my_asn=64512, peer_asn=64513, peer_address="192.0.2.1", **kw)


@pytest.mark.parametrize(
    ("text", "seconds"),
    [("90s", 90), ("1m30s", 90), ("2h", 7200), ("1.5m", 90), ("500ms", 0.5)],
)
def test_go_durations_parse(text: str, seconds: float) -> None:
    assert _go_duration_seconds(text) == seconds


@pytest.mark.parametrize("text", ["90", "s", "90x", "1m 30s", "-5s", ""])
def test_non_durations_do_not(text: str) -> None:
    assert _go_duration_seconds(text) is None


def test_hold_time_bounds() -> None:
    assert _peer(hold_time="90s").hold_time == "90s"
    assert _peer(hold_time=None).hold_time is None
    assert _peer(hold_time="  ").hold_time is None
    for bad in ("1s", "2999ms", "65536s", "ninety", "90"):
        with pytest.raises(ValidationError):
            _peer(hold_time=bad)


def test_communities() -> None:
    ok = MetalLBBgpAdvertisement(communities=["65000:100", "large:1:2:3", " 0:65535 "])
    assert ok.communities == ["65000:100", "large:1:2:3", "0:65535"]
    for bad in ("65536:1", "1:2:3", "no-export", "large:1:2", "large:1:2:4294967296", "²:1"):
        with pytest.raises(ValidationError):
            MetalLBBgpAdvertisement(communities=[bad])


def test_aggregation_length() -> None:
    assert MetalLBBgpAdvertisement(aggregation_length=24).aggregation_length == 24
    assert MetalLBBgpAdvertisement(aggregation_length=None).aggregation_length is None
    for bad in (-1, 33):
        with pytest.raises(ValidationError):
            MetalLBBgpAdvertisement(aggregation_length=bad)
