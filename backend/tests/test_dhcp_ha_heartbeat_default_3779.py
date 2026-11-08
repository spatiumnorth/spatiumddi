"""HA heartbeat-delay default (#3779): 2 s, still far below max-response-delay."""

from app.api.v1.dhcp.server_groups import GroupCreate
from app.drivers.dhcp.base import FailoverConfig
from app.models.dhcp import DHCPServerGroup


def test_new_group_defaults() -> None:
    col = DHCPServerGroup.__table__.c
    assert col.heartbeat_delay_ms.default.arg == 2000
    body = GroupCreate(name="g")
    assert body.heartbeat_delay_ms == 2000


def test_driver_default_and_kea_constraint() -> None:
    fc = FailoverConfig(
        channel_id="1", channel_name="g", mode="hot-standby", this_server_name="a", peers=()
    )
    assert fc.heartbeat_delay_ms == 2000
    # Kea needs max-response-delay > heartbeat-delay, ideally several times it.
    assert fc.max_response_delay_ms >= 5 * fc.heartbeat_delay_ms
