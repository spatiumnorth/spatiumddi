"""Before its first apply an agent must not report ``ok`` (#2258)."""

from spatium_dhcp_agent.config_apply import STATUS_OK, ApplyStatus


def test_initial_status_does_not_say_ok() -> None:
    # What heartbeat.py sends as the ``config`` field before any apply.
    assert ApplyStatus().as_dict().get("status") != STATUS_OK


def test_a_real_ok_with_an_etag_is_still_reported() -> None:
    payload = ApplyStatus(status=STATUS_OK, etag="abc").as_dict()
    assert payload["status"] == STATUS_OK
    assert payload["etag"] == "abc"
