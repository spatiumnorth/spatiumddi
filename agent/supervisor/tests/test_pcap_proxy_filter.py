"""The capture filter is an expression, never a tcpdump option."""

from __future__ import annotations

import pytest

from spatium_supervisor import pcap_proxy as pp


def _cmd(bpf: str) -> dict:
    return {"capture_id": "abc123", "interface": "any", "bpf_filter": bpf}


@pytest.mark.parametrize("bad", ["-V/tmp/x", "  -w/tmp/x", "-n"])
def test_leading_dash_refused(bad: str) -> None:
    with pytest.raises(pp.PcapValidationError):
        pp._validate(_cmd(bad))


@pytest.mark.parametrize("good", ["host 10.0.0.1 and port 53", "len - 10 > 0"])
def test_legit_filters_accepted(good: str) -> None:
    assert pp._validate(_cmd(good))["bpf_filter"] == good
