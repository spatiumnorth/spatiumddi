"""#3236 — an httpx failure says which address, and never leaks a secret."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest

from app.core.exc_text import describe_http_exc
from app.services.influxdb.client import InfluxDBWriteError, InfluxTargetConfig, write_lines

SECRET = "s3cr3t-token-value"
URL = f"http://192.0.2.13:8086/api/v2/write?org=o&bucket=b&p={SECRET}"


def _req() -> httpx.Request:
    return httpx.Request("POST", URL)


def test_connect_timeout_names_target_and_limit() -> None:
    msg = describe_http_exc(httpx.ConnectTimeout("", request=_req()), timeout=2)
    assert msg == "Connection to 192.0.2.13:8086 timed out after 2s"


def test_read_timeout_names_target() -> None:
    msg = describe_http_exc(httpx.ReadTimeout("", request=_req()), timeout=10)
    assert "192.0.2.13:8086" in msg and "10s" in msg


def test_connect_error_with_and_without_text() -> None:
    assert describe_http_exc(httpx.ConnectError("", request=_req())) == (
        "Could not connect to 192.0.2.13:8086"
    )
    msg = describe_http_exc(httpx.ConnectError("Connection refused", request=_req()))
    assert msg == "Could not connect to 192.0.2.13:8086: Connection refused"


def test_status_error_names_code_and_target() -> None:
    resp = httpx.Response(503, request=_req())
    exc = httpx.HTTPStatusError("boom", request=_req(), response=resp)
    assert describe_http_exc(exc) == "HTTP 503 from 192.0.2.13:8086"


def test_error_without_request_still_non_empty() -> None:
    msg = describe_http_exc(httpx.ReadTimeout(""))
    assert msg and msg != "ReadTimeout:"


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ConnectTimeout("", request=_req()),
        httpx.ConnectError(f"cannot reach {URL}", request=_req()),
        httpx.ReadError(f"broke talking to {URL}", request=_req()),
        httpx.InvalidURL(f"bad {URL}"),
        httpx.ConnectError("x", request=httpx.Request("GET", f"https://u:{SECRET}@h.example/x")),
    ],
)
def test_no_secret_in_message(exc: Exception) -> None:
    assert SECRET not in describe_http_exc(exc, timeout=3)


@pytest.mark.parametrize(
    ("exc", "expect"),
    [
        (httpx.ConnectTimeout("", request=_req()), "timed out after 2s"),
        (httpx.ReadTimeout("", request=_req()), "no response after 2s"),
        (httpx.ConnectError("", request=_req()), "Could not connect to 192.0.2.13:8086"),
    ],
)
async def test_influx_write_error_is_meaningful(exc: Exception, expect: str) -> None:
    cfg = InfluxTargetConfig(
        version="v1",
        url="http://192.0.2.13:8086",
        database="d",
        username="u",
        password=SECRET,
        timeout_seconds=2,
    )

    async def boom(self, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        raise exc

    with patch.object(httpx.AsyncClient, "post", boom):
        with pytest.raises(InfluxDBWriteError) as info:
            await write_lines(cfg, "m f=1i 1")
    text = str(info.value)
    assert expect in text and "192.0.2.13:8086" in text
    assert text.strip() and not text.endswith(":") and SECRET not in text


async def test_http_status_error_in_influx_write() -> None:
    cfg = InfluxTargetConfig(version="v1", url="http://192.0.2.13:8086", database="d")

    async def resp(self, *a, **kw):  # noqa: ANN001, ANN002, ANN003
        return httpx.Response(401, text="unauthorized", request=_req())

    with patch.object(httpx.AsyncClient, "post", resp):
        with pytest.raises(InfluxDBWriteError, match="HTTP 401: unauthorized"):
            await write_lines(cfg, "m f=1i 1")
