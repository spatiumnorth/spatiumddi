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


# ── Redaction attacks (#3236 validation) ─────────────────────────────────────


@pytest.mark.parametrize(
    "exc",
    [
        # A webhook URL (Slack / Teams / Discord) carries its secret in the PATH.
        httpx.ConnectError(
            f"cannot reach https://hooks.example.com/services/{SECRET}/x",
            request=httpx.Request("POST", f"https://hooks.example.com/services/{SECRET}"),
        ),
        # A password holding a bare ``@`` must not be cut at its first ``@``.
        httpx.ReadError(
            f"x http://u:p@{SECRET}@h.example:8086/w",
            request=httpx.Request("POST", "http://h.example/"),
        ),
        # Not an httpx error: the fallback path reduces URLs the same way.
        ValueError(f"bad https://h.example/{SECRET}/x?t={SECRET}#{SECRET}"),
        ValueError(f"bad http://[2001:db8::1]:8086/{SECRET}"),
    ],
)
def test_no_path_or_userinfo_secret(exc: Exception) -> None:
    msg = describe_http_exc(exc, timeout=3)
    assert SECRET not in msg
    assert msg.strip()


def test_fallback_keeps_the_host() -> None:
    msg = describe_http_exc(ValueError(f"bad http://[2001:db8::1]:8086/{SECRET}?p=1 now"))
    assert msg == "bad http://[2001:db8::1]:8086 now"


async def test_refused_header_value_is_not_quoted() -> None:
    """h11 quotes a header it refuses — and that header is the token."""
    import socket

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        async with httpx.AsyncClient(timeout=2) as client:
            with pytest.raises(httpx.LocalProtocolError) as info:
                await client.post(
                    f"http://127.0.0.1:{port}/w",
                    headers={"Authorization": f"Token {SECRET}\n"},
                )
    finally:
        srv.close()
    assert SECRET in str(info.value)  # positive control: h11 really echoes it
    msg = describe_http_exc(info.value, timeout=2)
    assert SECRET not in msg
    assert f"127.0.0.1:{port}" in msg


def test_tld_registry_stays_stdlib_only_at_import() -> None:
    """scripts/refresh_iana_tlds.py loads the module by path from a bare
    python:3.12, so the httpx / describe_http_exc imports must stay inside
    ``fetch_remote_payload``."""
    import subprocess
    import sys
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "app" / "services" / "dns" / "tld_registry.py"
    code = (
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('_t', {str(path)!r})\n"
        "m = importlib.util.module_from_spec(spec); sys.modules['_t'] = m\n"
        "spec.loader.exec_module(m)\n"
        "bad = [k for k in sys.modules if k == 'httpx' or k == 'app' or k.startswith('app.')]\n"
        "print(bad); sys.exit(1 if bad else 0)\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_tls_probe_failure_with_empty_exception_says_something(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pyOpenSSL error with no text used to store ``TLS connection failed: ``."""
    from OpenSSL import SSL

    from app.services.tls_cert import probe

    monkeypatch.setattr(probe, "_resolve_safe_ip", lambda host: ("192.0.2.1", None))

    def _boom(*a: object, **kw: object) -> list[bytes]:
        raise SSL.ZeroReturnError()

    monkeypatch.setattr(probe, "_served_chain_ders", _boom)
    outcome = probe.fetch_endpoint("h.example", 443, None, timeout=1)
    assert outcome.error and not outcome.error.rstrip().endswith(":")
    assert "ZeroReturnError" in outcome.error


@pytest.mark.parametrize(
    "text",
    [
        "bad https://h.example/services/'TOKEN",
        'bad https://h.example/services/"TOKEN',
        "bad https://h.example/p?k='TOKEN&x=1",
        "bad https://u:p'TOKEN@h.example/x",
        'bad https://u:p"TOKEN@h.example/x',
        "bad https://u:p@TOKEN@h.example/x",
        "bad https://u:p#TOKEN@h.example/x",
        "bad https://u:p/TOKEN@h.example/x",
        "bad (https://h.example/a'TOKEN)",
        "bad 'https://h.example/a'TOKEN",
        'bad "https://h.example/a"TOKEN"',
        "bad [https://h.example/a]TOKEN",
    ],
)
def test_url_reduction_fails_closed(text: str) -> None:
    out = describe_http_exc(ValueError(text))
    assert "TOKEN" not in out
    assert out.startswith("bad ")


def test_url_wrapped_in_quotes_or_brackets_keeps_the_wrapper() -> None:
    assert describe_http_exc(ValueError("see 'https://h.example/s/T'")) == "see 'https://h.example'"
    assert describe_http_exc(ValueError("see (https://u:p@h.example:8443/s)")) == (
        "see (https://h.example:8443)"
    )
    assert describe_http_exc(ValueError('x "http://h.example/a" y')) == 'x "http://h.example" y'
