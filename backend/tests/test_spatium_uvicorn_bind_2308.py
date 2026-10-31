"""The api serves IPv4 and IPv6 clients from one image (#2308).

``uvicorn --host 0.0.0.0`` left an IPv6-only Kubernetes pod unreachable, and
``--host ::`` is IPv6-only under uvicorn (asyncio sets IPV6_V6ONLY on the
sockets it binds), which would break IPv4 clients instead. ``spatium_uvicorn``
runs uvicorn's CLI with every address family bound. These start a real server
and connect over each family, because only a connect shows which families a
listener really serves.
"""

from __future__ import annotations

import os
import pathlib
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

BACKEND = pathlib.Path(__file__).resolve().parents[1]

_APP = """
async def app(scope, receive, send):
    if scope["type"] == "http":
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
"""


def _has_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _reaches(addr: str, port: int, family: int) -> bool:
    try:
        with socket.socket(family) as c:
            c.settimeout(2)
            c.connect((addr, port))
        return True
    except OSError:
        return False


@contextmanager
def _serve(tmp_path: pathlib.Path, *args: str, **env: str) -> Iterator[int]:
    (tmp_path / "bind_app_2308.py").write_text(_APP)
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "-m", "spatium_uvicorn", "bind_app_2308:app", "--port", str(port), *args],
        cwd=BACKEND,
        env={
            **{k: v for k, v in os.environ.items() if k not in ("UVICORN_HOST", "API_BIND_HOST")},
            "PYTHONPATH": f"{BACKEND}:{tmp_path}",
            **env,
        },
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 30
        while not _reaches("127.0.0.1", port, socket.AF_INET) and not (
            _has_ipv6_loopback() and _reaches("::1", port, socket.AF_INET6)
        ):
            assert proc.poll() is None, proc.communicate()[0].decode()
            assert time.monotonic() < deadline, "server did not start"
            time.sleep(0.1)
        yield port
    finally:
        proc.terminate()
        proc.wait(timeout=10)


@pytest.mark.skipif(not _has_ipv6_loopback(), reason="no IPv6 loopback in this environment")
def test_default_bind_serves_ipv4_and_ipv6(tmp_path: pathlib.Path) -> None:
    with _serve(tmp_path) as port:
        assert _reaches("127.0.0.1", port, socket.AF_INET), "IPv4 clients must still work"
        assert _reaches("::1", port, socket.AF_INET6), "IPv6 clients must work"


def test_default_bind_is_not_loopback_only(tmp_path: pathlib.Path) -> None:
    """uvicorn's own default is 127.0.0.1; the wrapper must replace it."""
    with _serve(tmp_path) as port:
        addrs = {
            a[4][0]
            for a in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
            if not a[4][0].startswith("127.")
        }
        if not addrs:
            pytest.skip("no non-loopback IPv4 address to probe")
        assert _reaches(sorted(addrs)[0], port, socket.AF_INET)


def test_api_bind_host_pins_one_address(tmp_path: pathlib.Path) -> None:
    with _serve(tmp_path, API_BIND_HOST="127.0.0.1") as port:
        assert _reaches("127.0.0.1", port, socket.AF_INET)
        if _has_ipv6_loopback():
            assert not _reaches("::1", port, socket.AF_INET6)


def test_explicit_host_flag_is_respected(tmp_path: pathlib.Path) -> None:
    with _serve(tmp_path, "--host", "127.0.0.1") as port:
        assert _reaches("127.0.0.1", port, socket.AF_INET)
        if _has_ipv6_loopback():
            assert not _reaches("::1", port, socket.AF_INET6)


@pytest.mark.parametrize(
    ("args", "env"),
    [(("--workers", "2"), {}), ((), {"WEB_CONCURRENCY": "2"})],
    ids=["--workers", "WEB_CONCURRENCY"],
)
def test_more_than_one_worker_still_starts(
    tmp_path: pathlib.Path, args: tuple[str, ...], env: dict[str, str]
) -> None:
    """uvicorn binds ONE socket in the parent for multiple workers
    (``Config.bind_socket``), which raises TypeError on a ``None`` host. The
    wrapper keeps the pre-#2308 IPv4 wildcard there instead of crashing."""
    with _serve(tmp_path, *args, **env) as port:
        assert _reaches("127.0.0.1", port, socket.AF_INET)


def test_runtime_image_runs_the_wrapper_without_a_host_literal() -> None:
    dockerfile = BACKEND / "Dockerfile"
    cmd = [ln for ln in dockerfile.read_text().splitlines() if ln.startswith("CMD [")]
    assert len(cmd) == 1
    assert "spatium_uvicorn" in cmd[0]
    assert "0.0.0.0" not in cmd[0] and "--host" not in cmd[0]
