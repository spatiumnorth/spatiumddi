"""A slot image download that ends early is detected and retried (#1216).

``fetch_to`` used to read until the connection returned no more data and
never compared the bytes received with ``Content-Length``. ``http.client``
returns a short body without complaint when the peer closes early, so a
download cut mid-transfer left a partial image on disk that the sha256
check then refused as "checksum mismatch". That is what a node sees when
the frontend pod serving its download is replaced during a rolling
upgrade (#1215): nginx is killed at the end of its grace period and the
stream simply stops.

These tests drive the real ``fetch_to`` and ``_fetch_image`` against a
local HTTP server that can promise a length and close early, honour or
ignore ``Range``, and answer an error status. Stdlib only, no network
beyond 127.0.0.1. The TLS tests also need the ``openssl`` CLI, to make a
throwaway self-signed certificate.
"""

from __future__ import annotations

import builtins
import errno
import http.server
import importlib.util
import io
import os
import shutil
import ssl
import subprocess
import threading
import urllib.error
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

SCRIPT = (
    Path(__file__).parent.parent
    / "mkosi.extra"
    / "usr"
    / "local"
    / "bin"
    / "spatium-upgrade-slot"
)

BODY = bytes(range(256)) * 4096  # 1 MiB, every byte position distinct mod 256


@pytest.fixture()
def slot_cli(tmp_path, monkeypatch):
    """Import the extensionless CLI, with no backoff and progress in tmp."""
    loader = SourceFileLoader("spatium_upgrade_slot_fetch", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    monkeypatch.setattr(module, "_FETCH_BACKOFF_SECONDS", (0, 0, 0, 0))
    monkeypatch.setattr(module, "_PROGRESS_FILE", tmp_path / "slot-upgrade.progress")
    return module


class _Server:
    """Serves BODY. Each request takes the next scripted plan (the last one
    repeats), and every request's headers are recorded.

    Plans: ("full",) = 200 with the whole body, Range ignored;
    ("cut", n) = 200 promising the whole body, n bytes sent, then closed;
    ("range",) = 206 from the requested offset when a Range is asked for,
    else like "full"; ("range_lc",) = the same, its ``content-range``
    header name in lower case; ("range_short", end) = 206 from the
    requested offset but stopping at ``end``; ("range_at", start) = 206
    from ``start`` whatever was asked; ("range_whole",) = 206 with the
    whole body whatever was asked; ("stall", n) = 200 promising the whole
    body, n bytes sent, then nothing until the server closes;
    ("status", code) = that error status.

    With ``tls`` the server speaks HTTPS with that context; the first
    ``drop_first`` connections are closed before their handshake. Every
    accepted connection is counted, handshake or not.
    """

    def __init__(self, plans, tls: ssl.SSLContext | None = None, drop_first: int = 0):
        self.plans = list(plans)
        self.requests: list[dict[str, str]] = []
        self.connections = 0
        self.release = threading.Event()  # ends a "stall"
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # keep pytest output clean
                pass

            def do_GET(self):
                server.requests.append(dict(self.headers))
                plan = server.plans.pop(0) if len(server.plans) > 1 else server.plans[0]
                kind = plan[0]
                if kind == "status":
                    self.send_error(plan[1])
                    return
                asked = self.headers.get("Range")
                offset = int(asked.split("=")[1].rstrip("-")) if asked else None
                span = None  # the 206's [start, end) of BODY
                if kind in ("range", "range_lc") and offset is not None:
                    span = (offset, len(BODY))
                elif kind == "range_short" and offset is not None:
                    span = (offset, plan[1])
                elif kind == "range_at":
                    span = (plan[1], len(BODY))
                elif kind == "range_whole":
                    span = (0, len(BODY))
                start, end = span or (0, len(BODY))
                if span:
                    self.send_response(206)
                    self.send_header(
                        "content-range" if kind == "range_lc" else "Content-Range",
                        f"bytes {start}-{end - 1}/{len(BODY)}",
                    )
                else:
                    self.send_response(200)
                body = BODY[start:end]
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if kind == "cut":
                    self.wfile.write(body[: plan[1]])
                    self.wfile.flush()
                    self.close_connection = True  # FIN after n bytes, as a killed nginx
                    return
                if kind == "stall":
                    self.wfile.write(body[: plan[1]])
                    self.wfile.flush()
                    server.release.wait(30)  # the connection stays open, silent
                    self.close_connection = True
                    return
                self.wfile.write(body)

        class Quiet(http.server.ThreadingHTTPServer):
            def get_request(self):
                sock, addr = super().get_request()
                server.connections += 1
                if tls is None:
                    return sock, addr
                if server.connections <= drop_first:
                    sock.close()  # gone before the handshake, as a replaced frontend pod
                    raise OSError("dropped before the TLS handshake")
                # A handshake the client refuses raises here; serve_forever
                # drops the connection and carries on.
                return tls.wrap_socket(sock, server_side=True), addr

            def handle_error(self, request, client_address):
                pass  # a client hanging up mid-response is the point of these tests

        self.httpd = Quiet(("127.0.0.1", 0), Handler)
        scheme = "https" if tls is not None else "http"
        self.url = f"{scheme}://127.0.0.1:{self.httpd.server_address[1]}/raw.xz?t=token"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.release.set()
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def serve():
    servers: list[_Server] = []

    def start(*plans, **kwargs):
        s = _Server(plans, **kwargs)
        servers.append(s)
        return s

    yield start
    for s in servers:
        s.close()


@pytest.fixture(scope="module")
def self_signed_tls(tmp_path_factory):
    """A server context with a throwaway self-signed certificate: what an
    external image URL looks like to a node that cannot verify it."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("the openssl CLI is needed to make a self-signed certificate")
    d = tmp_path_factory.mktemp("tls")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=127.0.0.1", "-keyout", str(key), "-out", str(cert)],
        check=True,
        capture_output=True,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    return ctx


# ── the defect, pinned ──────────────────────────────────────────────


def test_a_cut_download_is_never_taken_for_a_whole_one(slot_cli, serve, tmp_path, monkeypatch):
    """7ad8fbd returned normally here with half the image on disk."""
    monkeypatch.setattr(slot_cli, "_FETCH_ATTEMPTS", 1)
    s = serve(("cut", len(BODY) // 2))
    dst = tmp_path / "slot.raw.xz"
    with pytest.raises(slot_cli.DownloadFailed, match=r"received 524288 of 1048576 bytes"):
        slot_cli.fetch_to(s.url, dst)


# ── retries ─────────────────────────────────────────────────────────


def test_a_complete_download_is_one_request_without_range(slot_cli, serve, tmp_path):
    s = serve(("full",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst, report=True)
    assert dst.read_bytes() == BODY
    assert len(s.requests) == 1
    assert "Range" not in s.requests[0]


def test_a_cut_download_is_retried_and_arrives_whole(slot_cli, serve, tmp_path):
    """The server ignores Range, as the multi-node path does (the api
    proxies the mirror with a plain GET): the retry starts over."""
    s = serve(("cut", 400_000), ("full",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst, report=True)
    assert dst.read_bytes() == BODY
    assert len(s.requests) == 2
    assert s.requests[1].get("Range") == "bytes=400000-"


def test_a_retry_resumes_when_the_server_honours_range(slot_cli, serve, tmp_path):
    s = serve(("cut", 400_000), ("range",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert s.requests[1].get("Range") == "bytes=400000-"


def test_a_transfer_that_never_completes_fails_with_its_count(slot_cli, serve, tmp_path):
    s = serve(("cut", 1000))
    dst = tmp_path / "slot.raw.xz"
    with pytest.raises(slot_cli.DownloadFailed, match=r"after 5 attempts"):
        slot_cli.fetch_to(s.url, dst)
    assert len(s.requests) == 5


def test_a_5xx_is_retried(slot_cli, serve, tmp_path):
    s = serve(("status", 503), ("full",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert len(s.requests) == 2


def test_a_4xx_is_an_answer_and_is_not_retried(slot_cli, serve, tmp_path):
    s = serve(("status", 404))
    dst = tmp_path / "slot.raw.xz"
    with pytest.raises(urllib.error.HTTPError) as err:
        slot_cli.fetch_to(s.url, dst)
    assert err.value.code == 404
    assert len(s.requests) == 1


def test_a_partial_file_from_an_earlier_run_is_never_resumed(slot_cli, serve, tmp_path):
    """It may belong to a different image: the fetch starts from nothing."""
    s = serve(("range",))
    dst = tmp_path / "slot.raw.xz"
    dst.write_bytes(b"stale bytes from another image")
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert "Range" not in s.requests[0]


def test_a_local_write_error_is_raised_at_once(slot_cli, serve, tmp_path, monkeypatch):
    """A full disk is not a transfer problem; retrying it only wastes time."""
    s = serve(("full",))
    dst = tmp_path / "slot.raw.xz"

    def refuse(*args, **kwargs):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr("builtins.open", refuse)
    with pytest.raises(slot_cli._LocalWriteError, match="No space left"):
        slot_cli.fetch_to(s.url, dst)
    assert len(s.requests) == 1


def test_a_full_disk_at_the_final_flush_is_raised_at_once(slot_cli, serve, tmp_path, monkeypatch):
    """Closing the staged file flushes its last buffered bytes, which can
    meet a full disk too. That is a local write error like any other,
    raised at once, not transfer trouble retried until rc 6."""
    s = serve(("full",))
    dst = tmp_path / "slot.raw.xz"

    class FullDisk(io.RawIOBase):
        def writable(self):
            return True

        def write(self, b):
            raise OSError(errno.ENOSPC, "No space left on device")

    real_open = builtins.open

    def open_on_a_full_disk(file, *args, **kwargs):
        if isinstance(file, (str, os.PathLike)) and Path(file) == dst:
            # A buffer larger than the body holds every write(); only the
            # flush when the file closes reaches the disk.
            return io.BufferedWriter(FullDisk(), buffer_size=2 * len(BODY))
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", open_on_a_full_disk)
    with pytest.raises(slot_cli._LocalWriteError, match="No space left"):
        slot_cli.fetch_to(s.url, dst)
    assert len(s.requests) == 1


def test_a_stalled_read_is_still_retried(slot_cli, serve, tmp_path, monkeypatch):
    """A read that stops moving times out. That is transfer trouble, and is
    retried: only the file's own calls count as local write errors."""
    monkeypatch.setattr(slot_cli, "_FETCH_READ_TIMEOUT_SECONDS", 0.5)
    s = serve(("stall", 400_000), ("full",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert len(s.requests) == 2


# ── a resume is kept only when it continues the partial file ─────────


def test_a_resume_answered_from_another_offset_is_not_saved_as_the_whole_file(
    slot_cli, serve, tmp_path, capsys
):
    """A 206 that does not start at the byte asked for can neither continue
    the partial file nor stand for the whole image. It used to be written
    from byte 0 as the whole file, which the checksum then failed as
    "checksum mismatch" (rc 3). Now the partial file is discarded and the
    next attempt asks for the whole image."""
    s = serve(("cut", 400_000), ("range_at", 200_000), ("full",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert [r.get("Range") for r in s.requests] == [None, "bytes=400000-", None]
    out = capsys.readouterr().out
    assert "resume from byte 400000" in out
    assert "bytes 200000-1048575/1048576" in out


def test_a_resumed_range_that_stops_short_is_resumed_again(slot_cli, serve, tmp_path):
    """A 206 is counted against the whole file's length (the ``/n`` of its
    Content-Range), not its own Content-Length, so a range that stops
    before the end is not taken for the rest of the file."""
    s = serve(("cut", 400_000), ("range_short", 700_000), ("range",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert [r.get("Range") for r in s.requests] == [None, "bytes=400000-", "bytes=700000-"]


def test_a_resume_is_kept_whatever_the_header_case(slot_cli, serve, tmp_path):
    """Header names are case-insensitive, and an ASGI server (the api that
    serves a node's own image) sends ``content-range`` in lower case. The
    resume is kept: two requests, no restart."""
    s = serve(("cut", 400_000), ("range_lc",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert len(s.requests) == 2


def test_a_206_with_the_whole_file_is_kept(slot_cli, serve, tmp_path):
    """Even unasked, a 206 that starts at byte 0 and runs to the end is the
    whole image, and is kept."""
    s = serve(("range_whole",))
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert len(s.requests) == 1


# ── a certificate failure is configuration, not a dropped transfer ──


def test_a_certificate_the_node_cannot_verify_is_raised_at_once(
    slot_cli, serve, tmp_path, self_signed_tls, capsys
):
    """A verified fetch (an external image URL) that meets a certificate it
    cannot verify fails at once. Retrying cannot fix it: it only added 75 s
    of backoff before an rc 6 that said the download was interrupted.
    urlopen wraps the error in URLError, which is an OSError."""
    s = serve(("full",), tls=self_signed_tls)
    dst = tmp_path / "slot.raw.xz"
    with pytest.raises(urllib.error.URLError) as err:
        slot_cli.fetch_to(s.url, dst)
    assert isinstance(err.value.reason, ssl.SSLCertVerificationError)
    assert s.connections == 1
    assert "retrying" not in capsys.readouterr().out


def test_an_unwrapped_certificate_error_is_raised_at_once(slot_cli, tmp_path, monkeypatch):
    calls = []

    def refuse(*args, **kwargs):
        calls.append(1)
        raise ssl.SSLCertVerificationError(
            1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed"
        )

    monkeypatch.setattr(slot_cli, "_fetch_http_once", refuse)
    with pytest.raises(ssl.SSLCertVerificationError):
        slot_cli.fetch_to("https://127.0.0.1:9/raw.xz", tmp_path / "slot.raw.xz")
    assert len(calls) == 1


def test_the_self_served_fetch_still_skips_verification(slot_cli, serve, tmp_path, self_signed_tls):
    """The node's own image URL is behind its self-signed web certificate.
    It is fetched unverified and the bytes are checked against the sha256
    instead (#386), so the certificate is never a reason to refuse it."""
    s = serve(("full",), tls=self_signed_tls)
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst, insecure=True)
    assert dst.read_bytes() == BODY


def test_a_tls_handshake_cut_short_is_still_retried(slot_cli, serve, tmp_path, self_signed_tls):
    """Only a certificate failure is raised at once. A connection that drops
    during the handshake is transfer trouble, and is retried."""
    s = serve(("full",), tls=self_signed_tls, drop_first=1)
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst, insecure=True)
    assert dst.read_bytes() == BODY
    assert s.connections == 2


def test_a_refused_connection_is_still_retried(slot_cli, serve, tmp_path, monkeypatch):
    """What the live drills saw on the attempt after the cut, while the
    node's replacement frontend pod was not serving yet."""
    s = serve(("full",))
    real = slot_cli._fetch_http_once
    calls = []

    def refused_once(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            raise urllib.error.URLError(ConnectionRefusedError(111, "Connection refused"))
        return real(*args, **kwargs)

    monkeypatch.setattr(slot_cli, "_fetch_http_once", refused_once)
    dst = tmp_path / "slot.raw.xz"
    slot_cli.fetch_to(s.url, dst)
    assert dst.read_bytes() == BODY
    assert len(calls) == 2


def test_the_progress_sidecar_names_the_retry(slot_cli, serve, tmp_path):
    s = serve(("cut", 400_000), ("full",))
    slot_cli.fetch_to(s.url, tmp_path / "slot.raw.xz", report=True)
    # The last write is the completed second attempt.
    assert "(attempt 2 of 5)" in (tmp_path / "slot-upgrade.progress").read_text()


# ── what cmd_apply does with it ─────────────────────────────────────


def test_an_interrupted_fetch_returns_6_and_leaves_no_partial_image(slot_cli, serve, tmp_path, capsys):
    s = serve(("cut", 1000))
    staged = tmp_path / "slot.raw.xz"
    assert slot_cli._fetch_image(s.url, staged, insecure=False) == 6
    assert not staged.exists()
    err = capsys.readouterr().err
    assert "download interrupted after 5 attempts" in err
    assert "Nothing was written to the inactive slot" in err


def test_a_good_fetch_returns_0(slot_cli, serve, tmp_path):
    s = serve(("full",))
    staged = tmp_path / "slot.raw.xz"
    assert slot_cli._fetch_image(s.url, staged, insecure=False) == 0
    assert staged.read_bytes() == BODY


# ── what the wrapper reports ────────────────────────────────────────

RUNNER = SCRIPT.parent / "spatiumddi-slot-upgrade"


def test_the_wrapper_names_an_interrupted_download(tmp_path):
    """rc 6 is reported as an interrupted download with nothing written, not
    as the generic "apply failed … download / verify / write" of rc 3."""
    import os
    import subprocess

    stub = tmp_path / "spatium-upgrade-slot"
    stub.write_text("#!/bin/bash\nexit 6\n", encoding="utf-8")
    stub.chmod(0o755)
    trigger = tmp_path / "slot-upgrade-pending"
    trigger.write_text("https://example/img.raw.xz\n", encoding="utf-8")
    env = {
        **os.environ,
        "SPATIUM_SLOT_TRIGGER": str(trigger),
        "SPATIUM_SLOT_PROGRESS": str(tmp_path / "slot-upgrade.progress"),
        "SPATIUM_SLOT_LOG_DIR": str(tmp_path / "log"),
        "SPATIUM_UPGRADE_SLOT_BIN": str(stub),
        "SPATIUM_SLOT_TICK_SECONDS": "1",
    }
    subprocess.run(["bash", str(RUNNER)], env=env, capture_output=True, timeout=30, check=False)
    state = (tmp_path / "slot-upgrade-pending.state").read_text(encoding="utf-8")
    assert state.startswith("failed ")
    progress = (tmp_path / "slot-upgrade.progress").read_text(encoding="utf-8")
    assert "download was interrupted" in progress
    assert "rc=6" in progress
    assert "nothing was written to the inactive slot" in progress
