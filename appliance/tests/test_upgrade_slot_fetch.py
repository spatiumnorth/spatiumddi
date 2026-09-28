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
beyond 127.0.0.1.
"""

from __future__ import annotations

import http.server
import importlib.util
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
    else like "full"; ("status", code) = that error status.
    """

    def __init__(self, plans):
        self.plans = list(plans)
        self.requests: list[dict[str, str]] = []
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
                start = 0
                if kind == "range" and self.headers.get("Range"):
                    start = int(self.headers["Range"].split("=")[1].rstrip("-"))
                    self.send_response(206)
                    self.send_header(
                        "Content-Range", f"bytes {start}-{len(BODY) - 1}/{len(BODY)}"
                    )
                else:
                    self.send_response(200)
                body = BODY[start:]
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if kind == "cut":
                    self.wfile.write(body[: plan[1]])
                    self.wfile.flush()
                    self.close_connection = True  # FIN after n bytes, as a killed nginx
                    return
                self.wfile.write(body)

        class Quiet(http.server.ThreadingHTTPServer):
            def handle_error(self, request, client_address):
                pass  # a client hanging up mid-response is the point of these tests

        self.httpd = Quiet(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/raw.xz?t=token"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture()
def serve():
    servers: list[_Server] = []

    def start(*plans):
        s = _Server(plans)
        servers.append(s)
        return s

    yield start
    for s in servers:
        s.close()


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
