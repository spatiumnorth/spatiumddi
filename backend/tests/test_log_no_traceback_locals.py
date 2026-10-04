"""Logged tracebacks never carry local variables (GHSA-4mwf-qwqg-5fw7).

structlog's stock ``dict_tracebacks`` renders every frame's locals, so an
unhandled exception in a restore logged the backup passphrase and the
database password. Type, message and frames must stay; locals must not.
"""

from __future__ import annotations

import io
import logging

import pytest
import structlog

from app.config import settings
from app.log import configure_logging

SENTINEL = "s3ntinel-passphrase-9f2c"


def _fail() -> None:
    backup_passphrase = SENTINEL  # noqa: F841 - the local under test
    raise RuntimeError("restore failed")


@pytest.mark.parametrize("fmt", ["json", "console"])
def test_traceback_has_frames_but_no_locals(monkeypatch: pytest.MonkeyPatch, fmt: str) -> None:
    monkeypatch.setattr(settings, "log_format", fmt)
    buf = io.StringIO()
    try:
        configure_logging("api", stream=buf)
        log = structlog.get_logger("t")
        try:
            _fail()
        except RuntimeError:
            log.exception("boom")
        try:
            _fail()
        except RuntimeError:
            logging.getLogger("stdlib").exception("boom2")
    finally:
        for h in list(logging.getLogger().handlers):
            if getattr(h, "stream", None) is buf:
                logging.getLogger().removeHandler(h)
    out = buf.getvalue()
    assert SENTINEL not in out
    assert "RuntimeError" in out and "restore failed" in out and "_fail" in out
    if fmt == "json":
        for line in out.splitlines():
            assert line.startswith("{")
            assert '"locals":' not in line
