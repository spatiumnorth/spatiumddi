"""FTP / FTPS backup destination (issue #117 Phase 2 — Tier 2).

Writes archives to a remote host via FTP, FTPS-explicit
(``AUTH TLS``), or FTPS-implicit (port 990 wrapped in TLS from
the start). Uses the stdlib :mod:`ftplib` so there's no new
dependency — every Tier 2 deployment we expect (legacy NAS,
internal file server) speaks one of those three modes.

Config shape:

* ``host`` — required.
* ``port`` — optional; defaults to 21 for ftp/ftps_explicit and
  990 for ftps_implicit.
* ``username`` — required.
* ``password`` — required, **secret** (Fernet-wrapped at rest).
* ``remote_path`` — required, absolute path on the server.
* ``mode`` — ``"ftp"`` (default), ``"ftps_explicit"``, or
  ``"ftps_implicit"``.
* ``passive`` — ``"true"`` (default) for PASV, ``"false"`` for
  active. Most NATs need PASV.
* ``verify_tls`` — ``"true"`` (default) when ``mode`` is one of
  the FTPS variants; set ``"false"`` for self-signed labs.

Implementation notes:

* :mod:`ftplib` is sync; every method wraps the underlying
  calls in :func:`asyncio.to_thread`.
* ``FTP_TLS.implicit_tls`` is the right knob for FTPS-implicit
  on 3.12+; pre-3.12 had to subclass and override ``connect``.
* The driver does NOT auto-create ``remote_path``. Operators
  set this explicitly so a typo can't sprinkle backup files at
  the wrong directory.
* The control connection is closed in a ``finally`` so a slow
  remote can't leak FDs across calls.
"""

from __future__ import annotations

import asyncio
import io
import os
import ssl
from datetime import UTC, datetime
from typing import Any

import structlog

from app.services.backup.targets.base import (
    ARCHIVE_NAME_RE,
    ArchiveListing,
    BackupDestination,
    BackupDestinationError,
    ConfigFieldSpec,
    DestinationConfigError,
    safe_filename,
)

logger = structlog.get_logger(__name__)


_MODES = {"ftp", "ftps_explicit", "ftps_implicit"}

# Same generous budget as the SCP driver — FTP servers vary wildly
# in latency, particularly older NAS gear.
_FTP_TIMEOUT = 60


class FtpDestination(BackupDestination):
    kind = "ftp"
    label = "FTP / FTPS"
    config_fields = (
        ConfigFieldSpec(
            name="host",
            label="Hostname or IP",
            type="text",
            required=True,
        ),
        ConfigFieldSpec(
            name="port",
            label="Port",
            type="text",
            required=False,
            description="Default 21 (ftp / ftps_explicit) or 990 (ftps_implicit).",
        ),
        ConfigFieldSpec(
            name="username",
            label="Username",
            type="text",
            required=True,
        ),
        ConfigFieldSpec(
            name="password",
            label="Password",
            type="password",
            required=True,
            secret=True,
        ),
        ConfigFieldSpec(
            name="remote_path",
            label="Remote path",
            type="text",
            required=True,
            description="Absolute path on the server (must already exist).",
        ),
        ConfigFieldSpec(
            name="mode",
            label="Transport mode",
            type="text",
            required=False,
            description="'ftp' (default), 'ftps_explicit' (AUTH TLS), or 'ftps_implicit' (port 990).",
        ),
        ConfigFieldSpec(
            name="passive",
            label="Passive mode (PASV)",
            type="text",
            required=False,
            description="'true' (default) for PASV. Set 'false' for active mode.",
        ),
        ConfigFieldSpec(
            name="verify_tls",
            label="Verify TLS certificate",
            type="text",
            required=False,
            description="'true' (default) for FTPS modes. Set 'false' for self-signed labs.",
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> None:
        for required in ("host", "username", "password", "remote_path"):
            value = config.get(required)
            if not value or not isinstance(value, str):
                raise DestinationConfigError(
                    f"{required!r} is required and must be a non-empty string"
                )
        port = config.get("port")
        if port is not None and port != "":
            try:
                port_n = int(port)
            except (TypeError, ValueError) as exc:
                raise DestinationConfigError(f"'port' must be a number ({exc})") from exc
            if not 1 <= port_n <= 65535:
                raise DestinationConfigError("'port' must be 1..65535")
        if not config["remote_path"].startswith("/"):
            raise DestinationConfigError("'remote_path' must be absolute")
        mode = (config.get("mode") or "ftp").strip().lower()
        if mode not in _MODES:
            raise DestinationConfigError(f"'mode' must be one of {sorted(_MODES)} (got {mode!r})")

    def _connect(self, config: dict[str, Any]):
        """Build + return an open ``ftplib.FTP`` (or ``FTP_TLS``)
        client. Caller closes via ``client.quit()`` / ``close()``.
        """
        from ftplib import FTP, FTP_TLS  # noqa: PLC0415

        mode = (config.get("mode") or "ftp").strip().lower()
        verify = (config.get("verify_tls") or "true").strip().lower() != "false"
        host = config["host"]
        port = int(config.get("port") or (990 if mode == "ftps_implicit" else 21))

        ctx: ssl.SSLContext | None = None
        if mode in {"ftps_explicit", "ftps_implicit"}:
            ctx = ssl.create_default_context()
            # Pin to TLS 1.2+ explicitly. Modern OpenSSL already
            # disables 1.0 / 1.1 by default, but being explicit closes
            # CodeQL py/insecure-protocol and makes the contract
            # obvious to readers.
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                # Operator opted out of TLS verification for this backup
                # target. Surface it whenever we connect so the insecure
                # posture is visible in the centralized logs (#5); the
                # who/when of enabling it lives in the target's audit row.
                logger.warning("ftp_tls_verification_disabled", host=config.get("host"), mode=mode)

        try:
            if mode == "ftps_implicit":
                client = FTP_TLS(context=ctx, timeout=_FTP_TIMEOUT)
                # Implicit-mode TLS wraps the control connection
                # before any FTP commands. ftplib's FTP_TLS doesn't
                # do this on its own; we have to wrap the socket
                # right after ``connect`` and before ``login``.
                client.connect(host=host, port=port)
                # ``client.sock`` is annotated ``socket | None``;
                # ``connect`` populates it. Assert for the type-
                # narrow.
                assert client.sock is not None
                assert ctx is not None
                client.sock = ctx.wrap_socket(
                    client.sock,
                    server_hostname=host,
                )
                client.file = client.sock.makefile("r", encoding=client.encoding)
                client.welcome = client.getresp()
                client.login(config["username"], config["password"])
                client.prot_p()
            elif mode == "ftps_explicit":
                client = FTP_TLS(context=ctx, timeout=_FTP_TIMEOUT)
                client.connect(host=host, port=port)
                client.login(config["username"], config["password"])
                client.prot_p()
            else:
                client = FTP(timeout=_FTP_TIMEOUT)
                client.connect(host=host, port=port)
                client.login(config["username"], config["password"])
        except Exception as exc:  # noqa: BLE001
            raise BackupDestinationError(f"FTP connect failed: {exc}") from exc

        passive = (config.get("passive") or "true").strip().lower() != "false"
        client.set_pasv(passive)
        return client

    @staticmethod
    def _close(client) -> None:
        try:
            client.quit()
        except Exception:  # noqa: BLE001
            try:
                client.close()
            except Exception:  # noqa: BLE001
                pass

    async def write(
        self,
        *,
        config: dict[str, Any],
        filename: str,
        archive_bytes: bytes,
    ) -> None:
        safe = safe_filename(filename)
        remote = config["remote_path"].rstrip("/") + "/" + safe
        tmp = remote + ".tmp"

        def _do() -> None:
            client = self._connect(config)
            try:
                # Atomic-ish: STOR to .tmp, DELE existing target,
                # RNFR/RNTO into place. Mirrors the SCP driver.
                client.storbinary(f"STOR {tmp}", io.BytesIO(archive_bytes))
                try:
                    client.delete(remote)
                except Exception:  # noqa: BLE001
                    pass
                client.rename(tmp, remote)
            except Exception as exc:  # noqa: BLE001
                # Best-effort cleanup of the staged file (#1570),
                # mirroring the NFS driver: listing and retention only
                # match ``*.zip``, so a leftover ``.tmp`` is invisible
                # and is never pruned — every failed run on a full
                # destination would leave another orphan behind.
                try:
                    client.delete(tmp)
                except Exception as cleanup_exc:  # noqa: BLE001
                    # A 550 just means the failure happened before the
                    # staged file existed — nothing to clean up.
                    if not str(cleanup_exc).startswith("550"):
                        logger.warning(
                            "ftp_partial_cleanup_failed",
                            path=tmp,
                            error=str(cleanup_exc),
                        )
                raise BackupDestinationError(f"FTP write failed: {exc}") from exc
            finally:
                self._close(client)

        await asyncio.to_thread(_do)

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        remote_path = config["remote_path"].rstrip("/") or "/"

        def _do() -> list[ArchiveListing]:
            client = self._connect(config)
            try:
                # MLSD is the modern, parse-stable directory listing
                # (RFC 3659). Most servers post-2010 support it; we
                # fall back to LIST for legacy ones.
                rows: list[ArchiveListing] = []
                try:
                    entries = list(client.mlsd(remote_path))
                    for name, facts in entries:
                        if facts.get("type") not in {"file", "OS.unix=symlink"}:
                            continue
                        if not ARCHIVE_NAME_RE.match(name):
                            continue
                        size = int(facts.get("size", 0) or 0)
                        modify = facts.get("modify")  # YYYYMMDDhhmmss UTC
                        if not modify:
                            continue
                        try:
                            ts = datetime.strptime(modify[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)
                        except ValueError:
                            continue
                        rows.append(
                            ArchiveListing(
                                filename=name,
                                size_bytes=size,
                                created_at=ts,
                            )
                        )
                except Exception:  # noqa: BLE001
                    # Fallback: LIST + per-file SIZE + MDTM
                    raw_lines: list[str] = []
                    client.retrlines(f"LIST {remote_path}", raw_lines.append)
                    for line in raw_lines:
                        name = line.rsplit(" ", 1)[-1]
                        if not ARCHIVE_NAME_RE.match(name):
                            continue
                        try:
                            size_resp = client.sendcmd(f"SIZE {remote_path}/{name}").split(" ", 1)
                            size = int(size_resp[1]) if len(size_resp) > 1 else 0
                            mdtm = client.sendcmd(f"MDTM {remote_path}/{name}").split(" ", 1)[1]
                            ts = datetime.strptime(mdtm[:14], "%Y%m%d%H%M%S").replace(tzinfo=UTC)
                        except Exception:  # noqa: BLE001
                            continue
                        rows.append(
                            ArchiveListing(
                                filename=name,
                                size_bytes=size,
                                created_at=ts,
                            )
                        )
            except Exception as exc:  # noqa: BLE001
                raise BackupDestinationError(f"FTP listing failed: {exc}") from exc
            finally:
                self._close(client)
            rows.sort(key=lambda r: r.created_at, reverse=True)
            return rows

        return await asyncio.to_thread(_do)

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        safe = safe_filename(filename)
        remote = config["remote_path"].rstrip("/") + "/" + safe

        def _do() -> bytes:
            client = self._connect(config)
            try:
                buf = io.BytesIO()
                client.retrbinary(f"RETR {remote}", buf.write)
                return buf.getvalue()
            except Exception as exc:  # noqa: BLE001
                raise BackupDestinationError(f"FTP read failed: {exc}") from exc
            finally:
                self._close(client)

        return await asyncio.to_thread(_do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        safe = safe_filename(filename)
        remote = config["remote_path"].rstrip("/") + "/" + safe

        def _do() -> None:
            client = self._connect(config)
            try:
                client.delete(remote)
            except Exception as exc:  # noqa: BLE001
                msg = str(exc)
                # 550 = file not found ⇒ idempotent
                if msg.startswith("550"):
                    return
                raise BackupDestinationError(f"FTP delete failed: {exc}") from exc
            finally:
                self._close(client)

        await asyncio.to_thread(_do)

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            self.validate_config(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}
        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"
        remote_path = config["remote_path"].rstrip("/") or "/"
        probe_remote = f"{remote_path}/{probe_name}"

        def _do() -> dict[str, Any]:
            try:
                client = self._connect(config)
            except BackupDestinationError as exc:
                return {"ok": False, "error": str(exc)}
            try:
                client.cwd(remote_path)
                client.storbinary(f"STOR {probe_remote}", io.BytesIO(os.urandom(16)))
                size = client.size(probe_remote)
                ok = (size or 0) == 16
                client.delete(probe_remote)
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": f"ftp: {exc}"}
            finally:
                self._close(client)
            if not ok:
                return {
                    "ok": False,
                    "error": "wrote probe but SIZE disagreed",
                }
            return {
                "ok": True,
                "detail": f"wrote + verified + deleted probe at {probe_remote}",
            }

        return await asyncio.to_thread(_do)
