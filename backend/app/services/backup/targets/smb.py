"""SMB / CIFS backup destination (issue #117 Phase 2 — Tier 2).

Writes archives to a Windows / Samba share. Authentication is
username + password against the SMB server; Kerberos is not
exposed in the form because every Tier 2 deployment we expect
(homelab NAS, small enterprise file server) terminates at NTLM
or guest. Operators who need Kerberos can revisit later.

Config shape:

* ``server`` — SMB server hostname or IP.
* ``port`` — optional, default 445.
* ``share`` — share name (the part after ``\\\\server\\``).
* ``path`` — optional subdirectory inside the share, defaults
  to the share root.
* ``username`` — required.
* ``password`` — required, **secret** (Fernet-wrapped at rest).
* ``domain`` — optional NTLM domain / workgroup.
* ``encrypt`` — optional; ``"true"`` forces SMB3 encryption.

Implementation notes:

* The driver uses ``smbprotocol`` via its high-level
  ``smbclient`` shim. Both are sync; every method wraps the
  underlying calls in :func:`asyncio.to_thread`.
* ``smbclient`` keeps a process-wide session cache keyed by
  ``server``. Calls to ``register_session`` are idempotent —
  re-registering with the same creds is a no-op. We log out
  in a ``finally`` only when ``test_connection`` opened the
  session, so live writes don't tear down a session a
  concurrent operation might need.
* Listings reuse the same archive-name regex as the other
  drivers — a share with unrelated files stays clean.
"""

from __future__ import annotations

import asyncio
import os
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


def _unc(config: dict[str, Any], filename: str | None = None) -> str:
    """Compose the ``\\\\server\\share\\path[\\filename]`` UNC path
    smbclient expects. ``safe_filename`` refuses operator-supplied
    filenames containing path separators.
    """
    server = config["server"]
    share = config["share"].strip("/\\")
    sub = (config.get("path") or "").strip("/\\")
    parts = [f"\\\\{server}\\{share}"]
    if sub:
        parts.append(sub.replace("/", "\\"))
    if filename is not None:
        parts.append(safe_filename(filename))
    return "\\".join(parts)


class SmbDestination(BackupDestination):
    kind = "smb"
    label = "SMB / CIFS"
    config_fields = (
        ConfigFieldSpec(
            name="server",
            label="Server hostname or IP",
            type="text",
            required=True,
        ),
        ConfigFieldSpec(
            name="port",
            label="Port",
            type="text",
            required=False,
            description="Default 445.",
        ),
        ConfigFieldSpec(
            name="share",
            label="Share name",
            type="text",
            required=True,
            description="The share name without leading slashes (e.g. backups).",
        ),
        ConfigFieldSpec(
            name="path",
            label="Path within share",
            type="text",
            required=False,
            description="Optional subdirectory inside the share (must already exist).",
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
            name="domain",
            label="NTLM domain / workgroup",
            type="text",
            required=False,
            description="Leave blank for standalone servers / Samba.",
        ),
        ConfigFieldSpec(
            name="encrypt",
            label="Force SMB3 encryption",
            type="text",
            required=False,
            description="'true' to force, blank/false to negotiate.",
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> None:
        for required in ("server", "share", "username", "password"):
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

    def _register(self, config: dict[str, Any]) -> str:
        """Register a smbclient session for this server. Returns
        the server hostname (smbclient's session key).
        """
        from smbclient import register_session  # noqa: PLC0415

        server = config["server"]
        username = config["username"]
        if config.get("domain"):
            username = f"{config['domain']}\\{username}"
        kwargs: dict[str, Any] = {
            "username": username,
            "password": config["password"],
        }
        if config.get("port"):
            kwargs["port"] = int(config["port"])
        encrypt = (config.get("encrypt") or "").strip().lower()
        if encrypt in {"true", "1", "yes"}:
            kwargs["encrypt"] = True
        try:
            register_session(server, **kwargs)
        except Exception as exc:  # noqa: BLE001
            raise BackupDestinationError(f"SMB connect failed: {exc}") from exc
        return server

    async def write(
        self,
        *,
        config: dict[str, Any],
        filename: str,
        archive_bytes: bytes,
    ) -> None:
        target = _unc(config, filename)
        tmp = target + ".tmp"

        def _do() -> None:
            from smbclient import open_file, remove, rename  # noqa: PLC0415

            self._register(config)
            try:
                with open_file(tmp, mode="wb") as fh:
                    fh.write(archive_bytes)
                try:
                    remove(target)
                except OSError:
                    pass  # didn't exist
                rename(tmp, target)
            except Exception as exc:  # noqa: BLE001
                raise BackupDestinationError(f"SMB write failed: {exc}") from exc

        await asyncio.to_thread(_do)

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        root = _unc(config)

        def _do() -> list[ArchiveListing]:
            from smbclient import scandir  # noqa: PLC0415

            self._register(config)
            rows: list[ArchiveListing] = []
            try:
                for entry in scandir(root):
                    if not entry.is_file() or not ARCHIVE_NAME_RE.match(entry.name):
                        continue
                    stat = entry.stat()
                    rows.append(
                        ArchiveListing(
                            filename=entry.name,
                            size_bytes=int(stat.st_size or 0),
                            created_at=datetime.fromtimestamp(stat.st_mtime, UTC),
                        )
                    )
            except FileNotFoundError as exc:
                raise BackupDestinationError(f"SMB path {root!r} not found") from exc
            except Exception as exc:  # noqa: BLE001
                raise BackupDestinationError(f"SMB scandir failed: {exc}") from exc
            rows.sort(key=lambda r: r.created_at, reverse=True)
            return rows

        return await asyncio.to_thread(_do)

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        target = _unc(config, filename)

        def _do() -> bytes:
            from smbclient import open_file  # noqa: PLC0415

            self._register(config)
            try:
                with open_file(target, mode="rb") as fh:
                    return fh.read()
            except FileNotFoundError as exc:
                raise BackupDestinationError(
                    f"archive {safe_filename(filename)!r} not found at {target}"
                ) from exc
            except Exception as exc:  # noqa: BLE001
                raise BackupDestinationError(f"SMB read failed: {exc}") from exc

        return await asyncio.to_thread(_do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        target = _unc(config, filename)

        def _do() -> None:
            from smbclient import remove  # noqa: PLC0415

            self._register(config)
            try:
                remove(target)
            except FileNotFoundError:
                return  # idempotent
            except Exception as exc:  # noqa: BLE001
                raise BackupDestinationError(f"SMB delete failed: {exc}") from exc

        await asyncio.to_thread(_do)

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            self.validate_config(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}
        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"
        probe_target = _unc(config, probe_name)

        def _do() -> dict[str, Any]:
            from smbclient import (  # noqa: PLC0415
                delete_session,
                open_file,
                remove,
                stat,
            )

            try:
                self._register(config)
            except BackupDestinationError as exc:
                return {"ok": False, "error": str(exc)}
            try:
                with open_file(probe_target, mode="wb") as fh:
                    fh.write(os.urandom(16))
                head = stat(probe_target)
                ok = (head.st_size or 0) == 16
                remove(probe_target)
            except FileNotFoundError as exc:
                return {"ok": False, "error": f"path missing: {exc}"}
            except OSError as exc:
                return {"ok": False, "error": f"smb: {exc}"}
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": str(exc)}
            finally:
                # Tear down the session test-connection opened so a
                # fresh probe doesn't accumulate stale cached creds.
                try:
                    delete_session(config["server"])
                except Exception:  # noqa: BLE001
                    pass
            if not ok:
                return {"ok": False, "error": "wrote probe but stat disagreed on size"}
            return {
                "ok": True,
                "detail": f"wrote + verified + deleted probe at {probe_target}",
            }

        return await asyncio.to_thread(_do)
