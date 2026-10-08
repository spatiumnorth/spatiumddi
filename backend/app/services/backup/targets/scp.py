"""SCP / SFTP backup destination (issue #117 Phase 1d).

Writes archives to a remote host via SSH. Authentication is
either password or private-key (ED25519 / ECDSA / RSA / DSS —
whatever paramiko supports). Both creds are Fernet-wrapped at
rest via :mod:`secrets_config` because they're declared
``secret=True`` in the config-fields spec.

Config shape:

* ``host`` — required.
* ``port`` — optional, default 22.
* ``username`` — required.
* ``remote_path`` — required, absolute path on the remote.
* ``password`` — optional (use one of password / private_key).
* ``private_key`` — optional, PEM-encoded. **Secret.**
* ``private_key_passphrase`` — optional, **secret.** Only set
  when the key itself is passphrase-protected.
* ``host_key_check`` — ``"known_hosts"`` (default — refuse
  hosts not in the operator-supplied ``known_hosts``),
  ``"strict"`` (the same check under its historical name;
  also uses the supplied ``known_hosts``), or
  ``"insecure_skip"`` (homelab/lab shortcut, *not*
  recommended for production).
* ``known_hosts`` — the OpenSSH known_hosts content. Required
  for the checked modes: the driver loads no system host keys,
  so a checked mode with no supplied keys has an empty store
  and would refuse every server (#1569).

Implementation notes:

* paramiko is sync; every method wraps the underlying calls in
  ``asyncio.to_thread`` so a slow remote can't block the
  asyncio event loop.
* SSH connections are NOT pooled per target — connection setup
  is fast (~50 ms on a LAN, a few seconds across the WAN), and
  a long-lived pool would have to handle reconnect-after-idle
  / host-key-rotation / credential-rotation events. Open a
  fresh connection per operation; close in a ``finally`` so
  exceptions never leak FDs.
* SFTP is preferred over SCP — modern OpenSSH ships SFTP by
  default, and paramiko's SFTP API is much easier to drive
  for "list directory + delete file" than scping a tarball.
* The remote path must already exist; the driver will not
  ``mkdir -p`` it. Operators set this explicitly.
"""

from __future__ import annotations

import asyncio
import io
import os
import stat as stat_mod
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


_HOST_KEY_MODES = {"strict", "known_hosts", "insecure_skip"}

# Connection budget. SCP / SFTP has more variance than S3 since the
# remote may be a small home NAS over a residential link. 30 s
# connect, 5 min total per op covers everything except a degenerate
# situation where pg_dump itself is slow (handled separately by the
# build_backup_archive timeout).
_SSH_CONNECT_TIMEOUT = 30
_SSH_BANNER_TIMEOUT = 30
# Per-operation ceiling on the SFTP channel (#1515). connect / banner /
# auth timeouts were set, but the channel itself had none, so a server
# that stalls mid-transfer hung the backup run indefinitely — the
# runner's row sat ``in_progress`` with no process-level bound at all.
_SFTP_CHANNEL_TIMEOUT = 300


def _open_sftp(client):  # type: ignore[no-untyped-def]
    """Open the SFTP subsystem with a channel timeout set (#1515)."""
    sftp = client.open_sftp()
    channel = sftp.get_channel()
    if channel is not None:
        channel.settimeout(_SFTP_CHANNEL_TIMEOUT)
    return sftp


class ScpDestination(BackupDestination):
    kind = "scp"
    label = "SCP / SFTP"
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
            description="Default 22.",
        ),
        ConfigFieldSpec(
            name="username",
            label="Username",
            type="text",
            required=True,
        ),
        ConfigFieldSpec(
            name="remote_path",
            label="Remote path",
            type="text",
            required=True,
            description="Absolute path on the remote (must already exist).",
        ),
        ConfigFieldSpec(
            name="password",
            label="Password",
            type="password",
            required=False,
            secret=True,
            description="Set ONE of password / private_key.",
        ),
        ConfigFieldSpec(
            name="private_key",
            label="Private key (PEM)",
            type="password",
            required=False,
            secret=True,
            description=(
                "ED25519 / ECDSA / RSA / DSS. Paste the entire "
                "PEM-encoded key including BEGIN / END lines."
            ),
        ),
        ConfigFieldSpec(
            name="private_key_passphrase",
            label="Private key passphrase",
            type="password",
            required=False,
            secret=True,
            description="Only set when the private key itself is passphrase-protected.",
        ),
        ConfigFieldSpec(
            name="host_key_check",
            label="Host-key check",
            type="text",
            required=False,
            description=(
                "'known_hosts' (default; refuse hosts not in the supplied "
                "known_hosts), 'strict' (same check, historical name), or "
                "'insecure_skip' (homelab shortcut, not recommended)."
            ),
        ),
        ConfigFieldSpec(
            name="known_hosts",
            label="known_hosts content",
            type="text",
            required=False,
            description=(
                "OpenSSH known_hosts file content. Required when "
                "host_key_check = 'known_hosts' (the default) or 'strict'."
            ),
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> None:
        for required in ("host", "username", "remote_path"):
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
        if not config.get("password") and not config.get("private_key"):
            raise DestinationConfigError("set ONE of 'password' or 'private_key'")
        remote_path = config["remote_path"]
        if not remote_path.startswith("/"):
            raise DestinationConfigError("'remote_path' must be absolute")
        host_key_check = config.get("host_key_check") or "known_hosts"
        if host_key_check not in _HOST_KEY_MODES:
            raise DestinationConfigError(
                f"'host_key_check' must be one of {sorted(_HOST_KEY_MODES)} "
                f"(got {host_key_check!r})"
            )
        if host_key_check in {"known_hosts", "strict"} and not config.get("known_hosts"):
            # The driver loads no system host keys, so a checked mode
            # without supplied keys checks against an EMPTY store and
            # refuses every server (#1569). The old default was
            # exactly that ("strict" with nothing loaded), which
            # pushed operators to insecure_skip. Refuse the config
            # here, where the fix is obvious, instead of at connect
            # time, where it looks like a server problem.
            raise DestinationConfigError(
                f"host_key_check={host_key_check!r} requires 'known_hosts' to be "
                "set — paste the server's known_hosts line(s) (e.g. the output of "
                "`ssh-keyscan <host>`), or set host_key_check='insecure_skip' "
                "(not recommended: it accepts any host key)"
            )

    def _connect(self, config: dict[str, Any]):
        """Return an open paramiko ``SSHClient``. Caller closes."""
        import paramiko  # noqa: PLC0415

        client = paramiko.SSHClient()
        host_key_check = config.get("host_key_check") or "known_hosts"
        if host_key_check == "insecure_skip":
            # Equivalent to ``StrictHostKeyChecking no`` — only
            # appropriate for trusted lab networks.
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        else:
            # "known_hosts" and "strict" are the same check (#1569):
            # load the operator-supplied keys, then refuse anything
            # not among them. ``strict`` used to skip the load, which
            # left the store empty and made the mode unusable.
            _load_supplied_host_keys(client, config.get("known_hosts") or "")
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

        port = int(config.get("port") or 22)
        connect_kwargs: dict[str, Any] = {
            "hostname": config["host"],
            "port": port,
            "username": config["username"],
            "timeout": _SSH_CONNECT_TIMEOUT,
            "banner_timeout": _SSH_BANNER_TIMEOUT,
            "auth_timeout": _SSH_CONNECT_TIMEOUT,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if config.get("private_key"):
            pkey = _load_private_key(
                config["private_key"], config.get("private_key_passphrase") or None
            )
            connect_kwargs["pkey"] = pkey
        if config.get("password"):
            connect_kwargs["password"] = config["password"]
        try:
            client.connect(**connect_kwargs)
        except Exception as exc:  # noqa: BLE001
            client.close()
            raise BackupDestinationError(f"SSH connect failed: {exc}") from exc
        return client

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
                try:
                    sftp = _open_sftp(client)
                except Exception as exc:  # noqa: BLE001
                    raise BackupDestinationError(f"SFTP write failed: {exc}") from exc
                try:
                    # Atomic rename: write to .tmp then rename so a
                    # crashed transfer doesn't leave a half-archive
                    # the listing pass would pick up.
                    with sftp.file(tmp, "wb") as fh:
                        fh.write(archive_bytes)
                    try:
                        sftp.remove(remote)
                    except OSError:
                        pass  # didn't exist
                    sftp.rename(tmp, remote)
                except Exception as exc:  # noqa: BLE001
                    # Best-effort cleanup of the staged file (#1570),
                    # mirroring the NFS driver: listing and retention
                    # only match ``*.zip``, so a leftover ``.tmp`` is
                    # invisible and is never pruned.
                    try:
                        sftp.remove(tmp)
                    except FileNotFoundError:
                        pass  # the failure predates the staged file
                    except Exception as cleanup_exc:  # noqa: BLE001
                        logger.warning(
                            "scp_partial_cleanup_failed",
                            path=tmp,
                            error=str(cleanup_exc),
                        )
                    raise BackupDestinationError(f"SFTP write failed: {exc}") from exc
                finally:
                    sftp.close()
            finally:
                client.close()

        await asyncio.to_thread(_do)

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        remote_path = config["remote_path"].rstrip("/")

        def _do() -> list[ArchiveListing]:
            client = self._connect(config)
            try:
                sftp = _open_sftp(client)
                try:
                    entries = sftp.listdir_attr(remote_path)
                except FileNotFoundError as exc:
                    raise BackupDestinationError(
                        f"remote_path {remote_path!r} not found on host"
                    ) from exc
                except Exception as exc:  # noqa: BLE001
                    raise BackupDestinationError(f"SFTP listdir failed: {exc}") from exc
                finally:
                    sftp.close()
            finally:
                client.close()
            rows: list[ArchiveListing] = []
            for attr in entries:
                if attr.st_mode is None or stat_mod.S_ISDIR(attr.st_mode):
                    continue
                if not ARCHIVE_NAME_RE.match(attr.filename):
                    continue
                if not attr.st_mtime or not attr.st_size:
                    continue
                rows.append(
                    ArchiveListing(
                        filename=attr.filename,
                        size_bytes=int(attr.st_size),
                        created_at=datetime.fromtimestamp(attr.st_mtime, UTC),
                    )
                )
            rows.sort(key=lambda r: r.created_at, reverse=True)
            return rows

        return await asyncio.to_thread(_do)

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        safe = safe_filename(filename)
        remote = config["remote_path"].rstrip("/") + "/" + safe

        def _do() -> bytes:
            client = self._connect(config)
            try:
                sftp = _open_sftp(client)
                try:
                    with sftp.file(remote, "rb") as fh:
                        return fh.read()
                except FileNotFoundError as exc:
                    raise BackupDestinationError(f"archive {safe!r} not found at {remote}") from exc
                except Exception as exc:  # noqa: BLE001
                    raise BackupDestinationError(f"SFTP read failed: {exc}") from exc
                finally:
                    sftp.close()
            finally:
                client.close()

        return await asyncio.to_thread(_do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        safe = safe_filename(filename)
        remote = config["remote_path"].rstrip("/") + "/" + safe

        def _do() -> None:
            client = self._connect(config)
            try:
                sftp = _open_sftp(client)
                try:
                    sftp.remove(remote)
                except FileNotFoundError:
                    return  # idempotent
                except Exception as exc:  # noqa: BLE001
                    raise BackupDestinationError(f"SFTP delete failed: {exc}") from exc
                finally:
                    sftp.close()
            finally:
                client.close()

        await asyncio.to_thread(_do)

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            self.validate_config(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}
        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"
        remote_path = config["remote_path"].rstrip("/")
        probe_remote = f"{remote_path}/{probe_name}"

        def _do() -> dict[str, Any]:
            try:
                client = self._connect(config)
            except BackupDestinationError as exc:
                return {"ok": False, "error": str(exc)}
            try:
                sftp = _open_sftp(client)
                try:
                    # Sanity-check the path exists + is a directory.
                    stat = sftp.stat(remote_path)
                    if not stat.st_mode or not stat_mod.S_ISDIR(stat.st_mode):
                        return {
                            "ok": False,
                            "error": f"remote_path {remote_path!r} is not a directory",
                        }
                    with sftp.file(probe_remote, "wb") as fh:
                        fh.write(os.urandom(16))
                    head = sftp.stat(probe_remote)
                    ok = (head.st_size or 0) == 16
                    sftp.remove(probe_remote)
                except FileNotFoundError as exc:
                    return {"ok": False, "error": f"path missing: {exc}"}
                except OSError as exc:
                    return {"ok": False, "error": f"sftp: {exc}"}
                finally:
                    sftp.close()
            finally:
                client.close()
            if not ok:
                return {"ok": False, "error": "wrote probe but stat disagreed on size"}
            return {
                "ok": True,
                "detail": f"wrote + verified + deleted probe at {probe_remote}",
            }

        return await asyncio.to_thread(_do)


def _load_supplied_host_keys(client, known: str) -> None:
    """Load operator-supplied known_hosts lines into the client's
    host-key store. Malformed lines are skipped, as before.
    """
    import paramiko  # noqa: PLC0415

    for line in known.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parts = line.split()
            # paramiko's add_host_keys consumes a file path,
            # so we feed lines manually via load_host_keys's
            # internals.
            if len(parts) < 3:
                continue
            hostnames, keytype, key_b64 = parts[0], parts[1], parts[2]
            key_obj = paramiko.RSAKey if keytype == "ssh-rsa" else None
            if not key_obj:
                # Try the generic loader for non-RSA types.
                # paramiko's HostKeys handles parsing better
                # than a hand-rolled mapping.
                host_keys = paramiko.HostKeys()
                host_keys.add(hostnames, keytype, _decode_pubkey(keytype, key_b64))
                client._host_keys.update(host_keys)  # noqa: SLF001
            else:
                decoded = _decode_pubkey(keytype, key_b64)
                if decoded is not None:
                    client._host_keys.add(hostnames, keytype, decoded)  # noqa: SLF001
        except Exception:  # noqa: BLE001
            continue


def _load_private_key(pem: str, passphrase: str | None):
    """Load a PEM-encoded SSH private key. paramiko's
    ``RSAKey.from_private_key`` / ``Ed25519Key.from_private_key`` /
    etc. each only handle one algo, so we try them in turn.
    """
    import paramiko  # noqa: PLC0415

    text_io = io.StringIO(pem)
    last_exc: Exception | None = None
    for cls in (
        paramiko.Ed25519Key,
        paramiko.ECDSAKey,
        paramiko.RSAKey,
        paramiko.DSSKey,
    ):
        text_io.seek(0)
        try:
            return cls.from_private_key(text_io, password=passphrase)
        except paramiko.SSHException as exc:
            last_exc = exc
            continue
    raise BackupDestinationError(
        f"could not parse private key (tried Ed25519 / ECDSA / RSA / DSS): {last_exc}"
    )


def _decode_pubkey(keytype: str, b64: str):
    """Best-effort decoder for known_hosts pubkey lines.
    Returns a paramiko PKey subclass or None on parse failure.
    """
    import base64  # noqa: PLC0415

    import paramiko  # noqa: PLC0415

    try:
        raw = base64.b64decode(b64)
    except Exception:  # noqa: BLE001
        return None
    cls_map = {
        "ssh-rsa": paramiko.RSAKey,
        "ssh-dss": paramiko.DSSKey,
        "ssh-ed25519": paramiko.Ed25519Key,
        "ecdsa-sha2-nistp256": paramiko.ECDSAKey,
        "ecdsa-sha2-nistp384": paramiko.ECDSAKey,
        "ecdsa-sha2-nistp521": paramiko.ECDSAKey,
    }
    cls = cls_map.get(keytype)
    if cls is None:
        return None
    try:
        return cls(data=raw)
    except Exception:  # noqa: BLE001
        return None
