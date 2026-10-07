"""NFS backup destination (issue #971).

Points scheduled backups at an NFS export — a NAS (Synology / TrueNAS /
QNAP), a Linux file server — the same way ``smb`` points them at a
Windows share. NFS was the conspicuous gap in the destination tier
table: every other network filesystem a homelab or small enterprise
runs already had a driver.

``local_volume`` was the documented workaround, and it works, but it
pushes the mount to the deployment layer: the operator edits
``docker-compose.yml`` or a PVC, restarts the control plane, and the
destination row carries no knowledge of *where* the archives actually
live. On the appliance there was no supported way to do it at all.

Userspace, not a kernel mount
-----------------------------

The api / worker containers run unprivileged. A kernel ``mount -t nfs``
needs ``CAP_SYS_ADMIN``, which is not a capability to grant the process
that also holds the Fernet master key — so this speaks NFS in userspace
via :mod:`app.services.backup.targets.libnfs_client` (ctypes over
``libnfs``), exactly as ``smb`` speaks SMB in userspace via
``smbprotocol``. That module's docstring records why ctypes rather than
libnfs's own PyPI binding or its CLI tools; both were tried and both are
dead ends.

Because it is userspace, the ``nfs`` kind works on the appliance the
same as everywhere else — no host-mount plane needed, which was the
point of doing it this way.

Config shape
------------

* ``server`` — hostname or IP.
* ``export`` — the export path as the server publishes it, e.g.
  ``/volume1/backups``.
* ``path`` — optional subdirectory inside the export; created on first
  write if missing.
* ``version`` — ``4`` (default) or ``3``. Surfaced as a choice rather
  than auto-negotiated: v3 additionally needs the portmapper and mountd
  reachable, so silently falling back would turn a firewall problem into
  a mystery.
* ``port`` — optional, default 2049.
* ``uid`` / ``gid`` — the AUTH_SYS identity presented to the server.
  Defaults to the identity the process runs as. Exposed because
  ``root_squash`` / ``all_squash`` on the export decide whether writes
  land at all.
* ``timeout_s`` — per-RPC timeout so a dead NAS fails the run instead of
  wedging the beat sweep.

**There are no secret fields, and that is not an oversight.** NFS with
AUTH_SYS has no credential — the client asserts a uid and the server
believes it. This is the one destination where "test connection passed"
says nothing about who else can read the archives — and only an
archive's ``secrets.enc`` is encrypted, not its database dump, so an
unrestricted export exposes the archives' contents (#1352). Kerberos
(``sec=krb5*``) is out of scope for v1 — the same call ``smb`` made for
NTLM-only.
"""

from __future__ import annotations

import asyncio
import errno as _errno
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
from app.services.backup.targets.libnfs_client import NfsConnection, NfsError, connect

logger = structlog.get_logger(__name__)

#: Suffix for the in-flight write. Deliberately chosen so it does NOT
#: match ``ARCHIVE_NAME_RE``: a write killed halfway leaves a file a
#: concurrent ``list_archives`` (and therefore the retention sweep, and
#: therefore ``latest/download``) cannot see. The other drivers get this
#: for free — an object store PUT is atomic — and NFS does not.
_PART_SUFFIX = ".part"

_DEFAULT_TIMEOUT_S = 30
_MAX_TIMEOUT_S = 600

#: Characters that would break libnfs's URL parser, which is where the
#: port and version arguments have to travel (libnfs exports no
#: ``nfs_set_nfsport``). No real export path contains them, so rejecting
#: at validate time beats a silently mis-parsed mount.
_URL_HOSTILE = set("?&# \t\r\n")


def _squash_hint(exc: NfsError, *, action: str) -> str:
    """Turn an errno into the sentence the operator actually needs.

    ``EACCES`` / ``EPERM`` on an NFS export is very nearly always
    ``root_squash`` mapping the presented uid to ``nobody``, and
    ``EROFS`` is an export published read-only. Reporting the bare errno
    here is the difference between a five-minute fix and the single most
    common support question every NFS-backed product gets.
    """
    base = str(exc)
    if exc.errno in (_errno.EACCES, _errno.EPERM):
        return (
            f"{base} — the server refused the {action}. Two causes account for "
            "nearly all of these, and they need opposite fixes. (1) The export "
            "requires a PRIVILEGED SOURCE PORT: Linux's 'secure' export option is "
            "the default (Synology calls it 'allow connections from non-privileged "
            "ports', also off by default), and SpatiumDDI connects from an "
            "unprivileged port because the control plane runs as a non-root user "
            "with no CAP_NET_BIND_SERVICE — add 'insecure' to the export options on "
            "the server. (2) SQUASHING: with 'root_squash' (also the default) the "
            "uid presented here is mapped to 'nobody', which usually cannot write — "
            "set the destination's uid/gid to an identity the export allows, or "
            "grant that identity write access on the server. If the MOUNT itself "
            "failed, (1) is the likely cause; if the mount succeeded and only the "
            "write was refused, (2) is."
        )
    if exc.errno == _errno.EROFS:
        return f"{base} — the export is published read-only, so the {action} cannot succeed."
    if exc.errno == _errno.EDQUOT:
        return f"{base} — the presented uid is over quota on the server."
    if exc.errno == _errno.ENOSPC:
        return f"{base} — the export is out of space."
    return base


def _int_field(config: dict[str, Any], name: str) -> int | None:
    raw = config.get(name)
    if raw is None or raw == "":
        return None
    try:
        return int(raw)
    except (TypeError, ValueError) as exc:
        raise DestinationConfigError(f"{name!r} must be a number ({exc})") from exc


def _version(config: dict[str, Any]) -> int:
    v = _int_field(config, "version")
    return 4 if v is None else v


def _timeout(config: dict[str, Any]) -> int:
    t = _int_field(config, "timeout_s")
    if t is None:
        return _DEFAULT_TIMEOUT_S
    return max(1, min(t, _MAX_TIMEOUT_S))


def _subdir(config: dict[str, Any]) -> str:
    """The optional subdirectory inside the export, normalised to
    ``/a/b`` or ``""``. Everything below is composed against this.
    """
    sub = (config.get("path") or "").strip().strip("/")
    return f"/{sub}" if sub else ""


def _remote_path(config: dict[str, Any], filename: str | None = None) -> str:
    """Compose the path inside the export. ``safe_filename`` defends
    against an operator-supplied filename carrying separators — the
    shared sanitiser every driver applies.
    """
    base = _subdir(config)
    if filename is None:
        return base or "/"
    return f"{base}/{safe_filename(filename)}"


def _open(config: dict[str, Any]):
    return connect(
        server=config["server"],
        export=config["export"],
        version=_version(config),
        port=_int_field(config, "port"),
        uid=_int_field(config, "uid"),
        gid=_int_field(config, "gid"),
        timeout_s=_timeout(config),
    )


def _ensure_subdir(conn: NfsConnection, config: dict[str, Any]) -> None:
    """Create the configured subdirectory if it is missing, one
    component at a time (libnfs has no ``mkdir -p``). An already-present
    component is not an error.
    """
    sub = _subdir(config)
    if not sub:
        return
    walked = ""
    for part in sub.strip("/").split("/"):
        walked = f"{walked}/{part}"
        try:
            conn.mkdir(walked)
        except NfsError as exc:
            if exc.errno == _errno.EEXIST:
                continue
            # A component that exists but is not a directory, or a
            # permission failure, are both real — surface them with the
            # squash hint since that is the usual cause.
            raise BackupDestinationError(
                _squash_hint(exc, action=f"creation of directory {walked!r}")
            ) from exc


class NfsDestination(BackupDestination):
    kind = "nfs"
    label = "NFS export"
    config_fields = (
        ConfigFieldSpec(
            name="server",
            label="Server hostname or IP",
            type="text",
            required=True,
        ),
        ConfigFieldSpec(
            name="export",
            label="Export path",
            type="text",
            required=True,
            description=(
                "The export as the server publishes it, e.g. /volume1/backups. "
                "On the server this is the line in /etc/exports (or the share's "
                "NFS permissions on a NAS)."
            ),
        ),
        ConfigFieldSpec(
            name="path",
            label="Subdirectory within the export",
            type="text",
            required=False,
            description="Optional. Created on the first write if it does not exist.",
        ),
        ConfigFieldSpec(
            name="version",
            label="NFS version",
            type="text",
            required=False,
            description=(
                "'4' (default) or '3'. NFSv3 additionally needs the portmapper "
                "(111) and mountd reachable, so it is a choice rather than an "
                "automatic fallback."
            ),
        ),
        ConfigFieldSpec(
            name="port",
            label="Port",
            type="text",
            required=False,
            description="Default 2049.",
        ),
        ConfigFieldSpec(
            name="uid",
            label="UID to present",
            type="text",
            required=False,
            description=(
                "AUTH_SYS identity sent to the server. Blank uses the identity "
                "the control plane runs as. If the export uses root_squash or "
                "all_squash (most NAS defaults), set this to a uid the export "
                "grants write access — otherwise writes fail with permission denied."
            ),
        ),
        ConfigFieldSpec(
            name="gid",
            label="GID to present",
            type="text",
            required=False,
            description="AUTH_SYS group identity. Blank uses the process's own.",
        ),
        ConfigFieldSpec(
            name="timeout_s",
            label="Operation timeout (seconds)",
            type="text",
            required=False,
            description=(
                "Per-RPC timeout, default 30. Bounds every operation, not just "
                "listing — libnfs applies one timeout per context. Keeps a dead "
                "NAS from holding up the scheduled-backup sweep."
            ),
        ),
        ConfigFieldSpec(
            name="_auth_notice",
            label="Authentication",
            type="notice",
            required=False,
            description=(
                "NFS with AUTH_SYS has no credential: the client asserts a uid and "
                "the server believes it. A successful connection test therefore says "
                "nothing about who else on the network can read this export. An "
                "archive's database dump is not encrypted (only its secrets.enc is), "
                "so anyone who can read the export can read every archive on it. "
                "Restrict the export to this host on the server side."
            ),
        ),
    )

    # ── validation ────────────────────────────────────────────────────

    def validate_config(self, config: dict[str, Any]) -> None:
        for required in ("server", "export"):
            value = config.get(required)
            if not value or not isinstance(value, str):
                raise DestinationConfigError(
                    f"{required!r} is required and must be a non-empty string"
                )
        for field in ("server", "export", "path"):
            value = config.get(field)
            if isinstance(value, str) and (set(value) & _URL_HOSTILE):
                raise DestinationConfigError(
                    f"{field!r} contains a character that cannot be expressed in an "
                    "NFS URL (one of '?', '&', '#', or whitespace)"
                )
        version = _version(config)
        if version not in (3, 4):
            raise DestinationConfigError(f"'version' must be 3 or 4 (got {version})")
        port = _int_field(config, "port")
        if port is not None and not 1 <= port <= 65535:
            raise DestinationConfigError("'port' must be 1..65535")
        for ident in ("uid", "gid"):
            value = _int_field(config, ident)
            if value is not None and not 0 <= value <= 0xFFFFFFFF:
                raise DestinationConfigError(f"{ident!r} must be a 32-bit unsigned value")
        timeout = _int_field(config, "timeout_s")
        if timeout is not None and not 1 <= timeout <= _MAX_TIMEOUT_S:
            raise DestinationConfigError(f"'timeout_s' must be 1..{_MAX_TIMEOUT_S}")

    # ── operations ────────────────────────────────────────────────────

    async def write(
        self,
        *,
        config: dict[str, Any],
        filename: str,
        archive_bytes: bytes,
    ) -> None:
        final = _remote_path(config, filename)
        staged = final + _PART_SUFFIX

        def _do() -> None:
            with _open(config) as conn:
                _ensure_subdir(conn, config)
                try:
                    conn.write(staged, archive_bytes)
                except NfsError as exc:
                    # Clean up before re-raising. The staged name is
                    # deliberately invisible to ``list_archives``, which
                    # also means the retention sweep can never reap it —
                    # so without this, every failed run (an export that
                    # filled up, say) leaves another multi-GB orphan under
                    # a new timestamped name, forever, on exactly the
                    # destination that just ran out of room.
                    try:
                        conn.unlink(staged)
                    except NfsError:
                        # Best effort — the write failure is the error
                        # worth reporting, and a partial file we could not
                        # remove must not mask it.
                        logger.warning("nfs_partial_cleanup_failed", path=staged)
                    raise BackupDestinationError(_squash_hint(exc, action="write")) from exc
                # Overwrite semantics: the ABC requires a same-named
                # archive to be replaced. NFS rename is atomic and
                # replaces an existing target, so no unlink-first step
                # (which would open a window where neither file exists).
                try:
                    conn.rename(staged, final)
                except NfsError as exc:
                    # Leave nothing behind that a later run would trip
                    # over; the staged name is invisible to listing but
                    # would still consume space.
                    try:
                        conn.unlink(staged)
                    except NfsError:
                        # Best-effort cleanup — the rename failure below
                        # is the error worth reporting.
                        pass
                    raise BackupDestinationError(
                        _squash_hint(exc, action=f"rename of {staged!r} into place")
                    ) from exc

        await asyncio.to_thread(self._guarded, _do)

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        root = _remote_path(config)

        def _do() -> list[ArchiveListing]:
            with _open(config) as conn:
                try:
                    entries = conn.listdir(root)
                except NfsError as exc:
                    if exc.errno == _errno.ENOENT:
                        # The subdirectory has not been created yet —
                        # that is an empty destination, not a failure.
                        return []
                    raise BackupDestinationError(
                        _squash_hint(exc, action=f"listing of {root!r}")
                    ) from exc
                rows: list[ArchiveListing] = []
                for entry in entries:
                    if not ARCHIVE_NAME_RE.match(entry.name):
                        continue
                    size = entry.size
                    mtime = entry.mtime
                    is_file = entry.is_regular_file
                    if entry.attrs_missing:
                        # The server returned a bare readdir with no
                        # attributes. Reporting 0 bytes / the epoch here
                        # would put a plausible-looking but wrong row in
                        # front of the operator, and would break
                        # retention's newest-first ordering, so pay for
                        # an explicit stat instead.
                        try:
                            st = conn.stat(f"{root.rstrip('/')}/{entry.name}")
                        except NfsError:
                            continue
                        size, mtime, is_file = st.size, st.mtime, st.is_regular_file
                    if not is_file:
                        continue
                    rows.append(
                        ArchiveListing(filename=entry.name, size_bytes=size, created_at=mtime)
                    )
                rows.sort(key=lambda r: r.created_at, reverse=True)
                return rows

        return await asyncio.to_thread(self._guarded, _do)

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        target = _remote_path(config, filename)

        def _do() -> bytes:
            with _open(config) as conn:
                try:
                    return conn.read(target)
                except NfsError as exc:
                    if exc.errno == _errno.ENOENT:
                        raise BackupDestinationError(
                            f"archive {safe_filename(filename)!r} not found at {target}"
                        ) from exc
                    raise BackupDestinationError(
                        _squash_hint(exc, action=f"read of {target!r}")
                    ) from exc

        return await asyncio.to_thread(self._guarded, _do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        target = _remote_path(config, filename)

        def _do() -> None:
            with _open(config) as conn:
                try:
                    conn.unlink(target)
                except NfsError as exc:
                    if exc.errno == _errno.ENOENT:
                        return  # idempotent, per the ABC
                    raise BackupDestinationError(
                        _squash_hint(exc, action=f"delete of {target!r}")
                    ) from exc

        await asyncio.to_thread(self._guarded, _do)

    # ── probe ─────────────────────────────────────────────────────────

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        """Write + stat + **readdir** + unlink a 16-byte probe.

        The readdir step is not decoration. A v3 export whose mountd is
        reachable but whose directory the presented uid cannot read will
        pass a write and fail every listing — and listing is what
        retention, ``latest/download`` and the restore drill all depend
        on. A probe that stops at "the write worked" would certify a
        destination that silently stops pruning.
        """
        try:
            self.validate_config(config)
        except DestinationConfigError as exc:
            return {"ok": False, "error": str(exc)}

        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"
        probe_path = _remote_path(config, probe_name)
        root = _remote_path(config)
        payload = os.urandom(16)

        def _do() -> dict[str, Any]:
            with _open(config) as conn:
                _ensure_subdir(conn, config)
                try:
                    conn.write(probe_path, payload)
                except NfsError as exc:
                    return {"ok": False, "error": _squash_hint(exc, action="write")}
                try:
                    st = conn.stat(probe_path)
                    if st.size != len(payload):
                        return {
                            "ok": False,
                            "error": (
                                f"wrote a {len(payload)}-byte probe but the server "
                                f"reports {st.size} bytes"
                            ),
                        }
                    names = {e.name for e in conn.listdir(root)}
                    if probe_name not in names:
                        return {
                            "ok": False,
                            "error": (
                                f"wrote the probe but it is absent from a listing of "
                                f"{root!r} — retention and restore both read this "
                                "directory, so they would not work here"
                            ),
                        }
                except NfsError as exc:
                    return {"ok": False, "error": _squash_hint(exc, action="listing")}
                finally:
                    try:
                        conn.unlink(probe_path)
                    except NfsError as exc:
                        logger.warning(
                            "nfs_probe_cleanup_failed",
                            path=probe_path,
                            error=str(exc),
                        )
            return {
                "ok": True,
                "detail": (
                    f"NFSv{_version(config)}: wrote + verified + listed + deleted a probe "
                    f"at {config['server']}:{config['export']}{_subdir(config)}"
                ),
            }

        try:
            return await asyncio.to_thread(_do)
        except (NfsError, BackupDestinationError) as exc:
            # NfsUnavailableError subclasses NfsError; three clauses with
            # identical bodies were two too many.
            return {"ok": False, "error": str(exc)}

    # ── shared failure mapping ────────────────────────────────────────

    @staticmethod
    def _guarded(fn):
        """Run ``fn`` and translate the connection-level failures into
        :class:`BackupDestinationError`, which is the only exception
        type the runner and the API layer know how to report. Operation
        failures are already translated at their call site, where the
        action name is known.
        """
        try:
            return fn()
        except NfsError as exc:
            # ``NfsUnavailableError`` (libnfs missing) subclasses this, so
            # one clause covers both — a second, byte-identical clause for
            # the subclass was dead and invited the bodies to drift apart.
            raise BackupDestinationError(str(exc)) from exc
