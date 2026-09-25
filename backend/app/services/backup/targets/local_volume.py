"""Local-volume backup destination (issue #117 Phase 1b).

Writes archives to a directory on the api / worker container's
filesystem. The path is operator-configured; production
deployments should mount it into the container as a docker /
k8s volume so archives survive container recycle.

No auth and no network, so the only failure modes are filesystem
ones — with one exception, added by #989 item 3 and described below.
Useful as:

* A first-class destination for installs that mount NFS / external
  storage at the configured path (the typical homelab + small
  enterprise pattern).
* The reference implementation everyone else in
  :mod:`app.services.backup.targets` will mirror — ``write`` /
  ``list_archives`` / ``delete`` / ``test_connection`` shape +
  ``validate_config`` semantics + the
  ``DestinationConfigError`` envelope.
* On the appliance, the way a **removable USB disk** is used: the
  host mount plane mounts it under
  ``/var/lib/spatiumddi/removable/<name>`` and a target points at
  ``<name>/spatiumddi``.

That last one is why this driver has a runtime guard at all. ``write``
does ``mkdir -p`` before it writes, so a path whose disk is absent
would be *created* and written to — landing archives on the
appliance's own ``/var`` while the run reports success. See
:func:`_assert_removable_disk_present`.

The same ``mkdir -p`` hides a quieter trap on every deployment (#1160):
a path no volume covers is still writable — it is the container's own
filesystem — so the probe passes and every run "succeeds", while each
archive exists only inside the one container that wrote it. Scheduled
runs execute in the worker, so the api never lists them, and all of them
are gone at the next recreate. ``test_connection`` warns about that; see
:func:`_not_on_a_volume_warning`.
"""

from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import structlog

from app.services.appliance.removable import REMOVABLE_ROOT
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

# Don't follow symlinks out of the configured root — operators
# who mount an external volume at the path expect "delete"
# scoped to that volume, not chasing a symlink to ``/etc``.
# ``Path.is_file(follow_symlinks=...)`` is 3.13+; we run on
# 3.12, so the listing pass below uses ``Path.is_symlink()``
# + ``Path.is_file()`` together instead of the kwarg.


class LocalVolumeDestination(BackupDestination):
    kind = "local_volume"
    label = "Local volume"
    config_fields = (
        ConfigFieldSpec(
            name="path",
            label="Filesystem path",
            type="text",
            required=True,
            description=(
                "Absolute path inside the api and worker containers. It "
                "must be a volume mounted on both: the worker writes "
                "scheduled runs and the api lists and restores them. The "
                "Docker Compose file and the appliance mount "
                "/var/lib/spatiumddi/backups that way; Test connection "
                "warns when a path is not on a volume."
            ),
        ),
        ConfigFieldSpec(
            name="node_name",
            label="Kubernetes node",
            type="text",
            required=False,
            description=(
                "Only meaningful on a multi-node appliance cluster. Filled "
                "in for you when the path points at a removable disk the "
                "fleet knows about, so you normally leave this empty: the "
                "disk is plugged into exactly one node, and this is what "
                "lets a run scheduled elsewhere say where the disk is "
                "instead of just reporting that nothing is mounted."
            ),
        ),
    )

    def validate_config(self, config: dict[str, Any]) -> None:
        path = config.get("path")
        if not path or not isinstance(path, str):
            raise DestinationConfigError("'path' is required and must be a string")
        if not path.startswith("/"):
            raise DestinationConfigError("'path' must be absolute (start with '/')")
        # Refuse obvious foot-guns. ``/`` and ``/etc`` aren't safe
        # roots; force the operator to pick something application-
        # scoped.
        forbidden_roots = {"/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/proc", "/sys"}
        if path.rstrip("/") in forbidden_roots:
            raise DestinationConfigError(
                f"'path' may not be a system root ({path!r}); pick an app-scoped directory"
            )
        node_name = config.get("node_name")
        if node_name is not None and not isinstance(node_name, str):
            raise DestinationConfigError("'node_name' must be a string when set")
        # Deliberately NOT checked here: whether a removable disk is
        # actually mounted right now. ``validate_config`` also runs at
        # CREATE time, and a rotated off-site disk is legitimately absent
        # then — refusing there would make the destination unusable for
        # exactly the rotation it exists to support. The runtime check
        # lives in ``_path``, which every read and write goes through.

    def _path(self, config: dict[str, Any]) -> Path:
        self.validate_config(config)
        root = Path(config["path"]).resolve()
        _assert_removable_disk_present(root, config)
        return root

    async def write(self, *, config: dict[str, Any], filename: str, archive_bytes: bytes) -> None:
        # Synchronous filesystem ops are fast on a local disk; we
        # offload to a thread anyway so a slow NFS mount can't
        # block the asyncio loop — and ``_path`` now walks mountpoints
        # on a device that may have just been yanked, which is exactly
        # the stall that comment is about. Resolving it OUTSIDE the
        # thread would put those lstats on the shared api event loop.
        def _do() -> None:
            root = self._path(config)
            try:
                root.mkdir(parents=True, exist_ok=True)
                target = root / safe_filename(filename)
                tmp = target.with_suffix(target.suffix + ".tmp")
                tmp.write_bytes(archive_bytes)
                # Atomic rename so partial writes are never visible to
                # the listing pass — important for the retention sweep
                # which keys on filename + size.
                os.replace(tmp, target)
            except OSError as exc:
                # Translated, not propagated. ``run_backup_for_target``
                # commits ``last_run_status="in_progress"`` BEFORE the
                # write and catches only the BackupDestination/Archive
                # family — so a bare OSError escapes before the failure
                # row and the audit row are written, and
                # ``backup_sweep`` then skips an ``in_progress`` target
                # on every later tick FOREVER. The UI shows "in
                # progress", ``last_run_error`` is NULL, and the
                # schedule is silently dead.
                #
                # This is not a hypothetical on removable media: ENOSPC
                # on a full USB stick is the likeliest runtime failure
                # this feature has, EACCES follows a refused
                # ``--prepare`` chown, and a yanked disk gives EROFS or
                # EIO mid-write.
                raise BackupDestinationError(
                    f"could not write {filename!r} to {root}: {exc}"
                ) from exc

        await asyncio.to_thread(_do)

    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        def _do() -> list[ArchiveListing]:
            root = self._path(config)
            if not root.exists():
                return []
            rows: list[ArchiveListing] = []
            for entry in root.iterdir():
                # Skip symlinks explicitly so we never escape the
                # configured root, then check is_file() on what's
                # left. ``Path.lstat()`` returns the link's own
                # stat (not the target's) which is what we want
                # for size + mtime here.
                if entry.is_symlink() or not entry.is_file():
                    continue
                if not ARCHIVE_NAME_RE.match(entry.name):
                    continue
                stat = entry.lstat()
                rows.append(
                    ArchiveListing(
                        filename=entry.name,
                        size_bytes=stat.st_size,
                        created_at=datetime.fromtimestamp(stat.st_mtime, UTC),
                    )
                )
            rows.sort(key=lambda r: r.created_at, reverse=True)
            return rows

        return await asyncio.to_thread(_do)

    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        safe = safe_filename(filename)

        def _do() -> bytes:
            root = self._path(config)
            target = root / safe
            if not target.is_file():
                raise BackupDestinationError(f"archive {safe!r} not found at {root}")
            return target.read_bytes()

        return await asyncio.to_thread(_do)

    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        safe = safe_filename(filename)

        def _do() -> None:
            root = self._path(config)
            target = root / safe
            try:
                target.unlink(missing_ok=True)
            except OSError as exc:
                logger.warning(
                    "backup_local_volume_delete_failed",
                    path=str(target),
                    error=str(exc),
                )
                raise

        await asyncio.to_thread(_do)

    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        try:
            root = self._path(config)
        except BackupDestinationError as exc:
            # Catches DestinationConfigError AND the removable-disk
            # refusal below it — a test against a target whose disk is
            # out has to report why, not raise through the endpoint.
            return {"ok": False, "error": str(exc)}
        # Probe file uses ``.bin`` so it can't be confused with a
        # real archive by ``list_archives`` (which filters to the
        # ``spatiumddi-backup-*.zip`` / ``pre-restore-*.zip``
        # patterns). Existence-check goes through ``Path.is_file``
        # directly rather than via ``list_archives``.
        probe_name = f"spatiumddi-test-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.bin"

        def _exists() -> bool:
            return (root / probe_name).is_file()

        try:
            await self.write(config=config, filename=probe_name, archive_bytes=os.urandom(16))
            present = await asyncio.to_thread(_exists)
            await self.delete(config=config, filename=probe_name)
        except (OSError, PermissionError) as exc:
            return {"ok": False, "error": f"filesystem: {exc}"}
        if not present:
            return {
                "ok": False,
                "error": (f"wrote probe but it didn't appear at {root} — check permissions"),
            }
        outcome: dict[str, Any] = {
            "ok": True,
            "detail": f"wrote + verified + deleted probe under {root}",
        }
        # After the probe, so ``root`` exists and the walk starts at it.
        # A warning, not a failure: the write works — until the
        # container is replaced (#1160).
        warning = await asyncio.to_thread(_not_on_a_volume_warning, root)
        if warning:
            outcome["warning"] = warning
        return outcome


def _not_on_a_volume_warning(root: Path) -> str | None:
    """Why ``root`` is a trap, or ``None`` when it is on a mounted volume.

    Every supported deployment runs the api and the worker in containers
    (Docker Compose, Kubernetes, the appliance's k3s). Inside one, the
    nearest mountpoint of a path no volume covers is ``/`` — the
    container's own writable layer. Writing there succeeds, which is the
    whole problem (#1160): the archive exists only in the container that
    wrote it, so a scheduled run (the worker's) is never listed by the
    api, and every archive is gone at the next recreate — each upgrade
    included. The probe cannot see any of that.

    Same :func:`_nearest_mountpoint` walk as the removable-disk guard, so
    the two agree on what "mounted" means; a path under a mounted parent
    (a per-target subdirectory of the volume) counts as mounted.
    """
    if _nearest_mountpoint(root) != Path("/"):
        return None
    return (
        f"{root} is not on a mounted volume: it is inside this container's "
        "own filesystem. Archives written here are lost when the container "
        "is recreated (every upgrade does that), and scheduled runs, which "
        "the worker performs, land in the worker's filesystem, where they "
        "are never listed here and cannot be downloaded or restored. Mount "
        "one volume at this path on both the api and the worker (the "
        "Docker Compose file's spatium_backups does that for "
        "/var/lib/spatiumddi/backups), or use a network destination."
    )


def _nearest_mountpoint(path: Path) -> Path:
    """The deepest existing mountpoint at or above ``path``.

    Walks up rather than testing ``path`` alone so a destination pointed
    at a SUBDIRECTORY of a removable disk (the shape this feature
    actually ships — archives go to ``<mount>/spatiumddi``) resolves to
    the mount it sits on.
    """
    current = path
    while True:
        try:
            if os.path.ismount(current):
                return current
        except OSError:
            # Unstattable (a permission boundary, or the disk vanished
            # mid-walk). Keep walking up rather than refusing here: the
            # caller's rule is "the nearest mountpoint must be UNDER the
            # removable root", and a path we cannot stat never satisfies
            # it — so an unreadable ancestor fails closed either way.
            pass
        parent = current.parent
        if parent == current:
            return current
        current = parent


def _assert_removable_disk_present(root: Path, config: dict[str, Any]) -> None:
    """Refuse a removable-disk path whose disk is not actually there.

    **This is the single most important line of defence in #989 item 3**,
    and it is worth being explicit about why, because every failure it
    catches looks identical without it: a backup that reports success
    while writing to the appliance's own ``/var``. That leaves an
    operator with a green screen, no archives, and a root filesystem
    filling up — strictly worse than a destination that never worked,
    because they stopped worrying about backups.

    The four ways to get there are a disk ejected from the Fleet UI, a
    disk yanked without ejecting, a mount unit that failed, and a run
    that landed on a node the disk is not plugged into. One test covers
    all four: is the path still on a live mount under the removable root?

    ``os.path.ismount`` is the right test from inside a container and
    that was measured, not assumed — with ``mountPropagation:
    HostToContainer`` the host's mount is visible and reads as a
    mountpoint, and after an unmount it reads as a plain directory
    again. (With the DEFAULT private propagation the mount is invisible
    entirely, which is why the chart sets it and why this guard would
    otherwise fire on a perfectly healthy disk.)

    The node name only ever improves the MESSAGE. It is deliberately not
    load-bearing: it is absent on compose, and ``NODE_NAME`` is absent on
    any pod that predates this change — so a missing one has to mean "I
    cannot tell", and the mountpoint test is what actually decides.
    """
    removable_root = Path(REMOVABLE_ROOT)
    if removable_root != root and removable_root not in root.parents:
        return  # an ordinary local volume — nothing removable about it

    if root == removable_root:
        # The bare root is the directory the per-disk mountpoints live
        # IN, never a mountpoint itself, so a target pointed here could
        # only ever write to the appliance's own /var. That is a config
        # mistake rather than an absent disk, and saying so is the
        # difference between an operator fixing the path and one
        # hunting for a disk that is plugged in perfectly well.
        raise DestinationConfigError(
            f"{REMOVABLE_ROOT} is where removable disks are mounted, not a "
            "destination itself — point this at one of them, e.g. "
            f"{REMOVABLE_ROOT}/<disk>/spatiumddi."
        )
    name = root.relative_to(removable_root).parts[0]
    configured_node = str(config.get("node_name") or "").strip()
    this_node = os.environ.get("NODE_NAME", "").strip()
    where = f" The disk is on node {configured_node}." if configured_node else ""
    if configured_node and this_node and configured_node != this_node:
        raise BackupDestinationError(
            f"this run is on node {this_node} and the removable disk "
            f"{name or root.name!r} is plugged into node {configured_node}. "
            "A removable destination is node-local; schedule it from that node "
            "or move the disk."
        )

    mount = _nearest_mountpoint(root)
    if mount == removable_root or removable_root not in mount.parents:
        raise BackupDestinationError(
            f"no removable disk is mounted at {removable_root}/{name} — nothing "
            f"was read or written.{where} Plug the disk in, or re-mount it from "
            "Fleet → the appliance → Removable storage."
        )
