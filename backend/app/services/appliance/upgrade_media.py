"""Upgrade images on removable media, for sites with no network (#4727).

An air-gapped operator downloads the upgrade image and its ``.sha256``
sidecar from the release page, copies both onto a USB stick, mounts the
stick through the existing removable-storage plane (Fleet -> the appliance
-> Removable storage, #989 item 3) and imports the image from there. This
module is only the READ side of that: find candidate images under the
removable root, and open one for the upload path to store. Everything an
imported image must pass afterwards (the size cap, the fleet-architecture
gate, the store headroom check, sha256 verification while it is stored, and
the scheduling gates a staged row meets later) is the existing machinery,
reached through the same ``_store_verified_image`` the upload and GitHub
import use. There is no second path.

What this module refuses, each with a message an operator can act on:

* a directory that is not a live mountpoint (an ejected stick leaves a plain
  directory on the appliance's own ``/var``; nothing is read from it);
* a symlink, a non-regular file, a name that is not a release asset name, a
  file over the upgrade-image size cap;
* an image with no ``.sha256`` sidecar, an unreadable sidecar, or one that
  names a different file. The release does not sign slot images (it
  publishes sha256 sidecars only), so the sidecar is the only integrity
  statement there is, and an image without one is never imported;
* a version that is not a release version.

Files are only ever read, never executed or written, and the host mounts the
disk ``noexec,nosuid,nodev``. The stick is the operator's, so nothing is
copied back onto it and nothing is removed from it.
"""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path

from app.core.body_limit import UPGRADE_IMAGE_MAX_BYTES
from app.core.versions import parse_release
from app.services.appliance.removable import REMOVABLE_ROOT, validate_name

#: Directory on the stick searched besides its top level.
MEDIA_SUBDIR = "spatiumddi-upgrade"

#: ``spatiumddi-appliance-slot-<version>-<arch>.raw.xz`` — the versioned
#: release asset name. The unversioned (stable) name carries no version, and
#: the version is what the scheduling gates and the auto-clear logic key on,
#: so it is refused rather than guessed.
_VERSIONED_RE = re.compile(
    r"^spatiumddi-appliance-slot-(?P<version>[A-Za-z0-9][A-Za-z0-9._+]*(?:-[A-Za-z0-9._+]+)*?)"
    r"-(?P<arch>amd64|arm64)\.raw\.xz$"
)
_STABLE_RE = re.compile(r"^spatiumddi-appliance-slot-(amd64|arm64)\.raw\.xz$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_SIDECAR_MAX_BYTES = 4096


class MediaError(Exception):
    """A refusal: ``status`` is the HTTP code, ``message`` is for the operator."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class MediaImage:
    mount: str
    filename: str
    path: Path
    subdir: str
    size_bytes: int
    appliance_version: str | None = None
    architecture: str | None = None
    sha256: str | None = None
    #: Why this file cannot be imported; empty when it can.
    problems: list[str] = field(default_factory=list)


def _lstat_regular(path: Path) -> os.stat_result | None:
    try:
        st = os.lstat(path)
    except OSError:
        return None
    return st if stat.S_ISREG(st.st_mode) else None


def _read_sidecar(sidecar: Path, image_name: str) -> tuple[str | None, str | None]:
    """``(sha256, problem)`` from ``sidecar`` (``<hash>  <name>`` or a bare hash)."""
    st = _lstat_regular(sidecar)
    if st is None:
        return None, (
            f"no {sidecar.name} next to the image. Copy the release's .sha256 "
            "file onto the same stick; an image without its checksum is not imported"
        )
    if st.st_size > _SIDECAR_MAX_BYTES:
        return None, f"{sidecar.name} is {st.st_size} bytes, too large to be a checksum file"
    try:
        fd = os.open(sidecar, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as fh:
            text = fh.read(_SIDECAR_MAX_BYTES + 1).decode("utf-8", errors="replace")
    except OSError as exc:
        return None, f"could not read {sidecar.name}: {exc.strerror or exc}"
    tokens = text.split()
    digest = tokens[0].lower() if tokens else ""
    if not _SHA_RE.match(digest):
        return None, f"{sidecar.name} does not start with a 64-character sha256 digest"
    if len(tokens) > 1:
        named = tokens[1].lstrip("*")
        if named != image_name:
            return None, (
                f"{sidecar.name} is the checksum of {named!r}, not {image_name!r}. "
                "Copy the checksum that belongs to this image"
            )
    return digest, None


def _describe(mount: str, directory: Path, subdir: str, name: str) -> MediaImage | None:
    path = directory / name
    st = _lstat_regular(path)
    if st is None:
        return None  # a symlink, a directory or a device node: not offered at all
    vm = _VERSIONED_RE.match(name)
    image = MediaImage(mount=mount, filename=name, path=path, subdir=subdir, size_bytes=st.st_size)
    if vm is None:
        if _STABLE_RE.match(name):
            image.problems.append(
                "the unversioned file name carries no release version. Use the versioned "
                "asset (spatiumddi-appliance-slot-<version>-<arch>.raw.xz) from the release page"
            )
        else:
            return None
    else:
        version = vm.group("version")
        image.architecture = vm.group("arch")
        if parse_release(version) is None:
            image.problems.append(f"{version!r} is not a release version")
        else:
            image.appliance_version = version
    if st.st_size > UPGRADE_IMAGE_MAX_BYTES:
        image.problems.append(
            f"the file is {st.st_size} bytes; the upgrade-image limit is {UPGRADE_IMAGE_MAX_BYTES}"
        )
    if st.st_size == 0:
        image.problems.append("the file is empty")
    sha, problem = _read_sidecar(directory / (name[: -len(".raw.xz")] + ".sha256"), name)
    image.sha256 = sha
    if problem:
        image.problems.append(problem)
    return image


def _mount_dirs(root: Path) -> list[tuple[str, Path]]:
    try:
        entries = sorted(os.listdir(root))
    except OSError:
        return []
    out: list[tuple[str, Path]] = []
    for name in entries:
        try:
            validate_name(name)
        except ValueError:
            continue
        p = root / name
        try:
            if p.is_dir() and not p.is_symlink() and os.path.ismount(p):
                out.append((name, p))
        except OSError:
            continue
    return out


def scan(root: str | Path | None = None) -> list[MediaImage]:
    """Every upgrade-image candidate on a live removable mount."""
    found: list[MediaImage] = []
    for mount, mount_path in _mount_dirs(Path(root or REMOVABLE_ROOT)):
        for subdir in ("", MEDIA_SUBDIR):
            directory = mount_path / subdir if subdir else mount_path
            try:
                if subdir and (directory.is_symlink() or not directory.is_dir()):
                    continue
                names = sorted(os.listdir(directory))
            except OSError:
                continue
            for name in names:
                if not name.endswith(".raw.xz"):
                    continue
                image = _describe(mount, directory, subdir, name)
                if image is not None:
                    found.append(image)
    return found


def resolve(mount: str, filename: str, root: str | Path | None = None) -> MediaImage:
    """The importable image ``filename`` on ``mount``, or :class:`MediaError`."""
    try:
        name = validate_name(mount)
    except ValueError as exc:
        raise MediaError(422, str(exc)) from exc
    if "/" in filename or "\\" in filename or filename in ("", ".", ".."):
        raise MediaError(422, "filename must be a bare file name, not a path")
    root_path = Path(root or REMOVABLE_ROOT)
    mount_path = root_path / name
    live = dict(_mount_dirs(root_path))
    if name not in live:
        raise MediaError(
            409,
            f"nothing is mounted at {mount_path} on this node. Plug the stick in and mount "
            "it from Fleet -> the appliance -> Removable storage; a removable disk is "
            "per node, so use the node it is plugged into.",
        )
    match: MediaImage | None = None
    for subdir in (MEDIA_SUBDIR, ""):
        directory = live[name] / subdir if subdir else live[name]
        if subdir and (directory.is_symlink() or not directory.is_dir()):
            continue
        image = _describe(name, directory, subdir, filename)
        if image is not None:
            match = image
            break
    if match is None:
        raise MediaError(
            404,
            f"{filename!r} is not an upgrade image on {name!r} (expected "
            "spatiumddi-appliance-slot-<version>-<arch>.raw.xz as a regular file).",
        )
    if match.problems:
        raise MediaError(422, f"{filename}: " + "; ".join(match.problems) + ".")
    return match


def open_image(image: MediaImage) -> int:
    """Open the image read-only, refusing a symlink swapped in since the scan.

    Returns a file descriptor the caller owns. Re-checks the size on the
    open handle, so the size seen is the size read.
    """
    try:
        fd = os.open(image.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as exc:
        raise MediaError(
            409, f"could not open {image.filename} (was the stick removed?): {exc.strerror or exc}"
        ) from exc
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size > UPGRADE_IMAGE_MAX_BYTES or st.st_size == 0:
        os.close(fd)
        raise MediaError(422, f"{image.filename} is not a regular file within the size limit.")
    return fd
