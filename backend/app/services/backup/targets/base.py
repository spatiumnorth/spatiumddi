"""Backup destination ABC + registry (issue #117 Phase 1b).

A ``BackupDestination`` is the boundary between
``app.services.backup.archive`` (which builds a zip in memory) and
the storage backend (local volume, S3, SCP, Azure Blob, …). Each
driver implements four operations:

* :meth:`write` — accept ``bytes`` + filename, persist them.
* :meth:`list_archives` — return the stored archives newest-first.
* :meth:`delete` — drop one archive by filename. Used by the
  retention sweep + the manual delete UI.
* :meth:`test_connection` — write a tiny probe file, list it,
  delete it. Mirrors the existing DNS / DHCP server probe pattern.

The ABC also declares :attr:`config_fields` — the per-kind
config-shape descriptor the API layer uses to validate the
``config`` JSONB blob on create / update without baking knowledge
of every driver into the router.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

#: The archive names SpatiumDDI writes. Every driver filters its listing
#: with this so a destination shared with unrelated files stays clean.
#:
#: Shared rather than copied per driver: a change to the naming scheme that
#: missed one file would make that destination's retention sweep and
#: ``latest/download`` silently blind, with no error anywhere.
#:
#: The middle excludes path separators and control characters (#1243) so
#: the listing can never offer a name :func:`safe_filename` then refuses —
#: an object-store key under a nested "directory"
#: (``spatiumddi-backup-x/y.zip``) would otherwise be listed, picked as
#: ``latest``, counted by retention, and fail every download / delete.
ARCHIVE_NAME_RE = re.compile(r"^(spatiumddi-backup-|pre-restore-)[^/\\\x00-\x1f\x7f]*\.zip$")

#: Prefix of the pre-restore safety dumps ``restore`` writes into the
#: same directory a local-volume target is usually pointed at.
PRE_RESTORE_PREFIX = "pre-restore-"

#: How many safety dumps retention keeps. They are rollback copies,
#: not backups: they get their OWN small allowance (#1574) so they
#: neither consume the target's configured keep count nor pile up
#: without bound.
PRE_RESTORE_KEEP_LAST_N = 3


def is_pre_restore_archive(filename: str) -> bool:
    """True for a pre-restore safety dump, as opposed to a real backup
    archive. The two share a listing (and, on the recommended
    local-volume path, a directory) but not a passphrase, a retention
    policy, or a meaning for "latest" (#1574)."""
    return filename.startswith(PRE_RESTORE_PREFIX)


def safe_filename(filename: str) -> str:
    """Return *filename* if it is one plain path component, else refuse it.

    This is the defence that stops a crafted archive name escaping the
    configured directory / prefix / collection, so it lives in one place
    rather than being re-inlined per driver — hardening it in one copy
    while others stayed as they were is the failure worth avoiding.

    It REFUSES rather than strips (#1243). The old ``os.path.basename``
    stripped separators and let ``..`` through unchanged, because
    ``basename("..") == ".."`` — and ``..`` is not a name inside the
    collection, it is the collection's parent. On WebDAV ``urljoin`` turns
    it into the parent collection's URL, so deleting an archive called
    ``..`` sent a recursive ``DELETE`` one level up. Stripping is also the
    wrong shape in itself: ``a/b.zip`` quietly became ``b.zip``, an
    archive the caller never named.
    """
    if (
        not filename
        or filename in (".", "..")
        or "/" in filename
        or "\\" in filename
        or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in filename)
    ):
        raise InvalidArchiveNameError(f"invalid archive name {filename!r}")
    return filename


class BackupDestinationError(Exception):
    """Generic failure inside a destination driver — wraps the
    underlying client exception with a one-line message the API
    layer surfaces verbatim to operators."""


class DestinationConfigError(BackupDestinationError):
    """The ``config`` blob is malformed for this destination kind
    (missing a required field, type mismatch, etc.). 422-shaped on
    the API side."""


class InvalidArchiveNameError(BackupDestinationError):
    """The archive name is not a single plain path component (#1243).

    Raised by :func:`safe_filename` before anything reaches the
    destination. A subclass so every existing ``except
    BackupDestinationError`` still catches it; the API layer catches it
    first and answers 422, since the name is the caller's mistake, not
    the destination failing.
    """


class RetentionLockedError(BackupDestinationError):
    """The destination refused a delete because the object is under a
    retention lock (issue #989 item 1).

    Distinct from a generic delete failure, and the distinction is the
    whole point: on an S3 bucket in compliance mode a refused delete is
    the feature working, so the retention sweep skips it quietly. Logging
    it as a failure would produce a warning per archive per night on
    exactly the installs that configured immutability correctly.

    A *typed* exception rather than a string match on the driver's error
    text: the message comes from the storage SDK and is not ours to
    depend on.
    """


class UnsupportedOperationError(BackupDestinationError):
    """This destination kind cannot perform the operation at all —
    ``https_put`` is a one-way send to an operator-supplied receiver, so
    it can neither read an archive back nor delete one. Distinct from a
    permission failure, because no credential change would make it work.
    """


@dataclass(frozen=True)
class ArchiveListing:
    """One archive present at a destination."""

    filename: str
    size_bytes: int
    created_at: datetime


#: ``ConfigFieldSpec.type`` value for prose that renders without an input.
NOTICE_FIELD_TYPE = "notice"


@dataclass(frozen=True)
class ConfigFieldSpec:
    """Descriptor for one field inside a destination's ``config``
    JSONB blob. The API + frontend reflect on these to render the
    per-kind form + validate input.
    """

    name: str
    label: str
    #: ``text`` / ``password`` / ``number`` render an input.
    #: ``notice`` renders as prose with NO input — for a caveat that
    #: belongs to the destination kind rather than to any one field
    #: (``nfs``: AUTH_SYS has no credential at all).
    #:
    #: A notice is never read back out of ``config``, and that is
    #: enforced rather than asserted: :func:`config_field_specs` drops
    #: notices, and every generic consumer (validation, secret
    #: redaction, PATCH merge) iterates that instead of ``config_fields``
    #: — so a client that has not learned about the type cannot make one
    #: required or round-trip its prose into stored config.
    type: str
    required: bool = True
    description: str | None = None
    secret: bool = False  # hide from list responses


def safe_url(url: str) -> str:
    """``scheme://host[:port]/path`` only, for error messages.

    A receiver URL can carry its credential in the query string (a
    presigned ``X-Amz-Signature``) or in userinfo (``user:pass@``), and an
    error message reaches ``last_run_error``, the audit log and the logs.
    """
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        if parts.port:
            host += f":{parts.port}"
    except ValueError:
        return "<unparseable url>"
    if not parts.scheme or not host:
        return "<unparseable url>"
    return f"{parts.scheme}://{host}{parts.path}"


def scrub_url(text: str, *urls: str) -> str:
    """``text`` with each full URL in ``urls`` replaced by :func:`safe_url`
    — for a library exception message that echoes the URL it was given."""
    for url in urls:
        if url:
            text = text.replace(url, safe_url(url))
            # a caller may have appended a trailing slash to what the
            # library echoed back
            if url.endswith("/"):
                text = text.replace(url.rstrip("/"), safe_url(url).rstrip("/"))
    return text


def config_field_specs(driver: BackupDestination) -> tuple[ConfigFieldSpec, ...]:
    """The driver's INPUT fields — ``config_fields`` minus notices.

    Every generic consumer (validation, secret redaction, the PATCH
    merge) wants this one, not the raw tuple: a notice carries no value
    and must never round-trip into stored ``config``. Enforcing it here
    means a future notice cannot become required, or be read back, just
    because a consumer forgot to branch on the type.
    """
    return tuple(f for f in driver.config_fields if f.type != NOTICE_FIELD_TYPE)


class BackupDestination(ABC):
    """ABC for a backup destination. Subclasses are stateless;
    every operation receives the per-target ``config`` dict and
    handles its own per-call connection lifecycle.
    """

    #: Stable identifier — also the value of ``backup_target.kind``.
    kind: str

    #: Human-readable label rendered in the destination picker.
    label: str

    #: Per-kind config-field descriptors. Empty for destinations
    #: with no configurable fields beyond name/passphrase.
    config_fields: tuple[ConfigFieldSpec, ...] = ()

    #: True when the kind has no listing and no delete *by construction*
    #: (``https_put``), as opposed to a kind whose credential merely
    #: happens to lack delete permission. The API forces
    #: ``backup_target.write_only`` on for these at create / update, so
    #: an operator cannot configure a retention policy that could only
    #: ever fail silently every night.
    inherently_write_only: bool = False

    @abstractmethod
    def validate_config(self, config: dict[str, Any]) -> None:
        """Raise :class:`DestinationConfigError` if ``config`` is
        missing a required field or has the wrong type. Called on
        every create / update + before every run.
        """

    async def validate_config_network(self, config: dict[str, Any]) -> None:
        """Optional second validation pass that is allowed to touch the
        network — a DNS resolution for the SSRF guard, say.

        Split from :meth:`validate_config` because that one runs inside a
        request handler *and* on every scheduled run, where a synchronous
        ``getaddrinfo`` would block the event loop (non-negotiable #2)
        and would make each nightly backup depend on a resolver that has
        nothing to do with reaching the destination. This hook is called
        only at create / update / test — the moments an operator is
        waiting for an answer about a URL they just typed.

        Default is a no-op; drivers that need it override.
        """
        return None

    @abstractmethod
    async def write(self, *, config: dict[str, Any], filename: str, archive_bytes: bytes) -> None:
        """Persist ``archive_bytes`` under ``filename`` at this
        destination. Must overwrite if a file with the same name
        already exists.
        """

    @abstractmethod
    async def list_archives(self, *, config: dict[str, Any]) -> list[ArchiveListing]:
        """Return all archives stored at this destination,
        newest-first by ``created_at``.
        """

    @abstractmethod
    async def download(self, *, config: dict[str, Any], filename: str) -> bytes:
        """Fetch + return the archive bytes for ``filename``. The
        restore-from-destination flow streams these straight into
        :func:`app.services.backup.restore.apply_backup_restore`
        without ever materialising the file on the api / worker
        container's local disk.
        """

    @abstractmethod
    async def delete(self, *, config: dict[str, Any], filename: str) -> None:
        """Drop ``filename`` from this destination. Idempotent —
        deleting a missing file should not raise.
        """

    @abstractmethod
    async def test_connection(self, *, config: dict[str, Any]) -> dict[str, Any]:
        """Write + list + delete a tiny probe file. Returns
        ``{ok: bool, error?: str, detail?: str}`` in the same shape
        as the existing DNS / DHCP probe surfaces.
        """


# Module-level driver registry. ``__init__.py`` populates it on
# import; the API layer looks drivers up by ``kind`` here.
DESTINATIONS: dict[str, BackupDestination] = {}


def get_destination(kind: str) -> BackupDestination:
    driver = DESTINATIONS.get(kind)
    if driver is None:
        raise DestinationConfigError(
            f"unknown backup destination kind: {kind!r} " f"(known: {sorted(DESTINATIONS)})"
        )
    return driver


def list_destination_kinds() -> list[dict[str, Any]]:
    """Return the full destination catalog for the frontend
    "pick a kind" picker. Each entry carries ``kind`` / ``label``
    plus the per-kind ``config_fields`` descriptors so the form
    can render itself.
    """
    out: list[dict[str, Any]] = []
    for kind in sorted(DESTINATIONS):
        d = DESTINATIONS[kind]
        out.append(
            {
                "kind": d.kind,
                "label": d.label,
                "inherently_write_only": d.inherently_write_only,
                "config_fields": [
                    {
                        "name": f.name,
                        "label": f.label,
                        "type": f.type,
                        "required": f.required,
                        "description": f.description,
                        "secret": f.secret,
                    }
                    for f in d.config_fields
                ],
            }
        )
    return out
