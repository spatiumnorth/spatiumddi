"""Backup destinations (issue #117 Phase 1b+).

Each destination is a thin driver that knows how to ``write``,
``list``, ``delete``, and ``test_connection`` against its own
storage backend. Phase 1b ships ``local_volume``; Phase 1c/1d
add ``s3`` / ``scp`` / ``azure_blob``; Phase 2 Tier 2 adds
``smb`` / ``ftp`` / ``gcs``; Phase 3 adds ``webdav``; #971 adds
``nfs``. Every driver is mounted on the same
:class:`BackupDestination` ABC + module-level registry.
"""

from app.services.backup.targets.azure_blob import AzureBlobDestination
from app.services.backup.targets.base import (
    ARCHIVE_NAME_RE,
    DESTINATIONS,
    ArchiveListing,
    BackupDestination,
    BackupDestinationError,
    DestinationConfigError,
    InvalidArchiveNameError,
    RetentionLockedError,
    UnsupportedOperationError,
    get_destination,
    list_destination_kinds,
    safe_filename,
)
from app.services.backup.targets.ftp import FtpDestination
from app.services.backup.targets.gcs import GcsDestination
from app.services.backup.targets.https_put import HttpsPutDestination
from app.services.backup.targets.local_volume import LocalVolumeDestination
from app.services.backup.targets.nfs import NfsDestination
from app.services.backup.targets.s3 import S3Destination
from app.services.backup.targets.scp import ScpDestination
from app.services.backup.targets.secrets_config import (
    REDACTED_SENTINEL,
    SecretFieldError,
    decrypt_config_secrets,
    encrypt_config_secrets,
    merge_config_for_update,
    redact_config_secrets,
)
from app.services.backup.targets.smb import SmbDestination
from app.services.backup.targets.webdav import WebDAVDestination

# Side-effect register every driver. New drivers register the
# same way — no other code path needs to learn about them.
DESTINATIONS["local_volume"] = LocalVolumeDestination()
DESTINATIONS["s3"] = S3Destination()
DESTINATIONS["scp"] = ScpDestination()
DESTINATIONS["azure_blob"] = AzureBlobDestination()
DESTINATIONS["smb"] = SmbDestination()
DESTINATIONS["ftp"] = FtpDestination()
DESTINATIONS["gcs"] = GcsDestination()
DESTINATIONS["webdav"] = WebDAVDestination()
DESTINATIONS["nfs"] = NfsDestination()
DESTINATIONS["https_put"] = HttpsPutDestination()

__all__ = [
    "ARCHIVE_NAME_RE",
    "ArchiveListing",
    "BackupDestination",
    "BackupDestinationError",
    "UnsupportedOperationError",
    "DestinationConfigError",
    "InvalidArchiveNameError",
    "RetentionLockedError",
    "AzureBlobDestination",
    "FtpDestination",
    "GcsDestination",
    "HttpsPutDestination",
    "LocalVolumeDestination",
    "NfsDestination",
    "S3Destination",
    "ScpDestination",
    "SmbDestination",
    "WebDAVDestination",
    "DESTINATIONS",
    "REDACTED_SENTINEL",
    "SecretFieldError",
    "decrypt_config_secrets",
    "encrypt_config_secrets",
    "get_destination",
    "list_destination_kinds",
    "merge_config_for_update",
    "redact_config_secrets",
    "safe_filename",
]
