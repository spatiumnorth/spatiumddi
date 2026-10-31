"""DHCP configuration importer (issue #129).

Three sources, one canonical IR. Each source module parses the upstream
config (Kea JSON file, Windows DHCP WinRM live-pull, ISC ``dhcpd.conf``)
into :class:`ImportPreview`; the shared :func:`commit_import` writes the
IR to the DB stamping ``import_source`` + ``imported_at`` on every row
it creates so the provenance is queryable later.

Sister to :mod:`app.services.dns_import` — same preview/commit contract,
DHCP scopes instead of DNS zones.
"""

from .canonical import (
    ConflictAction,
    ImportedClientClass,
    ImportedPool,
    ImportedReservation,
    ImportedScope,
    ImportPreview,
    ImportSource,
    ScopeConflict,
)
from .commit import (
    CommitResult,
    CommitScopeResult,
    commit_import,
    detect_conflicts,
    drop_invalid_pools,
    drop_unservable_hostnames,
)
from .isc_dhcp_parser import IscImportError, parse_isc_config
from .kea_parser import KeaImportError, parse_kea_config
from .windows_dhcp_pull import WindowsDHCPImportError, parse_windows_dhcp_server

__all__ = [
    "CommitResult",
    "CommitScopeResult",
    "ConflictAction",
    "ImportPreview",
    "ImportSource",
    "ImportedClientClass",
    "ImportedPool",
    "ImportedReservation",
    "ImportedScope",
    "IscImportError",
    "KeaImportError",
    "ScopeConflict",
    "WindowsDHCPImportError",
    "commit_import",
    "detect_conflicts",
    "drop_invalid_pools",
    "drop_unservable_hostnames",
    "parse_isc_config",
    "parse_kea_config",
    "parse_windows_dhcp_server",
]
