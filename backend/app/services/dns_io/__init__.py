"""DNS zone-file parsing, diffing, and writing.

All zone-file I/O lives here so routers remain thin and driver/service
code does not leak into the API layer (see CLAUDE.md non-negotiable #10).

Public API:
    parse_zone_file(text, zone_name) -> list[ParsedRecord]
    diff_records(parsed, existing) -> ZoneDiff
    write_zone_file(zone, records) -> str
"""

from app.services.dns_io.diff import (
    RecordChange,
    ZoneDiff,
    apply_cname_rule,
    diff_records,
)
from app.services.dns_io.parser import (
    ParsedRecord,
    ZoneParseError,
    parse_zone_file,
)
from app.services.dns_io.writer import write_zone_file

__all__ = [
    "ParsedRecord",
    "ZoneParseError",
    "parse_zone_file",
    "RecordChange",
    "ZoneDiff",
    "diff_records",
    "apply_cname_rule",
    "write_zone_file",
]
