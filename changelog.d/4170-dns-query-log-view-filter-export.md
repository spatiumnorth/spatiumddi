### Added

- **Logs → DNS Queries: a View filter and an export (#4170, #4171).**
  The filter bar gains a View select listing the server group's
  configured views (including ones with no traffic yet), and a chip
  naming the active view whether it came from the select or the "By
  view" card. A new Export CSV / Export JSONL control downloads exactly
  the rows the current filters select, through
  `GET /api/v1/logs/dns-queries/export.csv` and `.jsonl`. The file is
  streamed, capped at 100,000 newest rows (`X-Export-Truncated: true`
  and a note on the page when capped), has spreadsheet-formula cells
  quoted, and each export writes an audit row recording the filter. The
  copilot's `find_dns_queries` tool also takes a `view`.
