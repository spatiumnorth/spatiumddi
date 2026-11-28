### Added

- Logs → DNS Queries and Logs → DHCP Activity can export exactly what the current filters select as CSV or JSON Lines, from new Export buttons or `GET /api/v1/logs/dns-queries/export` and `GET /api/v1/logs/dhcp-activity/export` (`format=csv|jsonl`, same filters, scope and permission as the list). The download is streamed, stops at 100,000 rows and says so (`X-Export-Capped`), neutralises spreadsheet formulas in CSV, is named with a UTC timestamp, and writes an audit row recording who exported what. (#4171)
