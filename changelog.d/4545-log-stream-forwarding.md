### Added

- The DNS query log and the DHCP activity log can now be forwarded to syslog / SIEM collectors through the existing Audit Event Forwarding targets: two per-target switches (off by default) with filters by server group, server, response code, query type and DHCP message code, optional query sampling, and the RFC 5424 JSON, RFC 3164 and JSON-lines formats. Delivery never slows agent ingest; a collector that cannot keep up causes counted drops and a `log_forward_dropping` alert (#4545).
