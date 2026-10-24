### Added

- **Logs → DNS Queries and DHCP Activity read a whole server group,
  or every server, not one server at a time (#2120).** A group behind
  one load-balanced address spreads a client's queries across its
  servers, so "did this client ask for this name?" used to mean opening
  each server in turn. The server picker is now grouped: `All servers`,
  then per group `<Group> (all N servers)` followed by its servers, and
  a server's hostname is shown only when it differs from its name. The
  results gain a Server column whenever more than one server is
  selected, and the analytics panels (top names, top clients, qtype,
  view, result) roll up across the whole selection.
  `POST /logs/dns-queries`, `/logs/dns-queries/analytics` and
  `/logs/dhcp-activity` take an optional `server_id` and an optional
  `group_id` (neither = every server); each row carries `server_id`
  and `server_name`, and the response lists the `server_ids` it
  covered. The filter is never trusted on its own: the selection is
  intersected with the servers the caller may read, so a `read` grant
  on `server` scoped to one server or one server group sees only that
  through the group and "all" filters (another group answers 403).
  This also closes a gap where an API token bound to one server could
  read any server's query log by naming it, because the single-server
  read never checked the token's binding.
  `GET /logs/agent-sources` lists only readable servers, with their
  group. The Copilot tools `find_dns_queries`, `query_dns_query_log`
  and `query_dhcp_activity_log` take the same `server_id` / `group_id`
  and share the resolution (`app/services/logs/agent_logs.py`). Also:
  the search box now matches `%` and `_` literally.

### Changed

- **Logs → DNS Queries and DHCP Activity rows open in full (#2246).**
  The grids cut the client, qname and raw columns off at one line, and
  the rest was only a hover tooltip, which cannot be selected or
  copied, does not work on touch, and is clipped for long lines. Each
  row now starts with a details button that opens every field
  untruncated: the timestamp in full ISO plus local time, client
  `ip#port` and view, qname / qtype / qclass, the result, the answer
  count, flags, and the raw line in a wrapping block with a Copy
  button. The result uses the grid's wording: NODATA for NOERROR with
  no answers, and "not recorded" when response logging is off, never
  NOERROR (#914). A DNS row's details also offer Filter by client and
  Filter by qname. DHCP rows show severity, log code, MAC, IP,
  transaction id and raw the same way.
