### Added

- **DNS query details: block or allow the name, and see who asked
  (#4250).** The details modal on Logs → DNS Queries gains **Block
  domain…** (an exact or wildcard entry for the name or a parent, on a
  manual blocking list that applies to the row's server group or view,
  with an Undo) and, when the name is already blocked, **Allow
  domain…** (an exception, or removing a hand-made exact entry, with an
  Undo). A "Blocked by" line names the list and entry. A Client panel
  shows the IPAM address and the active DHCP lease for the client, each
  only if you may read it. A **More** menu opens the zone that serves the
  name, opens dig or whois on the Tools page with the form filled in
  (never run for you), and copies the qname, the client address or a link
  to the filter. Ask AI is in the footer. **Block client** is listed but
  disabled with the reason: nothing at the DNS level blocks one client
  yet. Each disabled control says which permission or condition is
  missing. New `GET /dns/blocklists/match` (and the
  `find_blocklist_matches` Copilot tool) answers "which lists cover this
  name, and is it blocked here?"; it is also the missing "Test a domain"
  lookup.
