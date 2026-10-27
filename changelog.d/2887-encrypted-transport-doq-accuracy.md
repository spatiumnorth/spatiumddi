### Fixed

- **Encrypted-transport text and the copilot read no longer misstate
  DoQ and PowerDNS support (#2887).** The DoQ toggle in a DNS group's
  options said PowerDNS speaks none of the encrypted transports, when it
  serves DoT and DoH through the dnsdist front; it now says only DoQ is
  missing there (#2886). `docs/features/DNS.md` section 20 now covers DoQ
  (Technitium-only today). The `find_dns_encrypted_transports` MCP tool
  returned `dot_*` and `doh_*` but not `doq_enabled` and `doq_port`, so
  the copilot could not see a Technitium group's DoQ listener; it does
  now.
