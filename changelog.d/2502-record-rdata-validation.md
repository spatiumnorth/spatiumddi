### Fixed

- **Record API refuses rdata dnspython cannot read (#2502).** CAA, TLSA,
  SSHFP, NAPTR, LOC, MX and SRV values were stored unchecked, and the
  BIND9 agent wrote them into the zone file verbatim, so `named-checkzone`
  refused the zone and the agent quarantined the server's whole bundle.
  Create, update (when the value changes), bulk create, the sheet import,
  the Copilot and the zone importers now 422 or skip such a row.
