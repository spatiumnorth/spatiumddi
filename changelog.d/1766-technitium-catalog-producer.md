### Fixed

- **Catalog zones work on the agent-managed Technitium driver (#1766).**
  Turning the catalog on used to make every member zone take the
  catalog zone's transfer Deny and notify None, which undid the TSIG
  transfer grant: drift checks, Sync with Servers and external
  secondaries were all refused, and no NOTIFY went out. The agent now
  sets the override flags on every member so each keeps its own
  transfer, notify and query-access settings, and configures the
  catalog zone's own transfer (the group's keys and ACL) and notify
  (the also-notify addresses) so a secondary can read the catalog.
  Technitium is producer-only, like BIND9 and PowerDNS. The 422 that
  refused enabling catalog zones on a Technitium group, moving or adding
  a Technitium server to one, or assigning a Technitium appliance to one
  is lifted; it stays for the agentless `technitium_api` driver, which
  writes no catalog state.
