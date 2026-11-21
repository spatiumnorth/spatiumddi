### Fixed

- **A zone removed from a PowerDNS server now stops being served
  (#4564).** The PowerDNS agent created and updated zones and never
  deleted one, so a deleted zone, a zone moved to another group, the
  old group's zones after a server move, a zone converted to forward, a
  secondary whose primaries were removed and a switched-off catalog
  zone all kept answering authoritatively with the data they last had.
  The agent now keeps a ledger of the zones it manages and deletes the
  ones the bundle no longer carries, once the control plane has
  confirmed that bundle; it deletes nothing while running from its
  cached config with the control plane unreachable. On the first start
  after the upgrade the agent adopts every zone PowerDNS holds, so
  zones orphaned by earlier releases are removed as well. A zone
  created by hand in the agent's PowerDNS and not present in
  SpatiumDDI is removed with them: add it in SpatiumDDI before
  upgrading to keep it.
  The first run after the upgrade removes zones on the PowerDNS server
  that SpatiumDDI does not manage, including any created there by hand.
  A pass that would delete every managed zone (an empty bundle, or one
  carrying none of them) is held instead: nothing is deleted, the server
  row shows a warning, and removal resumes once a bundle carries a zone.
  Set `PDNS_ALLOW_EMPTY_RETIRE=1` on the agent to allow an empty server.
