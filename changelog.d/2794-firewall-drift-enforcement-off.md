### Fixed

- **Fleet firewall drift no longer persists after enforcement is turned off
  (#2794).** The heartbeat stored the server's rendered hash only while
  enforcement was on and never cleared it, so every node whose last enforced
  render held a fleet or appliance rule kept showing `drift: true` (Fleet chip,
  `/effective`, the `find_firewall_effective` tool, and the apply-stalled alarm)
  with nothing to apply. With enforcement off drift is now false, the stale hash
  is cleared, and turning enforcement back on detects real drift from a fresh
  render.
