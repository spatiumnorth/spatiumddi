### Fixed

- **Integrations no longer take IP addresses from other IP spaces (#2577).**
  UniFi, Docker, Kubernetes, Proxmox, Tailscale, NetBird and Cloud looked
  up existing addresses across every IP space. Pointing one at a space
  that overlapped an operator's range made it adopt the operator's rows,
  move them into its own space (their DNS records went with them), and
  sometimes delete them. Every reconciler, OPNsense and the firewall
  mirrors included, now reads, adopts, moves, dedupes and deletes addresses
  only inside its target's own space, through one shared helper. A row
  that carries an integration's claim but sits in another space is left
  where it is and reported in the sync warnings.

### Added

- **Finding rows an earlier build moved.** A new superadmin report,
  `GET /api/v1/ipam/integration-space-audit` (Operator Copilot:
  `find_cross_space_integration_adoptions`), lists integration-owned rows
  that were created by an operator or predate the integration, together
  with the subnets in other spaces they probably came from. It changes
  nothing. Troubleshooting → "An integration took IP addresses from another
  IP space" walks through putting them back by hand.
