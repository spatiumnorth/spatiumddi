### Fixed

- **Integrations no longer take IP addresses from other IP spaces (#2577).**
  UniFi, Docker, Kubernetes, Proxmox, Tailscale, NetBird and Cloud looked
  up existing addresses across every IP space. Pointing one at a space
  that overlapped an operator's range made it adopt the operator's rows,
  move them into its own space (their DNS records went with them), and
  sometimes delete them. Every reconciler, OPNsense and the firewall
  mirrors included, now reads, adopts, moves, dedupes and deletes addresses
  only inside its target's own space, through one shared helper. Owned
  subnets are loaded the same way, so the subnet pass no longer renames,
  re-parents or deletes a subnet the target owns in another space.
- **Changing an integration's IP space no longer strands its old rows.**
  On its next sync an integration releases whatever it owns outside its
  current space — addresses, subnets and blocks — and never moves anything
  across spaces. A pure mirror row it created and nobody touched is
  deleted and re-created in the new space; anything else (an adopted
  operator row, one with an operator edit or audit entry, a subnet still
  holding other rows or a DHCP scope, and any row an operator registry
  points at — an OT or BACnet device, an E911 binding, a multicast
  membership, a DNS record, an address set or OT zone on a subnet, tags
  or custom fields) is un-claimed in place, keeping its
  `user_modified_at`. That last list is the same test a target delete
  applies (#2334), shared by both. When the evidence is unclear the row is un-claimed,
  not deleted. The same release frees operator rows an earlier build
  claimed in their home space without moving them.
- **A release is reported, and counted.** Each release writes its own
  audit row (`integration.release_outside_space`, with the counts), shown
  on the Integrations dashboard under the new "Recent reconciler warnings"
  list and as the target's sync warning for 24 hours. Every reconciler's
  sync audit row, log line and task result now carry a `released` block,
  and the rows a release deleted count in the sync's own deleted totals,
  which used to read 0.
- **An integration whose IP space is in Trash stops syncing.** It used to
  keep syncing into the deleted space, rebuilding its block, subnets and
  addresses as live rows inside it. Every reconciler now stops before it
  fetches or writes anything, with the sync error "its IP space is in
  Trash". Restore the space or point the integration at another one.

### Added

- **Finding rows an earlier build moved.** A new superadmin report,
  `GET /api/v1/ipam/integration-space-audit` (Operator Copilot:
  `find_cross_space_integration_adoptions`), lists integration-owned rows
  that were created by an operator or predate the integration and whose
  address also exists in another space, with the subnets they may have come
  from. `likely_cross_space` is set only on evidence the row lived in
  another space (a DHCP reservation there, or the row predating every
  subnet of its own space that holds it); without it the row is marked
  `needs_review`, since an ordinary same-space adoption looks the same. It
  changes nothing. Troubleshooting → "An integration took IP addresses from another
  IP space" walks through putting them back by hand.
