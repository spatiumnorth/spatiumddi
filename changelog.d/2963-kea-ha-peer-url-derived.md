### Fixed

- **A Kea HA pair on appliances no longer needs `ha_peer_url` typed on
  both servers (#2963).** The config bundle renders the HA hook only when
  every Kea member of a group has a peer URL, so a pair built through Fleet
  role assignment silently never formed until someone set
  `http://<node IP>:8000/` by hand. When an appliance-hosted Kea server joins
  a host-networked `hot-standby` / `load-balancing` group that then has
  exactly two Kea members, each empty URL is derived from the node's k3s
  InternalIP (the address the join URL and the HA firewall rule already use).
  It runs on a membership change only (new agent registration, Fleet /
  Copilot role assignment, a server's group change), so an agent restart
  never refills a URL an operator cleared. Never derived: an operator-set
  URL, a `standalone` group (filling it would render an HA relationship with
  `mode: standalone`, which Kea rejects), `bridged` groups, non-appliance
  members, and a third or later member (it would join as a backup and could
  take the primary role from the live pair). The DHCP group response gains
  `ha_peer_urls_missing` and `ha_autofill_skipped_reason`, shown as a warning
  on the group page. A derived URL is not refreshed if the node is
  re-addressed.
