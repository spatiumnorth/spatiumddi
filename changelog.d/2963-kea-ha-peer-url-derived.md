### Fixed

- **A Kea HA pair on appliances no longer needs `ha_peer_url` typed on
  both servers (#2963).** The config bundle renders the HA hook only when
  every Kea member of a group has a peer URL, so a pair built through Fleet
  role assignment silently never formed until someone set
  `http://<node IP>:8000/` by hand. An empty URL on an appliance-hosted Kea
  member of a host-networked group with two or more Kea members is now
  derived from the node address the supervisor reports, at agent
  registration and at Fleet / Copilot role assignment. A URL an operator set
  is never overwritten; `bridged` groups and non-appliance members stay
  manual (the node IP is not what Kea listens on there). The DHCP group
  response gains `ha_peer_urls_missing`, naming members that still block HA.
