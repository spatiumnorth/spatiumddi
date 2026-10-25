### Fixed

- **A service's Summary shows only the attached rows you may read.** For an
  MPLS L3VPN service, `GET /api/v1/services/{id}/summary` filled the VRF,
  edge-site, edge-circuit and edge-subnet sections for any caller who could
  read the service, including a role with no `read` on `vrf` or `circuit`
  (the built-in IPAM Editor). Each attached row is now included only when the
  caller may read it through its own router; the rest are counted in a new
  `withheld` map and carry no name, id or value. The Summary tab says how many
  are not shown (no read permission). Attaching a resource to a service
  (`POST /api/v1/services/{id}/resources`) now needs `read` on that resource,
  and answers 403 without saying whether the id exists. Superadmin and roles
  with `read` on those types see the same summary as before.
