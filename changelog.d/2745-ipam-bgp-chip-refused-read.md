### Fixed

- **Opening a space on the IPAM page no longer asks the Looking Glass
  of a user who may not read it (#2745).** The tree's BGP chip asked
  `GET /looking-glass/routes` once per space whatever the user's
  grants, so an IPAM, DNS or DHCP Editor was refused once per space,
  each refusal a console error and a `denied` row in the audit log.
  The chip now asks only with read on `bgp_lg_peer`, the gate #2704
  gave the page's other reads.
