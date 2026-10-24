### Fixed

- **A search, filter or chip that matches nothing no longer says the list is
  empty (#2616).** IPAM Templates, a DNS group's Zones under a tag chip, an
  IPAM block's subnets under a role chip, Domains, Sites, Customers,
  Providers, Circuits, Overlays, Certificates, ASNs, Multicast groups, VRFs,
  Network devices and Services answered "No X yet" while holding rows. They
  now say "No X match the current search or filter" with a Clear filters
  link, through one shared `ListEmpty` option; "No X yet" stays for a list
  that really is empty.
