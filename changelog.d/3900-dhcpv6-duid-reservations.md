### Fixed

- **A DHCPv6 reservation can be keyed on a DUID with no MAC, from IPAM
  and from DHCP (#3900).** The reservation table required a MAC, so
  an IPv6 `static_dhcp` address had no way to carry the DUID Kea
  matches a DHCPv6 client on. A reservation on a v6 scope now takes a
  DUID, a MAC or both, and an IPv6 IPAM address accepts a `duid` in
  the Add / Edit address dialogs, the API, the CSV import and the
  copilot tools, mirrored to the v6 scope's reservation. A v4
  reservation still needs a MAC. The MAC uniqueness check is now per
  address family, so one dual-stack host no longer 409s when it holds
  a v4 and a v6 reservation under the same MAC. Migration
  `f3a7c1d94e52` makes the reservation MAC nullable (a CHECK still
  demands a MAC or a DUID) and adds `ip_address.duid`.
