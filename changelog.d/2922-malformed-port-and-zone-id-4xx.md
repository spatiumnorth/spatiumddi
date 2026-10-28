### Fixed

- **A forwarder or also-notify port written in non-ASCII digits is a
  422, not a 500 (#2922).** `192.0.2.1@²` and `192.0.2.1 port ²` passed
  the port rule's `str.isdigit()` test and then crashed `int()`. The
  rule, and the same test in the zone masters validator, the port-53
  check and the DoT forwarder renderer, now require ASCII digits, as do
  the other places that parsed a number that way (BACnet search, overlay
  DSCP, cloud and Technitium MX / SRV / SVCB / CAA rdata, reverse-zone
  names).
- **A `dns_zone_id` that is not a UUID is a 422 on every IPAM body
  (#2923).** Next-IP allocation answered 500, and the space and block
  creates stored the value. The subnet create's rule now also covers
  space and block create and update, subnet update, address create and
  update, next-IP, bulk allocate and IPAM templates, the
  `dns_additional_zone_ids` / `extra_zone_ids` / `dns_group_ids` lists
  on the same bodies, and subnet plans (reported as a conflict, so apply
  answers 409). An empty string still means "no DNS record" on an
  address. A value an older build already stored reads as no zone
  instead of failing every allocation in the subnets that inherit it.
