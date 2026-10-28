### Fixed

- **A forwarder or also-notify port written in non-ASCII digits is a
  422, not a 500 (#2922).** `192.0.2.1@²` and `192.0.2.1 port ²` passed
  the port rule's `str.isdigit()` test and then crashed `int()`. The
  rule, and the same test in the zone masters validator, the port-53
  check and the DoT forwarder renderer, now require ASCII digits.
- **A `dns_zone_id` that is not a UUID is a 422 on every IPAM body
  (#2923).** Next-IP allocation answered 500, and the space and block
  creates stored the value. The subnet create's rule now also covers
  space and block create and update, subnet update, address create and
  update, next-IP and bulk allocate, and the `dns_additional_zone_ids`
  / `extra_zone_ids` lists on the same bodies. An empty string still
  means "no DNS record" on an address.
