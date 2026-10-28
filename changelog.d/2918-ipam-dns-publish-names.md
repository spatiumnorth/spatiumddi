### Fixed

- **IPAM publishes only names the record API would accept (#2918,
  #2919, #2920, #2921).** An A or AAAA owner under a zone whose own
  name carries an underscore label (`_lab.example.test`) was published
  by Allocate IP although the record API refuses it and BIND holds the
  zone back; the publish path now runs the record API's check-names
  rule on the full owner. The request paths answer 422 naming the
  label, background paths skip the zone. The rule also covers an A
  alias in such a zone, and the default gateway placeholder, whose PTR
  names `gateway.<zone>`: BIND refuses a reverse zone whose PTR target
  is not a host name, so that PTR is no longer written there. An edit
  that changes neither the hostname nor the zone runs no DNS sync and
  is not refused. The Kea (and ISC / Windows)
  DHCP import imported reservation hostnames the static form refuses,
  and the next save published them; such a hostname is now imported
  as blank with a warning in the preview and the commit result that
  names the reservation and the source hostname, and
  the commit holds the rule against a hand-edited plan. Bulk
  allocate's preview now returns the commit's 422 when a name would
  pass 253 characters (or break check-names) in the zone, instead of
  promising it. The address import's "DNS records published" counts
  only rows actually published; a row skipped for its name is listed
  in the result's errors, and a subnet with no zone is simply not
  counted.
