### Fixed

- **An approved IP request with a hostname now creates its DNS
  record (#2900).** The `create_ip_address` operation, which the
  request portal's approve and the copilot's apply both run, inserted
  the address and published nothing, so the zone held no A record
  for it even though a manual allocation in the same subnet did. A
  named address now goes through the same create the REST endpoint
  runs: the A (or AAAA) record in the subnet's effective zone, the
  collision and dynamic-pool checks, MAC history, the static-DHCP
  reservation and utilisation. A name DNS refuses, or a collision,
  fails the apply and nothing is created; the request stays pending
  with the reason. The preview now names the record it will publish.
  Applying a named address now also needs write on the subnet, as
  the REST create does.
  An address without a hostname, which has no DNS to publish, now
  also records its MAC history, gets its static-DHCP reservation
  and updates the subnet and block utilisation, which it skipped
  before.
