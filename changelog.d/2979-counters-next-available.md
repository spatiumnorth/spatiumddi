### Fixed

- **A subnet gets the same rows and counters whichever path created it
  (#2979, #2981).** Import subnets stored the gateway but made none of the
  network / broadcast / gateway rows New Subnet makes, so Next available
  handed the gateway's address to the first host; it now makes them (the
  gateway defaults to the first host, as New Subnet does), and a gateway
  equal to the subnet's network or broadcast address is a row error, named
  in the preview as well as at commit. An imported multicast subnet is now
  stamped `multicast` (it was stored as unicast) and, like one made with New
  Subnet, gets no placeholder rows.
  Import IP addresses counted every new row as allocated (an `available`
  row is free) and never touched the block counts; it now recounts the
  subnet with the product's own rule and rolls the change up every block on
  the chain. A Subnet Planner apply anchored to an existing block that
  creates no block of its own now recounts the anchor too. The recounts run
  once at the end, batched: one grouped count for the subnets and each block
  on their chains recounted once, rather than per row. The three create
  paths share one placeholder-rows rule.
- **An address the counters call free is one Next available and Specific IP
  can hand out (#2980).** A row with status `available` (made by Allocate
  IP, the reservation expiry sweep or a deleted DHCP reservation) counted as
  free, but Next available skipped it and Specific IP refused it as already
  allocated. Both now take the slot over in place: the row keeps its id (so
  its MAC history and the OT / BACnet / E911 registrations hanging off it
  are not cascade-deleted), any A / PTR / alias records it still published
  (the reservation sweep leaves them) are retracted, every other field is
  reset, and the take is audited with what it replaced. Any other status
  still holds the address, and so does an `available` row a DHCP
  reservation still points at.
