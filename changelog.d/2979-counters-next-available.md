### Fixed

- **A subnet gets the same rows and counters whichever path created it
  (#2979, #2981).** Import subnets stored the gateway but made none of the
  network / broadcast / gateway rows New Subnet makes, so Next available
  handed the gateway's address to the first host; it now makes them (the
  gateway defaults to the first host, as New Subnet does), and a gateway
  equal to the subnet's network or broadcast address is a row error.
  Import IP addresses counted every new row as allocated (an `available`
  row is free) and never touched the block counts; it now recounts the
  subnet with the product's own rule and rolls the change up every block on
  the chain. A Subnet Planner apply anchored to an existing block that
  creates no block of its own now recounts the anchor too. The three create
  paths share one placeholder-rows helper.
- **An address the counters call free is one Next available and Specific IP
  can hand out (#2980).** A row with status `available` (made by Allocate
  IP, the reservation expiry sweep or a deleted DHCP reservation) counted as
  free, but Next available skipped it and Specific IP refused it as already
  allocated. Both now reuse the slot, replacing the `available` row; any
  other status still holds the address.
