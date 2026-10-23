### Fixed

- **Resize with "Move gateway" now reserves the new gateway
  (#2413).** The commit wrote the new address into the subnet's
  `gateway` field and nothing else, so no row marked it and Next
  available offered the router's own address to the next host. The
  new gateway is now reserved the way creating a subnet reserves
  one, the old default "Gateway" row is retired, and the resize is
  refused (409, and a preview conflict) when a host already holds the
  new first-usable address.
