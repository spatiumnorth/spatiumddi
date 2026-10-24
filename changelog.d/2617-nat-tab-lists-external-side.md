### Fixed

- **A subnet's NAT tab now lists mappings that reference it by their external
  IP (#2617).** The tab read `GET /ipam/nat-mappings/by-subnet/{id}`, which
  matched the internal side only, so an address row showing "NAT 1" sat under
  a tab saying no mapping references any IP in the subnet. The endpoint now
  matches either side, as the badge does.
