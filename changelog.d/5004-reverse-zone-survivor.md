### Fixed

- A deleted subnet's auto-generated reverse zone is now handed to a surviving subnet only when that subnet is in the zone's DNS group and view and is not an overlapping subnet of another IP space; otherwise the zone is retired with the subnet. The PTR pick also ignores a linked zone in a DNS group the subnet is not bound to (its effective groups, or the group or zone set on the subnet itself). (#5004)
