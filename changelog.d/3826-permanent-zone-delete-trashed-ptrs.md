### Fixed

- Deleting a live shared auto reverse zone for good (`?permanent=true`, or the copilot's `delete_dns_zone`) is now refused with a 409 naming the subnets whose trashed PTR records sit in it, instead of destroying them and leaving that subnet's restore without its PTRs and reverse zone.
