### Fixed

- Deleting an operator-made DNS zone for good (`?permanent=true`, the copilot's `delete_dns_zone`, or its Trash row) is now refused with a 409 naming the subnets whose trashed records sit in it, instead of destroying them and leaving that subnet's restore without its records.
- The daily Trash expiry sweep likewise keeps an expired operator-made zone while another trashed subnet's records still sit in it, and takes it once that subnet is purged or restored.
