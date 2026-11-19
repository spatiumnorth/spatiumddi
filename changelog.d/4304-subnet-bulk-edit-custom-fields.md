### Fixed

- The subnet Bulk edit dialog now has the custom-field controls the address one has (tick a field to write it; a ticked field left empty clears it). The subnet bulk-edit API (`POST /ipam/subnets/bulk-edit`) now merges `tags` and `custom_fields` into each subnet's existing values per key, and a key set to `null` is removed; previously it replaced the whole dict, which would have wiped every other custom field on the selected subnets (#4304).
