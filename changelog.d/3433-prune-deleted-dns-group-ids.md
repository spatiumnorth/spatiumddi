### Fixed
- Deleting a DNS server group now removes its id from every IP space, block and subnet that referenced it (Trash included), so Edit Subnet no longer shows "Inheriting from parent: 1 group(s)" and the effective DNS no longer resolves to a deleted group. A migration cleans ids already stranded by earlier deletes. (#3433)
