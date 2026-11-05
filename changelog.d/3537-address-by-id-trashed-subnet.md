### Fixed

- IPAM: an address whose subnet is in the Trash is no longer readable or writable by its own id. `GET`, `PUT`, `DELETE` and the alias, MAC-history, network-context, profile and NAT-by-IP routes answer 404 like the subnet does, bulk edit and bulk delete report such rows as not found, and a MAC set through the API can no longer be stored under a trashed subnet and raise new-device alerts after the restore (#3537).
