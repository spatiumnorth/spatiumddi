### Fixed

- Deleting a DHCP scope, or a subnet, block or space that holds DHCP scopes, no longer answers 503 while both members of a Kea HA pair report lease renewals for those scopes. The delete used to wait behind an endless line of overlapping lease batches; it now waits only for the batches already running, and later ones queue behind it and find the scope in the Trash (#3748).
