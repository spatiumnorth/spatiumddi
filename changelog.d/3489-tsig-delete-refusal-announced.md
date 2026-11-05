### Fixed

- DNS and IPAM: a refused delete in the two-step confirm dialogs (TSIG key, DNS server group, zone and bulk zone delete; IP block, subnet and both IPAM bulk deletes) now announces the server's reason as an alert, so a screen reader says the delete failed instead of the reason only being shown on screen (#3489).
