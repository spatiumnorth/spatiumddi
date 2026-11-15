### Fixed

- Permanently deleting a DHCP scope from the Trash no longer tears its remaining leases down in one long request that answers 504: they are removed in committed batches first, and when that takes longer than a few seconds the rest goes to the background task and the purge answers 409 with a Retry-After to send again (#3783).
