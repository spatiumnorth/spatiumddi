### Fixed

- A DHCP scope delete now wakes its Kea servers as soon as the scope is in the Trash, instead of after the lease teardown, and a lease teardown batch that fails after the delete has committed no longer answers 500: the rest is handed to the background teardown task and the delete answers as it succeeded (#3748).
