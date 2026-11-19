### Fixed

- Restoring a DHCP scope from the Trash whose prefix a live scope of another IP space now holds is still refused, but the message names that scope and says to deactivate or delete it first, instead of the create's advice to use a separate DHCP server group, which a restore cannot follow (#4363).
