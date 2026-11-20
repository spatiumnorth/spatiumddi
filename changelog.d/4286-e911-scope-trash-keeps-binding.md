### Fixed
- Deleting a DHCP scope (or its subnet, block or space) to the Trash no longer leaves an E911 location with no active binding: a reservation's address row that a binding names stays as it is while the scope sits in the Trash, so a restore brings it back. Permanently deleting such a scope now answers 409 naming the binding, and the nightly Trash purge holds it back (#4286).
