### Fixed

- Sending a DHCP scope (or its subnet) to the Trash and restoring it no longer erases its reservations' MAC history: the history is saved with the Trash batch and put back on the restored address with its first-seen and last-seen times; purging the scope discards it.
