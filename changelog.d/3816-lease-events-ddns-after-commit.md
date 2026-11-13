### Fixed

- DHCP agent: on a Kea HA pair, a burst of first acquisitions no longer makes both members' lease-events batches queue on the DNS zone row for the whole batch. A batch's DDNS publishes now run after its mirror rows commit, in short transactions of a few names each (zone rows taken in id order after the address rows, as before), so the other member's batch waits for a few names at most; a replay of the batch is still a duplicate by its receipt (#3816).
