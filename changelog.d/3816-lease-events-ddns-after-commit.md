### Fixed

- DHCP agent: on a Kea HA pair, a burst of first acquisitions no longer makes both members' lease-events batches queue on the DNS zone row for the whole batch. A batch's DDNS publishes now run after its mirror rows commit, in short transactions that grow with the box's speed (8 names, up to as many as take about 2 s; a fast box makes few commits, so a batch is not slower than before) (zone rows taken in id order after the address rows, as before), so the other member's batch waits about 2 s at most; a replay of the batch is still a duplicate by its receipt (#3816).
