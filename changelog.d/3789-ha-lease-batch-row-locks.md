### Fixed

- On a Kea HA pair, the second member's report of a renewal that changes nothing no longer waits for the first member's whole lease batch on the shared IPAM address rows, and on a first acquisition the second member no longer waits on the first's uncommitted insert of the same address (which could hit the 30 s timeout and answer 503); the member already writing the row is left to finish it (#3789).
