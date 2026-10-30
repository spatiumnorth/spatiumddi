### Fixed

- IPAM Allocate IP and Bulk allocate now offer and send the DNS zone the subnet names today: both re-read the subnet's DNS settings each time they open (an Edit Subnet that moved the primary zone no longer leaves the old zone showing for 30 s), Allocate and Preview wait until the zones have loaded instead of storing an address with no DNS record, and Bulk allocate offers a forward zone whose name merely contains "arpa" and pre-fills the primary zone like Allocate IP does. (#3078, #3079, #3080)
