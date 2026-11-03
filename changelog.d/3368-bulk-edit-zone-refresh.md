### Fixed

- Bulk edit's DNS Zone and the Edit IP dialog read the subnet's DNS settings afresh every time they open, and Apply waits for them, so a primary zone moved in Edit Block a few seconds earlier is the one marked "(primary)" and offered instead of the zone the block left. Saving a block or an IP space now refreshes the effective DNS settings its subnets are read from (#3368).
