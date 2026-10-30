### Fixed

- A role scoped to one IP space, IP block, customer, site or provider in the Roles dialog now lets its holder read and edit that item (and see it in the list) instead of getting 403 on it, as a subnet-scoped role already did; it still reaches nothing else of its type, nothing inside it, cannot re-point the item at other resources, and cannot change a setting the subnets underneath a space or block inherit, such as DDNS or do-not-probe (#3039).
