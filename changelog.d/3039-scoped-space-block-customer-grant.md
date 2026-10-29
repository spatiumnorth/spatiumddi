### Fixed

- A role scoped to one IP space, IP block, customer, site or provider in the Roles dialog now lets its holder read and edit that item (and see it in the list) instead of getting 403 on it, as a subnet-scoped role already did; it still reaches nothing else of its type, nothing inside it, and cannot re-point the item at other resources (#3039).
