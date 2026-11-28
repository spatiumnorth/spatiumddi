### Fixed

- A count of one now reads in the singular across the console, not just on the Overview: "of 1 subnet", "of 1 token", "1 node", "1 container", "1 policy", "1 scope", "1 host" and about 40 more lines that said "1 subnets", "1 tokens" and the like. A guard test scans the console source and fails any new count glued to a fixed plural word (#4780).
