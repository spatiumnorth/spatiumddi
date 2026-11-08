### Fixed

- Resize with "Move gateway" now retracts the old gateway placeholder's PTR, as Edit Subnet's gateway move does, instead of leaving it served from the reverse zone (#3723).
- Resize and Edit Subnet's gateway move lock the old gateway row before the DNS zones they retract its PTR from, so a move running alongside a permanent delete of that reverse zone no longer deadlocks and answers 500 (#3723).
