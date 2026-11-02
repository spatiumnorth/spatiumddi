### Fixed

- Editing a subnet's gateway now follows New Subnet's rules. The new gateway address gets its own reserved `Gateway` row and the old default `Gateway` row is retired, so Next available no longer offers the subnet's router address to the next host (a renamed or operator-owned old row is kept); and a gateway on the subnet's network or broadcast address is refused with a 422 naming it, as it is on New Subnet, instead of being stored.
