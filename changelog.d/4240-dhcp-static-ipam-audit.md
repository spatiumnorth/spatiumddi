### Fixed

- A DHCP reservation's IPAM address now writes the same `ip_address` audit row an address made through the IPAM API does (create, edit, re-address, delete), attributed to the acting user or the approver of a portal request. A `compliance_change` rule on a PCI / HIPAA / internet-facing subnet now fires for it and `ip.created` / `ip.updated` / `ip.deleted` events are emitted ([#4240](https://github.com/spatiumnorth/spatiumddi/issues/4240)).
