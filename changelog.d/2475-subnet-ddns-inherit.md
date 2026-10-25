### Fixed

- **New Subnet and Edit Subnet show and keep inherited DDNS (#2475).** The DDNS tab showed "Enabled" unticked for a subnet that inherits DDNS on from its block, and an untouched Edit Subnet Save on a subnet that inherited a stored `ddns_enabled: true` ended the inheritance. The tab now has an "Inherit from parent" toggle (on by default for a new subnet) that shows the effective setting and where it comes from, and a Save while inheriting sends only `ddns_inherit_settings`. New read endpoints `GET /ipam/subnets/{id}/effective-ddns` and `GET /ipam/blocks/{id}/effective-ddns` back it.
