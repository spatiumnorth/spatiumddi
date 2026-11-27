### Added

- Commercial DDI live mirror: a read-only, periodically refreshed copy of an Infoblox estate (networks, ranges, fixed addresses, host / A / PTR records, zones, views) kept in its own store, with a cutover-rehearsal view of what an import would create and what differs, source management with test connection, Copilot read tools and Integrations dashboard panels. Behind the new `migration.ddi_mirror` module (off by default); nothing is written to the source or to live IPAM / DNS / DHCP. BlueCat and EfficientIP are not supported yet. (#4729)
