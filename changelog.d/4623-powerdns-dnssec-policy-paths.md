### Fixed

- A custom DNSSEC policy is now refused on every path into a PowerDNS group, not only the zone update and Sign: the Copilot `sign_zone_dnssec` proposal (preview and apply), a zone move into the group, and a server joining a group whose zones hold one are all refused with the reason. A zone that still holds a custom policy on a PowerDNS group (stored before the upgrade, or restored from a backup) now reports `unapplied_warning` on its DNSSEC info and shows it in the zone's DNSSEC card. (#4623)
