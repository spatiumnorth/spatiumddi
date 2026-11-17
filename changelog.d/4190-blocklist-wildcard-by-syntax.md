### Changed

- **Blocklist feed entries follow their own syntax (#4190).** A hosts-format line (`0.0.0.0 host`) or a bare domain now blocks only that name, one RPZ record, while an adblock `||name^` rule or a `*.name` line still blocks the name and its subdomains. A hosts-format list therefore renders half the records and no longer blocks subdomains the feed never named, matching AdGuard Home. The per-list switch is now a three-way setting, *By syntax* (the default), *Always* and *Never*, in the list's edit form and as `feed_wildcard_mode` in the REST API and the copilot's list tool. The old `feed_entries_are_wildcard` boolean is still returned and accepted (true means Always, false means Never). Catalog sources that publish plain domains meaning "and everything under them" (HaGeZi `wildcard/`, OISD `domainswild`) are set to Always.

### Migrations

- `b6d2e9f41a07` — #4190, adds `dns_blocklist.feed_wildcard_mode` and backfills it from `feed_entries_are_wildcard`, which stays (deprecated) for rolling upgrades. A list that had the box unticked becomes Never, one subscribed to a HaGeZi `wildcard/` or OISD `domainswild` feed becomes Always, every other list becomes By syntax and has its stored entries restamped by its next refresh.
