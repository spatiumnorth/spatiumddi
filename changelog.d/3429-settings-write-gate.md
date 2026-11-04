### Fixed

- Settings page: a user whose role grants `write` on `settings` now gets Save and can edit the settings the API delegates to them, plus the reverse-DNS "Run now" and OUI "Refresh now" actions, instead of "View-only - superadmin required". `GET /settings` now returns that list as `delegate_writable_fields`, which the page reads, so the page and the API cannot disagree about it; every other field stays superadmin-only (#3429).
