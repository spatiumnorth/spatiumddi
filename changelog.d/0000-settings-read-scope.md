### Fixed

- `GET /settings`, `GET /groups` and `GET /roles` no longer answer every signed-in account in full: the complete settings document needs `read` on `settings` (anyone else gets only the fields the console shell and ordinary pages use), and groups and roles need `read` on `group` / `role`. The Copilot settings tools carry the same requirement, and a grant scoped to one IP space can no longer change the install-wide default-space flag.
