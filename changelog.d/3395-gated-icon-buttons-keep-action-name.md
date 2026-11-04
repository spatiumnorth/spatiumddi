### Fixed

- Icon-only Edit, Delete, Enable and similar buttons on about 30 pages (every alert rule and conformity policy row, roles, groups, sites, domains, certificates, the integration pages and more) are no longer announced by a screen reader as just "Requires superadmin" or another refusal reason for a read-only user. Each now keeps a name for its action, with the reason still shown as the tooltip, and a test fails any new icon-only button beside a permission gate that has no `aria-label`.
