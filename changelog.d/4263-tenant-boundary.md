### Added

- Multi-tenancy phase 1: a tenant owns IP spaces, and groups bound to it confine their members to those spaces on every IPAM page, search, export and Copilot tool. Other tenants' rows are simply absent (a guessed id reads not found), routes that are not tenant-aware are refused to tenant users, and an install with no tenants behaves as before. Administration gains a Tenants page; API tokens can be pinned to a tenant. (#4263)
