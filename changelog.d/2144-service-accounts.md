### Added

- Service accounts: API access for an external system (Home Assistant, Ansible, a monitoring poller, CI) without inventing a person. A service account has no password and cannot sign in by any path, holds groups and roles like a user, and authenticates only with tokens a superadmin mints for it under Administration → Service Accounts (`/api/v1/service-accounts`), using the usual scopes, resource bindings, expiry and one-time reveal. It stays out of the user list, is never a superadmin, cannot manage itself or mint itself tokens, has its tokens revoked when disabled, and every change it makes is audited under its name with `auth_source=service` (new `auth_source` and `user_id` filters on the audit log). New copilot tool `find_service_accounts` (#2144).

### Migrations

- `e3a9c5f17b26` — #2144, an API token's creator becomes nullable with `ON DELETE SET NULL`, so deleting the superadmin who minted a service account's token keeps the token instead of being refused.
