### Fixed

- A read-only account (the Viewer role) can now use the POST routes that only read. `POST /ipam/spaces/{id}/find-free`, `POST /ipam/blocks/{id}/plan-allocation` and `POST /av/allocation-preview` answered 403 "need 'write'" because the permission gate read every POST as a write; a route marked read-only is now gated on `read`. Resize, import and bulk-allocate previews are still refused to a read-only account.
- A `read` API token can use the four previews that only read the database: `POST /appliance/acme/preview`, `POST /appliance/firewall/preview`, and the two `POST /wake-scheduler/.../preview-targets` routes.
- `POST /held` (E911 HELD location request) works with a `read` API token and with an account holding only `e911_location: read`. The E911 doc no longer tells operators to scope a token with a path that does not exist.
- `POST /logs/dns-queries/analytics` serves a token bound to subnets or DNS zones the way `POST /logs/dns-queries` does, instead of being refused by the token-binding check.
- `GET /dns/groups/{id}/options` no longer writes a default options row on first read; it returns the defaults and the row is created when the options are first saved.
