### Fixed

- `GET /api/v1/ipam/subnets/{id}/addresses` no longer returns every row of a subnet in one response: a call with no `limit` is capped at 10,000 rows (and `limit` may not exceed that). A cut-short list says so with `X-Result-Truncated: true` and a `Warning` header, and `X-Total-Count` still carries the full count, so clients should page with `limit` / `offset`. The IPAM page now loads a subnet's addresses in pages, and the orphan, edit-subnet and bulk-edit dialogs ask only for the rows they need.
