### Fixed

- **Re-enabling an expired API token is refused instead of reporting
  success (#3120).** `PATCH /api-tokens/{id}` returned 200 with
  `is_active: true` for a token whose expiry had passed, and the token
  kept answering 401 "API token has expired". It now answers 422 saying
  the token has expired and a new one must be created, and the Api tokens
  page shows Re-enable disabled, with that reason, on an expired row.
