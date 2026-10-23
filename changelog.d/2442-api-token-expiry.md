### Fixed

- **An already-past API token expiry is refused, and expired or revoked
  tokens no longer read as active or expiring (#2442).** Creating a
  token with an `expires_at` in the past now answers 422, the API
  Tokens list shows an expired token as "Expired", and the dashboard's
  expiring card counts only active, not-yet-expired tokens.
