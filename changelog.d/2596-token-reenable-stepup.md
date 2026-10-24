### Changed

- **API-token re-enable requires a superadmin and step-up; widening
  a token's scopes requires step-up.** Re-enabling an inactive token
  was open to its owner with no further check. It is now
  superadmin-only and asks for the operator's password (or an
  authenticator code for an account without one), the same check that
  minting a token already needs; an owner who wants access back
  creates a new token. Widening a token's scopes, which includes
  clearing the list so the token is unrestricted, now needs the same
  check. Renaming, narrowing scopes and revoking need neither. The
  API Tokens page hides Re-enable for anyone who is not a superadmin
  and asks a superadmin for the step-up before sending it. Behaviour
  change: a script that re-enables its own token through
  `PATCH /api/v1/api-tokens/{id}` now gets a 403.
