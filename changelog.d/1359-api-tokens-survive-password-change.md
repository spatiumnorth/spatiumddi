### Fixed

- A password change, an admin reset or linking an external account to its provider now reports how many live API tokens the account still holds (they survive it, as AUTH.md now says), accepts an opt-in `revoke_api_tokens` to revoke them, and a new "Revoke all API tokens" action (self: `POST /api-tokens/revoke-all`; admin: `POST /users/{id}/revoke-api-tokens`) revokes them without a password change (#1359).
