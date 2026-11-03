### Fixed

- Disabling a user now also revokes the user's API tokens, as it already ended their sessions, and the update's audit row records the count (`api_tokens_revoked`). Re-enabling the account does not bring the tokens back; mint new ones. The Edit user dialog says so before Save.
