### Fixed

- Disabling a user now also revokes the user's API tokens, as it already ended their sessions. The user's audit row records the count (`api_tokens_revoked`) and each token gets its own audit row, as a token revoke does; a token minted while the disable is being saved is refused rather than left live. Re-enabling the account does not bring the tokens back; mint new ones. The Edit user dialog says so before Save.
