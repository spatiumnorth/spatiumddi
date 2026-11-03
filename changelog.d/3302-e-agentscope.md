### Fixed

- The `agent` API-token scope is retired. It was described as the agent push surface, but those routes only accept the agent's own credentials, so an `sddi_*` token could never use it. Creating or updating a token with it is now refused with an explanation, and it is gone from the scope picker. A token that already holds it still can do nothing; it does not become unrestricted.
