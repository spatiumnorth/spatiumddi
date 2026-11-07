### Fixed

- A HELD (E911) lookup posted through the appliance's web front while the api has no ready endpoint now gets a retryable `503` with `Retry-After` and an RFC 5985 `generalLisError` document, instead of nginx's HTML "405 Not Allowed"; the ACME http-01 challenge path likewise answers a JSON `502` instead of the starting page (#3679).
