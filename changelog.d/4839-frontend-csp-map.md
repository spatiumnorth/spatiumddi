### Fixed

- The frontend's own 400 response for a request whose headers cannot be parsed now carries the Content-Security-Policy header and no longer logs an uninitialized-variable warning; the policy is an nginx `map` instead of a `set` in both frontend configs (#4839).
