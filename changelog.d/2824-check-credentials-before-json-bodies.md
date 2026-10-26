### Fixed

- **The importers' JSON routes and the DNS agent routes check the caller
  before reading the body.** These routes may take bodies well above the
  app-wide 8 MiB cap (up to 50 MiB on the DNS importers, 25 MiB on the
  DHCP, IPAM and NetBox importers, and 64 MiB on the DNS agent's record
  ingest), and FastAPI read and parsed a JSON body before any dependency
  ran, so a caller with no credentials could make the api hold one in
  memory before being answered 401. Every body route on the DNS, DHCP,
  IPAM and NetBox import routers now checks the login from the request
  headers first, as the upload routes on those routers already did; and
  every body route on the DNS agent router checks the agent's bearer
  token (or, for `/register`, the bootstrap key) the same way. The
  answers are unchanged (the same 401 / 403 and error detail, and the
  same `denied` audit row), and the routes' own permission checks still
  run afterwards. One visible difference: a request with no credentials
  and a malformed body is now answered 401 rather than 422, and one to a
  disabled NetBox import module 401 rather than 404, because the
  credentials are checked first. A test now fails when a body route
  covered by a body-size allowance does not check the caller first.
