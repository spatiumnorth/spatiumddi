### Changed

- **One set of security response times, and a deprecation rule for
  `/api/v1` (#3399).** `SECURITY.md` now promises what the website
  does: an acknowledgement within two business days and an initial
  assessment within five (it said 48 hours and 7 days). `docs/API.md`
  now says how `/api/v1` changes from 1.0.0: within 1.x it only grows,
  anything going away is deprecated at least one minor release ahead,
  and the removal itself waits for the next major release.
