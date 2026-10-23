### Changed

- **Sign-in budgets that no choice of source address escapes.** The
  per-source budget on `/auth/login` (30 attempts a minute, shared with the
  MFA step and the approvals break-glass) now counts an IPv6 client by its
  /64 rather than by its full address, and an IPv4-mapped address as its
  IPv4 address: one host is routinely handed a whole /64, and each address
  in it used to get a budget of its own. Two failed-password ceilings are
  added on top, each over 15 minutes: 20 per submitted username, counted
  by the lower-cased name whether or not an account has it, and 500 across
  the whole install (`LOGIN_FAIL_MAX_PER_USERNAME` /
  `LOGIN_FAIL_MAX_GLOBAL`, `0` turns one off). A right password is not
  counted. A refusal is a `429` with `Retry-After`, the same for a real
  name and an invented one, audited as `login_throttled`. Both fail open
  when Redis is unreachable. **The install-wide ceiling is a bounded denial
  of service by design**: 500 wrong passwords spread across names and
  addresses refuse every password sign-in, a superadmin's included, until
  the 15-minute window ends; existing sessions, API tokens and OIDC / SAML
  sign-in are unaffected. `docs/features/AUTH.md` has the trade-off and
  how to end a refusal early. The sign-in page now says a sign-in was
  throttled instead of reporting a wrong password.
