### Fixed

- **A blocklist edit no longer reloads the whole RPZ zone (#4041).**
  The BIND9 agent now applies a changed list as RFC 2136 adds and
  deletes against what named already holds, instead of rewriting the
  zone file and reloading it, so named no longer holds the old and the
  new zone in memory together. The full reload remains the fallback
  (first apply, revert, views, no group key, a refused update, or a
  change of more than 50,000 lines).
