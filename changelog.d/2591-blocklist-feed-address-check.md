### Fixed

- **A DNS blocklist feed URL goes through the outbound address check.** The
  feed was fetched with redirects followed automatically and no check on
  where the URL pointed. It now uses the same guard as the other
  operator-configured fetches, shared with the WoL calendar feed: `http` or
  `https` only, and loopback, link-local (including the cloud metadata
  address) and the unspecified address are refused when the list is saved,
  before each fetch, when the connection is opened, and on every redirect
  hop. Private (RFC 1918) addresses are still allowed, so an internal feed
  mirror keeps working. A failed fetch now records only the HTTP status or
  the kind of failure on the list, never the error text or the URL, and the
  worker log names the feed by scheme and host only. The fetch no longer
  uses `HTTP_PROXY` / `HTTPS_PROXY` from the worker's environment.
