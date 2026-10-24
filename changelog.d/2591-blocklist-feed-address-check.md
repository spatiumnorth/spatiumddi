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
- **Credentials in a DNS blocklist feed URL are used for the fetch only.** A
  feed URL with a password or a `?token=` in it was returned in full by the
  blocklist API and the `list_dns_blocklists` copilot tool, and a failed
  fetch (a 404, say) wrote the full URL into the worker log through Celery's
  retry and failure lines and its stored task result. The API, the UI and
  the copilot now show the URL with those values replaced by `***`, and a
  failed fetch raises an error naming only the HTTP status or the kind of
  failure. Saving a list with the masked URL unchanged keeps the stored
  one; a URL that still contains `***` in a credential position is refused,
  so the mask is never stored as the credential. The WoL calendar feed,
  which shares the fetch, gets the same error message.
