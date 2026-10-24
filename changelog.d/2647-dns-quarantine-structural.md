### Fixed

- **DNS agent re-applied a broken config on every record change (#2647).** The DNS agent's bad-config quarantine is now keyed on the bundle's structural etag, not its full etag. A record-only change (a DDNS update, a UI edit) no longer clears the quarantine and re-renders, re-validates and reloads the same broken structure, resets the 60 s / 5 min / 15 min backoff, or burns record-op retry attempts. A quarantine file written by an older agent still loads and matches on the full etag.
