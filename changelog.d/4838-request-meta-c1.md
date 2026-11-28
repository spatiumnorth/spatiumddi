### Fixed

- The request metadata cleaner now also drops C1 control characters (U+0080 to U+009F) from the User-Agent stored on sessions and audit rows, and from the Host and `X-Forwarded-Prefix` values it logs. It already dropped C0 controls and DEL; this matches the DNS record value check fixed in #4483.
