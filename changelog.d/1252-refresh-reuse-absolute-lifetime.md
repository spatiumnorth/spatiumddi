### Fixed

- Refresh tokens: presenting an already-rotated refresh cookie after the 10-second grace window now revokes the live session of that rotation chain and writes a `session.refresh_reuse_detected` audit row, instead of a plain 401. Sessions also have an absolute lifetime (`SESSION_ABSOLUTE_MAX_DAYS`, default 30 days from sign-in, 0 disables) that refreshing no longer slides past.
