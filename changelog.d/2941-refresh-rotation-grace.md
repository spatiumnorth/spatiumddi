### Fixed

- **Two console tabs refreshing at once no longer log the operator out
  (#2941).** A refresh rotates the session, and the tabs of one browser
  share the refresh cookie, so when one tab refreshed every other tab's
  access token stopped working at once, and two tabs refreshing together
  with the same cookie left one of them with a 401 and sent the operator
  to the sign-in page. A rotation now has a 10-second grace window: a
  refresh presenting the cookie that was just rotated gets a new access
  token for the same successor session (it does not mint a third one or
  set another cookie), and an access token for the rotated session keeps
  working for those 10 seconds. Concurrent refreshes take a row lock, so
  they land on one successor. After the window a rotated cookie is
  refused with a 401, as before. The grace applies only to rotation:
  signing out, a force-logout from the session viewer, a password change
  and disabling the account end the session at once, for the old cookie
  and the old access token alike. A password change made from a tab
  whose token is inside the window now keeps that tab's current session
  instead of revoking it.

### Migrations

- `c4f81e2a9d37` — #2941, adds the nullable `user_session.rotated_at`
  and `user_session.rotated_to_id`, which mark a session as revoked by
  a refresh rotation and name its successor. No backfill.
