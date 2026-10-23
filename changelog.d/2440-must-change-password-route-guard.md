### Fixed

- **A user who must change their password was shown the console, every read
  refused, after a reload or a typed URL (#2440).** Only the login form sent
  them to Change Password; the route guard checked just that they were signed
  in and the boot-time session restore dropped `force_password_change`. The
  flag is now kept with the session (login, MFA, OIDC callback, boot and
  interceptor refresh) and every protected route redirects to
  `/change-password` until the change is made.
