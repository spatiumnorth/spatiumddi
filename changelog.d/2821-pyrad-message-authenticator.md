### Changed

- **RADIUS sign-in now uses pyrad 2.6.0, which adds a
  Message-Authenticator to every request (#2821).** Each Access-Request
  carries a Message-Authenticator attribute, and a reply whose
  Message-Authenticator is wrong, or which carries a Proxy-State the
  request did not send, is discarded. A RADIUS server that mishandles
  the attribute therefore shows up as a timeout (logged as
  `radius_target_unreachable`), not as a reject. FreeRADIUS 3.2 works
  unchanged. If a server stops answering after the upgrade, enable
  Message-Authenticator support on it, or check that its shared secret
  matches.
