### Fixed

- **A RADIUS server that never answers is logged as a timeout (#2828).**
  pyrad raises its own `Timeout`, which is not the builtin `TimeoutError`,
  so a silent server fell through to the protocol-error branch and was
  logged as `radius_target_protocol_error` with an empty reason. When
  every server was silent, the login and Test connection error was that
  same empty text. A silent server now logs `radius_target_unreachable`
  and the error reads "no reply from host:port after N retries". The
  protocol-error message also names the exception type when the exception
  has no text of its own. Failover to the next server is unchanged.
