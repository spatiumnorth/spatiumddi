### Fixed

- **A supervisor's signed request now binds the whole request, and is
  accepted once (#3631).** The signature an appliance's supervisor sends
  with its heartbeat, kubeapi-proxy, network-tool, storage and packet
  capture requests covered only the method, the path and a timestamp, so
  the same headers were accepted again for five minutes with any body or
  query string. It now also covers the query string and a SHA-256 of the
  body (a packet capture upload is checked against it before the file is
  kept), carries a nonce, and the control plane remembers each accepted
  signature in Redis and refuses a repeat with 401. If Redis cannot be
  reached the repeat check is skipped with a warning, so heartbeats keep
  flowing through a Redis failover. The k3s join token for a node being
  promoted is no longer returned in clear: the supervisor sends a one-off
  key in its signed heartbeat and the token comes back sealed to it.
  Supervisors on older builds keep working while
  `APPLIANCE_LEGACY_SIGNATURE_ALLOWED` is true (the default); each one is
  logged as `appliance_cert_auth_legacy_signature`, and it is not handed
  a join token until it is upgraded.
  A current supervisor talking to an older control plane (a remote
  appliance paired to one, or any node between its slot upgrade and the
  application roll) signs the older form after the first heartbeat answer
  shows the control plane does not check the new one, so the kubeapi,
  network-tool, storage and capture channels keep working through an
  upgrade. A promote of an appliance whose supervisor is too old to receive
  the sealed token is refused with a message saying to upgrade it first.
