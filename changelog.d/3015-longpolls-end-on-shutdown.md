### Fixed

- **Stopping an api pod no longer answers open long-polls with a 500 and
  a traceback (#3015).** uvicorn cancels in-flight requests 20 s after
  SIGTERM (#2944), but the DNS / DHCP / Looking Glass config long-polls
  and the supervisor's heartbeat, nettool, storage and kubeapi-proxy
  polls hold for up to 30 s, so a poll opened in the last 10 s before a
  stop was cancelled into a `CancelledError` traceback and a 500 to the
  agent. The api now notes SIGTERM the moment it lands (a wrapper around
  uvicorn's handler, installed at lifespan startup) and every long-poll
  wait ends at once with its ordinary "nothing new" answer: 304 for the
  config polls, the empty shape for the supervisor's command polls and a
  normal response for the heartbeat. Clients re-poll another pod
  immediately. A poll that arrives after the signal does not wait at all.
  The ETag compare still decides what is served; the stop only ends the
  wait. The holds themselves stay at 30 s.
