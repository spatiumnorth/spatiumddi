### Fixed

- **Sync with Servers no longer moves a zone's serial when it sends
  nothing (#3004).** The push phase took the zone's next serial before
  it looked for anything to send, and the group's Sync with Servers,
  the per-server sync and the scheduled DNS server sync commit whatever
  happened, so a sync that imported nothing and pushed nothing still
  raised every zone's serial, once per enabled server. No record op
  carried that serial to an agent-managed server, and in a group
  without views the serial is not part of the agent's bundle, so the
  zone's sync pill read "drift" (server-state `in_sync: false`) until
  the next record change while its Drift tab read "In sync". In a
  group with views every press re-rendered and reloaded every zone
  instead. The serial is now taken only when something is sent: once
  per agentless push, and once per batch of new agent ops, which all
  carry it. A row whose op is still queued from an earlier press adds
  no op and takes no serial, so pressing again before the agent applies
  it no longer leaves the zone one serial ahead of what the server
  will report.
