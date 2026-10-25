### Fixed

- **An api pod already in service stays ready while a newer release
  migrates the database (#2777).** On a rolling upgrade the new
  release's migration commits while the previous release's api pods
  still serve. `/health/ready` used to read any revision but its own
  head as "schema behind" and answer 503, so every old pod left the
  Service at once and the api answered 502 until the first new pod was
  ready (about 80 s on a three-node roll). A revision the image's
  migrations do not contain is now told apart as *ahead*: a pod that
  has already been ready at its own head keeps serving there, with
  `checks.schema` reading `ok: …` and naming both revisions. A pod that
  never was (a new pod of an older release, a restarted container), a
  schema behind the image and an unstamped one still answer 503. Each
  change of schema state is logged once (`readiness_schema_mismatch`,
  warning; `readiness_schema_at_head`, info), so a 503 is no longer
  silent. A one-node control plane under `hard` anti-affinity replaces
  its only api pod first and still has its brief outage per rollout.
