### Security

- **Anonymous requests no longer reveal the product version or the
  stack (#2935).** Version and stack details are for signed-in users
  only. `GET /api/v1/version` now gives an anonymous caller a coarse
  handshake, `product: "SpatiumDDI"`, `api_level: 1` and
  `restricted: true`, with the version, the release check and the
  appliance identity withheld (null / false). A signed-in caller,
  session or API token, gets the full answer as before. The appliance
  installer's control-plane probe (#995) now matches on `product`, and
  still accepts an older control plane that sends a version.
  `/api/openapi.json` needs a session or an API token (401 otherwise).
  `/api/docs` and `/api/redoc` still load, then fetch the schema with a
  token from the browser's sign-in cookie, the same silent refresh a
  second console tab makes; signed out, they say so and link to the
  sign-in page. The `openapi.json` release asset (#903) is unchanged.
  `GET /health/platform` gives an anonymous caller the rollup `status`
  only; the component list, which named every Celery worker by container
  id or pod name, needs a signed-in caller. Every nginx we ship sets
  `server_tokens off`: the console image, the chart's TLS config and the
  appliance's agent landing page. DNS servers answer
  `version.bind CH TXT` with `"none"`: BIND9 also stops answering
  `hostname.bind`, and
  PowerDNS answers `id.server` and NSID with `"none"` instead of the
  container hostname, so the liveness checks that dig them still get a
  reply. Technitium already refuses CHAOS queries. The first config
  apply after the agent upgrade reloads BIND9 and restarts PowerDNS once.

### Changed

- **`GET /api/v1/version` is nullable in the published schema (#2935).**
  `version` is `string | null` (null only for an anonymous caller), and
  the response gains `product`, `api_level` and `restricted`. A client
  generated from the release asset needs a one-line change where it
  reads `version`. Tooling that read `/health/platform` components or
  `/api/openapi.json` without a credential must now send one; the perf
  war-room scripts send their admin token.
