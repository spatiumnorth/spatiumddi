### Changed

- **Upgrade-image uploads and backup uploads check the caller before
  reading the body.** FastAPI reads a request body before it runs the
  route's dependencies, and nginx admits up to 4 GiB on
  `/api/v1/appliance/upgrade-images` and 2 GiB on `/api/v1/backup/`, so
  a request the api was going to answer 401 or 403 was still received
  in full first: a multipart file spooled onto the api pod's node, a
  JSON body held in memory. Every route on those two locations that
  takes a body now runs its own superadmin and permission checks from
  the request headers before reading anything, with the same 401 / 403
  answers and the same `denied` audit row. The receiving node's
  free-space check now runs after authorisation, and an upgrade-image
  upload without a `Content-Length` header is answered **411** instead
  of being buffered without that check. Browsers, `curl -F` and the
  common HTTP client libraries send one, so the Fleet upload dialog is
  unaffected.
