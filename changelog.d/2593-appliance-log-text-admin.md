### Changed

- **Appliance log text takes `admin` on `appliance`, and is redacted.**
  The host log viewer (`GET /appliance/diagnostics/logs` and
  `/logs/{name}`) and pod logs (`GET /appliance/containers/{name}/logs`,
  its `/logs/stream`, and `/containers/workloads/{component}/logs/stream`)
  required only `read` on `appliance`, so any read-only role could read
  raw log lines, which can carry whatever a process printed. They now
  require `admin` on `appliance`, the permission the diagnostic bundle
  already takes, and a running stream re-checks that same permission, so
  cutting a role back to `read` ends it. Every line is also passed
  through the support bundle's secret redaction (URL credentials, keys,
  tokens, password hashes) before it is sent. The pod list, the cluster
  health view and the self-test stay on `read`; the console hides the
  log viewer, the diagnostic bundle card, each pod's Logs button and the
  Cluster live log pane for a role without `admin`. **Custom roles that
  grant only `read` on `appliance` lose log access**; grant `admin` on
  `appliance` to a role that should keep it. The builtin Viewer role is
  read-only and is affected the same way.
- **Log redaction covers keyword credentials and keys split across lines.**
  The redaction now also replaces a credential written as `key=value` or
  `key: value` (a libpq keyword DSN such as `host=db password=…`, an
  ADO-style `Pwd=…;`, `PGPASSWORD=…`, a JSON or YAML `password` field),
  and an OpenPGP private key block. A private key whose text holds only
  its BEGIN or only its END line (a log tail that starts or stops inside
  the key) loses the body lines next to that marker. The one-shot views
  (the host log viewer, a pod's log fetch, the Fleet pod-log view and the
  diagnostic bundle's pod tails) read back up to 256 lines before their
  window and trim after redacting, so a window that falls wholly inside a
  key, with neither marker in it, is still recognised and redacted. The pod log streams
  keep the redaction state between lines, since a key arrives one line at
  a time and was previously sent with only its BEGIN line replaced. The
  Fleet pod-log view (superadmin) is redacted the same way, and the
  diagnostic bundle picks up the new forms. A pod log stream that
  prints nothing also ends within the re-check interval once its caller
  loses access, instead of staying open until its next line.
