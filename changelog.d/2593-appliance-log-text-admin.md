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
