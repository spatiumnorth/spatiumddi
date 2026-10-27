### Fixed

- **The plain-Kubernetes HA manifest no longer restarts the database
  primary under its clients on a rolling update (#2831).**
  `k8s/ha/postgres-cluster.yaml` now sets CloudNativePG's
  `primaryUpdateMethod: switchover`, as the Helm chart has since #2861,
  so a rolling update (a new image, a resources change, a parameter that
  needs a restart, `kubectl cnpg restart`) promotes an already-updated
  replica before it touches the primary. Left on CNPG's default
  `restart`, the operator restarted the primary while it served, and its
  smart shutdown refused every new connection for the full 180 s
  `smartShutdownTimeout`, because pooled sessions never end: on the
  manifest's CNPG 1.24.0 with four idle pooled sessions, 186 to 194 s
  without a new login, against 6 to 7 s with the switchover. The field is
  not part of the instance pods' spec, so applying the manifest to a
  running cluster rolls nothing.
