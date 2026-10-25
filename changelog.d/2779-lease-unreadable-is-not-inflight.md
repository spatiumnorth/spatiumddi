### Fixed

- **An unreadable upgrade lease is no longer reported as another upgrade in
  flight (#2779).** When the Kubernetes API did not answer the read of the
  upgrade lease, the pre-flight failed `inflight_conflict` with holder
  `<unreachable>`, and `POST /api/v1/upgrades/plan` answered 409 `preflight
  failed; refusing to plan: inflight_conflict`, sending the operator to look
  for a run that did not exist. Pre-flight now reports a separate failing
  check, `kubeapi_unreachable`, naming the lease read and saying the API could
  not be reached; the plan's 409 carries that message. A lease another run
  really holds still reports `inflight_conflict`.
