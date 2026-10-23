### Fixed

- **A Rolling Upgrade node rides out a transient CNPG admission
  answer instead of failing the run (#2449).** A node's
  `cnpg_maintenance_on` step PATCHes the CloudNativePG Cluster once.
  When that node's turn cordons and drains the node the operator pod
  runs on, CloudNativePG's mutating webhook (`mcluster.cnpg.io`,
  failurePolicy Fail) is briefly between endpoints, so the API server
  answers the PATCH with a 500 ("failed calling webhook"). A single
  try failed the step and ended the whole three-node run. The step
  runner already retried a step that lost its database connection
  (#2177); it now also retries one that returned a transient kubeapi
  answer (a 5xx, 408, 409 or 429, or a socket error that never
  reached the server), in place, for up to five minutes from the
  first such answer, the way the shared-tag writes do (#2056). Only
  the idempotent per-node writes retry, cnpg_maintenance_on, cordon
  and uncordon, and only a kubeapi helper's own answer: a permission
  refusal, a sub-500 status, and a non-kubeapi error still fail at
  once, and an answer that never clears fails the step with the
  server's own error once the budget is spent.
