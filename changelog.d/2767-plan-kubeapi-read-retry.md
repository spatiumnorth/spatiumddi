### Fixed

- **Planning a rolling upgrade rides out a refused kubeapi connection
  (#2767).** `POST /api/v1/upgrades/plan` read the appliance nodes with one
  request. The api reaches kubeapi through the `kubernetes` Service, which
  spreads each new connection across the control-plane nodes' API servers, so
  while one server restarted k3s a new connection could be refused and the plan
  answered 409 `kubeapi unreachable` with two of three servers up. The node
  read, the CloudNativePG cluster detection, and the quorum and
  upgrade-lease reads of the pre-flight (the Plan's and `GET /upgrades/preflight`)
  now try again for up to 30 s on a refused or unanswered connection or a
  408 / 409 / 429 / 5xx, on the same classifier the rolling run's writes use
  (#2449). A kubeapi that is still unreachable after that answers 409 with the
  same message as before; a 403 or other permanent answer is not retried.
  Before, a refused lease read also failed the plan with "another upgrade is in
  flight (lease held by '<unreachable>')", and a refused CNPG read silently
  dropped the maintenance window from the plan.
