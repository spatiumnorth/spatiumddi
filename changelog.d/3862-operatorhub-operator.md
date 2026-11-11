### Added

- **A SpatiumDDI Operator for OperatorHub (#3862), opt-in and not yet
  published.** A Helm-based operator in `operator/` turns a
  `SpatiumDDI` custom resource (whose spec is the chart's values) into
  a chart release, with an OLM bundle for OpenShift's OperatorHub and
  OperatorHub.io (capability level II, Seamless Upgrades; OwnNamespace
  and SingleNamespace; channels `stable` and `candidate`). `make
  operator-bundle VERSION=x.y.z COMMUNITY=<dir>` lays the bundle out
  for the two community catalogs. The chart gains
  `migrate.nameByContent` (default `false`), which names the migrate
  Job after a hash of its inputs instead of the Helm revision; the
  Operator sets it so its periodic reconcile does not upgrade the
  release, and re-run the migration, every time. The chart also gains
  `dnsAgents.agentKey.generate` and `dhcpAgents.agentKey.generate`
  (default `false`), which mint and keep a random agent key when none
  is given; the Operator sets them. Nothing changes for
  existing installs, and the image is published only when the
  repository variable `OPERATOR_PUBLISH` is `true`. Not yet tested
  through OLM on a real cluster. See `docs/deployment/OPERATOR.md`.
