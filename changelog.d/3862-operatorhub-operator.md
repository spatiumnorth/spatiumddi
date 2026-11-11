### Added

- **A SpatiumDDI Operator for OperatorHub (#3862), opt-in and not yet
  published.** A Helm-based operator in `operator/` turns a
  `SpatiumDDI` custom resource (whose spec is the chart's values) into
  a chart release, with an OLM bundle for OpenShift's OperatorHub and
  OperatorHub.io (capability level II, Seamless Upgrades; OwnNamespace
  and SingleNamespace; channels `stable` and `candidate`). `make
  operator-bundle VERSION=x.y.z COMMUNITY=<dir>` lays the bundle out
  for the two community catalogs. Nothing changes for existing
  installs, and the image is published only when the repository
  variable `OPERATOR_PUBLISH` is `true`. See
  `docs/deployment/OPERATOR.md`.
