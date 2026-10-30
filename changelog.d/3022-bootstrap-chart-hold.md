### Fixed

- **A cluster Rolling Upgrade no longer rolls the supervisor and the
  CNPG operator before it moves the image tags (#3022).** The run holds
  the bootstrap chart's image tag until every node runs the target, but
  that hold covered the chart's values, not the chart: the seed's boot
  onto its new slot wrote the new bootstrap chart live, and a release
  whose chart changed the supervisor DaemonSet or the CNPG operator pod
  template rolled them on the old image mid-run, the operator while the
  database primary may be moving and the supervisor that reports each
  node's upgrade state. While a run's hold is on, the seed now keeps
  the new bootstrap chart back as it does the control chart (#2865), and
  releases it when the hold ends, before the control chart: at the end
  of the run, or, for a run that failed or was aborted, when its hold is
  released. Fresh installs, single-node installs and node-by-node
  upgrades set no hold and are unchanged, except that an upgraded node's
  new bootstrap chart goes in once k3s is ready instead of while it
  starts.
