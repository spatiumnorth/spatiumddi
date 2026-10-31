### Fixed

- **The chart's api autoscaler no longer runs 10 idle api replicas on any
  cluster with a metrics-server (#3110).** It aimed memory at 80 % of a
  256Mi request, about 205 MiB, while one api process holds about 300 MiB
  as soon as it has started. The HPA took an idle install from 2 to 10
  replicas within two minutes and kept it there, because a process's memory
  does not fall as replicas are added. The HPA now scales on CPU (memory
  is opt-in, `api.autoscaling.targetMemoryUtilizationPercentage`), and the
  api's defaults hold its measured use: requests 200m / 512Mi (were 100m /
  256Mi) and a 1Gi memory limit (was 512Mi). An idle install stays at 2
  replicas. `make charts-lint` fails a default render whose autoscaler aims
  below one api pod's measured use, or whose api memory request or limit
  is below it. **Upgrade note:** `--reuse-values` keeps the old defaults,
  so upgrade once with `--reset-then-reuse-values`. The appliance keeps
  the limits it sizes from the node and takes the new requests.
