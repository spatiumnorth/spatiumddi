### Fixed

- **Fleet's "Service lifecycle apply failed" banner no longer blames
  docker compose (#3295).** When an appliance's role apply failed, the
  banner said the supervisor's `docker compose` returned a non-zero
  exit and that "the previous container state remains", though since
  #183 Phase 7 the supervisor applies roles through the appliance's
  Kubernetes API (k3s) and the reason printed under the banner names
  the kube API (for example `kubeapi /readyz not ok`). The banner now
  says the supervisor could not apply the assigned roles through the
  appliance's Kubernetes API, that it tries again on the next
  heartbeat, and to check k3s over SSH if the reason persists. The
  reason line under it is unchanged.
