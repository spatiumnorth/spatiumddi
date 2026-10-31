### Fixed

- **The Helm chart no longer renders the api's replica count while the
  api autoscaler is on, so `helm upgrade` succeeds and keeps the count the
  autoscaler set (#3111).** Helm 4 applies server-side, and the rendered
  `replicas` made Helm an owner of the field the HPA writes through the
  `scale` subresource. Once the HPA had scaled, every upgrade failed with
  `conflict with "kube-controller-manager" with subresource "scale" using
  apps/v1: .spec.replicas` and left a failed revision. Under Helm 3 each
  upgrade put the count back to `api.replicas` instead. The chart now
  renders `replicas` only with `api.autoscaling.enabled: false`, as the
  appliance sets it, and `make charts-lint` fails a render that gives an
  autoscaled workload a replica count. **Upgrade note:** where the HPA
  never scaled (no metrics-server, say), and on any client-side (Helm 3)
  release, this one upgrade sets the count to 1 until the HPA's next sync,
  about 15 s; the chart README has the hand-over that avoids it under
  Helm 4. On a release installed from an older chart, turning the
  autoscaler off later can need `--force-conflicts` on that one upgrade.
