### Fixed

- **Forming a cluster from a fresh appliance no longer runs the control
  release under `reinstall` (#2826).** The first promote creates the
  `spatium-control` HelmChartConfig when firstboot's boot-time pin (#1299)
  could not, and it was created with its values alone, so it took the CRD's
  default `failurePolicy: reinstall`, which overrides the HelmChart's
  `retry`. Until the seed's next boot a failed helm upgrade of the control
  release was answered by uninstalling it and installing it again: on a
  fresh three-node formation two override writes 44 s apart did exactly
  that, and the seed refused its web ports for 34 s. The supervisor now
  creates that HelmChartConfig with `failurePolicy: retry`. A
  HelmChartConfig that already exists keeps the policy it has (the boot pin
  still sets `retry` on every boot), and the MetalLB and appliance
  HelmChartConfigs are created as before, under the same policy as their
  charts.
