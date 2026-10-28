### Fixed

- The appliance console header no longer reads CRITICAL / DEGRADED forever
  because of lifetime counters. Every node reboot adds one to every pod's
  restart count, and etcd's failed-proposal counter never goes back down,
  so a healthy box could stay red or amber for the life of the pod. The
  console now keeps its own baseline and judges the increase inside a
  window: a pod that restarted 3 or more times in the last 15 minutes is
  flapping (red), 1 or 2 is amber, and etcd write failures only count when
  the counter rose in the last 10 minutes. The first sample is the
  baseline, so a counter that was already high when the console started
  (including after a reboot) is not an alarm. The lifetime totals are still
  shown, dimmed, in the RST column and the etcd panel. A pod in
  CrashLoopBackOff and similar states is still red. (#2928)
