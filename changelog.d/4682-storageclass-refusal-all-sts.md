### Fixed

- Helm chart: setting `storageClass` on an existing install now refuses once and lists a `kubectl delete sts ... --cascade=orphan` line for every DNS and DHCP agent StatefulSet that needs it, instead of naming one StatefulSet per upgrade attempt (#4682).
