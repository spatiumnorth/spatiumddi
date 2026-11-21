### Fixed

- A rolling upgrade's Start could answer 200 and leave the run `planned` for good, with no error shown, when the drive's first read of the upgrade Lease met a kubeapi 503 or refused connection (for example while k3s restarts). That read now retries for the same short budget the Plan's kubeapi reads use, and if the Lease still cannot be read the reason is written to the run's last error and event list, and the run stays `planned` so Start can be pressed again. (#4512)
