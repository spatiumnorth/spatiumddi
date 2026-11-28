### Fixed

- The appliance installer now logs a warning when a headless (preseed) control-plane install targets a disk below the recommended 40 GiB, instead of installing silently and hitting kubelet DiskPressure on first boot. Interactive installs already prompted; agent-only nodes keep the 32 GiB floor. (#4661)
