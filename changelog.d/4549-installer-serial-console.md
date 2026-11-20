### Fixed

- The appliance installer now runs on the serial console as well as `tty1`, so IPMI Serial-over-LAN, headless servers and serial-only VMs can be installed interactively instead of showing GRUB and then nothing. Whichever console answers the Welcome screen first runs the install and the other says where it is running; preseeded installs still run on `tty1` only. The rescue / diagnostics boot also shows its SSH address and one-time password on `ttyS0`. (#4549)
