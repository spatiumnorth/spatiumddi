### Fixed

- The appliance's GRUB recovery boot entry gave no shell on a default install, because it asked for the root password and root is locked. It now asks for a username and password on both the screen and the serial console, accepts the admin account (any member of the `sudo` group; `sudo -i` works) or root when root has a password, and continues the boot when you leave the shell. (#5027)
