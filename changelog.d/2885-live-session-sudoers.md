### Fixed

- **The live ISO's session sudoers rule no longer reaches an installed
  appliance.** The installer ISO boots with Debian's live-config, whose
  `sudo` component writes `/etc/sudoers.d/live`
  (`user ALL=(ALL) NOPASSWD: ALL`) on every live boot. The installer
  copied the live root, that file included, onto the target disk and
  into the `/etc` baseline of both OS slots. No `user` account exists on
  the appliance, so the rule named nobody, but it should never have been
  there. The image no longer ships live-config's account components
  (`0030-user-setup`, `0030-live-debconfig_passwd`, `0040-sudo`), the
  installer leaves the file and live-config's `/var/lib/live/config`
  markers behind, and on existing installs `spatium-etc-reconcile`
  removes the file at boot when its whole content is that one line,
  logging what it removed. A file with any other content is kept. `user`
  and `debian` are now refused as the admin username, in both the wizard
  and the preseed validator, as names reserved by the live installer.
