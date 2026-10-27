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
  markers behind, and on existing installs the file is hidden from both
  slots. A slot upgrade replaces only one slot's `/etc` baseline, so the
  other slot would bring the rule back on a rollback; a new boot step,
  `spatium-etc-premount`, runs after `/var` is mounted and before the
  `/etc` overlay is, and writes an overlay whiteout for
  `sudoers.d/live` into the upper layer both slots share, so neither
  slot's baseline can show it. It does nothing when the upper already
  holds a file of its own at that path, so an operator's
  `/etc/sudoers.d/live` is kept, and it logs what it changed. `user`
  and `debian` are now refused as the admin username, in both the wizard
  and the preseed validator, as names reserved by the live installer.
