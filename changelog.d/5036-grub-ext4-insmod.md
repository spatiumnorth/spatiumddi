### Fixed

- The appliance's GRUB menu no longer prints `error: file '/grub/i386-pc/ext4.mod' not found.` before every boot. GRUB has no `ext4` module (its `ext2` module reads ext4), so the rendered grub.cfg no longer loads one. The boot always went on; the message only made a healthy boot look broken. (#5036)
