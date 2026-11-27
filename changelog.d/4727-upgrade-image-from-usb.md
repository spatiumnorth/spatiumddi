### Fixed

- Air-gapped appliances can now take an upgrade from a USB stick. Put the release's versioned slot image and its `.sha256` on a stick, mount it under Removable storage, and use Fleet, Upgrade images, From USB to import it without a browser upload. The image goes through the same verified store as an upload (size limit, architecture check, checksum), and anything that fails is refused with a reason. Release images are not signed, so the published checksum is the only integrity check. (#4727)
