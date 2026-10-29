### Fixed

- **Appliance host runners no longer write through a name another
  writer prepared.** The release-state directory is mode 1770: the api
  and the supervisor can create names in it, and the root host runners
  wrote their lock, status, hash and state files there by plain
  redirect, by a fixed temp name, or with `mv` onto a predictable name.
  A symlink at such a name made root create, truncate or re-mode the
  file it pointed at; a directory, or a link to one, received the
  renamed file. Every runner now writes these files under a fresh
  `mktemp` / `mkstemp` name and renames it over (`mv -T`,
  `os.replace`), which replaces whatever is at the name and never
  writes through it. The firewall auto-revert keeps its lock in `/run`,
  and restores only a snapshot and deadline it wrote itself. The packet
  capture and storage runners work from inside their directories (which
  the supervisor owns), start Python isolated (`python3 -I`) so nothing
  in that directory is imported, create the capture
  `O_EXCL|O_NOFOLLOW`, and keep tcpdump's stderr in a private temp file. The trigger guard, the slot
  runners, the k3s token publisher and the reboot unit rename with `-T`; the slot
  sidecars are re-moded only when root owns them; firstboot re-modes the
  capture directory from inside it. A cluster join keeps its k3s
  identity backup in a fresh `mktemp -d` directory, and a leave restores
  parked bootstrap manifests only from a directory nobody else can
  write. The removable-disk prepare step refuses a `spatiumddi` symlink
  on the disk, and `spatium-pair` removes the supervisor's pinned
  certificates only from a `tls/` directory that resolves to itself.
