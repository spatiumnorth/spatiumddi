### Added

- Backup targets have an "Encrypt the whole archive" option. On, the database dump is encrypted (AES-256-GCM, key derived from the target's passphrase) as well as `secrets.enc`, so an archive on an NFS export, a removable disk or a pull-only token no longer exposes the database to whoever can read the file. It is on for new targets and off for existing ones; restore, the restore preview, selective restore and restore drills accept both formats, and a wrong passphrase or a tampered archive is refused before anything is replayed.
