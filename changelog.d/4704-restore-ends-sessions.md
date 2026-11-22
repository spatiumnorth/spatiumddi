### Fixed

- A backup restore now ends every session, as its notice says. The archive's copy of the session table replaced the live one, so a session revoked after the archive was made, and every session live when it was made, was accepted again, access and refresh tokens alike. Full restores, and selective restores that reach the auth data, now revoke every restored session, from an uploaded archive or a backup target, and the audit entry records how many were ended. Sign in again after a restore.
