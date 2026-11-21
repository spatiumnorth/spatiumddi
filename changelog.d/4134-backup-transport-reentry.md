### Fixed

- Changing a backup destination's transport settings to a weaker setting (FTPS to plain FTP, TLS certificate verification off on FTP, WebDAV or HTTPS upload, SSH host-key checking off or a replaced known_hosts on SCP) now asks for the destination's stored credential again, as changing its host does.
