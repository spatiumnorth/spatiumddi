### Fixed

- The Delete DNS Server and Delete DHCP Server dialogs no longer promise the server is removed from management. They now say a still-running agent registers the server again on its next heartbeat (waiting for approval where agent approval is required), that you should stop or uninstall the agent first to remove it for good, and link the recovery recipe in Troubleshooting (#4292).
