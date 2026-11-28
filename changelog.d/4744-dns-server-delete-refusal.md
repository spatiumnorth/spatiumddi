### Fixed

- A refused "Delete DNS Server" (for example 404 "Server not found" when the server was removed elsewhere while the confirm was open) left the second step open, unchanged and silent. It now shows the server's reason inside the confirm, in an announced alert. (#4744)
