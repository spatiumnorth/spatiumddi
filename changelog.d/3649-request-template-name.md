### Fixed

- A request naming an IPAM template now carries the template's name from the server, so the Requests page no longer looks the template up (a 403 for the built-in Requester and Change Approver roles) and shows the name instead of the raw id; only the name is exposed (#3649).
