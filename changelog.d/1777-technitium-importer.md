### Fixed

- The Technitium importer no longer offers Technitium's built-in internal zones (`localhost`, the loopback reverse zones), follows paginated zone lists, accepts an API URL ending in `/api`, and has a TLS-verification toggle for self-signed servers. The SOA mailbox is converted from Technitium's email form (`hostmaster@example.com`) to the domain form SpatiumDDI stores instead of being stored with an `@` that BIND9 rejects, and a plan naming a managed Technitium (API) server as its source is now accepted so the commit does not push records back to it.
