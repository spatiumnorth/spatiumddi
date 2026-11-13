### Fixed

- A DNS import commit into a group served by an agentless server (Technitium API, Windows DNS, a cloud provider) now creates the zone at that server before the imported records are sent, instead of failing the records with "No such zone" or writing them into an enclosing zone. Sync with Servers no longer tries to create every zone in the group when the server's zone list could not be read, and no longer lists a zone the server already held as pushed.
