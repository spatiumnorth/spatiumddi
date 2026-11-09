### Fixed

- Moving a DNS zone between two server groups whose agentless servers (Technitium API, Windows DNS, Route 53, Cloudflare, Azure DNS, Google Cloud DNS) reach the same provider no longer deletes the zone at that provider. The source-group delete is now skipped for any server that shares a provider with a target server, or whose provider cannot be identified, and the move preview lists each source copy it will keep.
