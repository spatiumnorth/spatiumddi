### Fixed

- Deleting a DNS server no longer cascades its query log inside the request. The request answers 202 and marks the server "Removing…", a worker removes its operational rows in batches, and the query log and RPZ hits are kept with the server name (the DHCP activity log likewise), aging out with normal retention. The missing index on `dns_rpz_hit.server_id` is added (#4173).
