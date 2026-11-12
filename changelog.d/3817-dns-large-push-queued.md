### Fixed

- A zone move or Sync with Servers on an agentless DNS server (cloud providers, Technitium API) no longer pushes a large zone's records one provider call at a time inside the request, which could outrun the reverse-proxy timeout. Above 200 missing records they are queued as record ops and delivered, with retry, in the background; smaller zones still push inline (#3817).
