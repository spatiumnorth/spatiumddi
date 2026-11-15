### Fixed

- A BIND9 DNS pod no longer answers blocked names normally for the first 5 to 11 seconds after it starts: the rendered `response-policy` now carries `servfail-until-ready yes`, so named returns SERVFAIL until the policy zones have loaded (a zone that fails to load does not hold named back) (#4064).
