### Fixed

- DNS catalog zones: the consumer's `producer_addr` is now an IP (the producer's host if it is one, else its last seen IP), and the BIND9 agent refuses to render a hostname into `default-masters`, which BIND rejects and which stopped the whole group converging (#3764).
