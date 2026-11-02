### Fixed

- The reservation expiry sweep now recounts the subnet and block utilization figures in the same pass that frees an address (#3320); the IPAM page refetches block figures after an address write such as Bulk allocate (#3325); and the IPAM tree's dots and bars draw amber and red from Settings' Warning and Critical Thresholds instead of fixed 80% and 95% (#3327).
