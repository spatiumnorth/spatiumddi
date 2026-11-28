### Fixed

- The DHCP agent's passive fingerprint sniffer, MAC-sighting sniffer and Router-Advertisement sniffer reported "started" but decoded no frames (every packet was read as raw bytes), so no fingerprints, sightings or RA observations were recorded unless another agent feature happened to load scapy's protocol layers first. They now load the layers before opening their socket and listen on named interfaces. (#5001)
