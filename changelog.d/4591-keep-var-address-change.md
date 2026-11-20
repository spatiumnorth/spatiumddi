### Fixed

- A reinstall with "Keep /var and STATE" on a node whose address changed (new hardware, VM or NIC, so a new DHCP lease) no longer leaves k3s refusing its own etcd member and the node down: a single-node control plane now resets its etcd peer address once on first boot (`k3s server --cluster-reset`, logged on the console), while a multi-member etcd is left alone with the reason printed. The installer's confirm screen notes this for DHCP. (#4591)
