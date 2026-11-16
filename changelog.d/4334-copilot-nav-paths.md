### Fixed

- The Copilot's `find_control_plane_vip` and `find_etcd_snapshots` tool descriptions sent operators to a "Fleet → Control plane" section that does not exist; they now name Appliance → Network & Host and Appliance → Cluster → etcd snapshots, and the other appliance and firewall tool descriptions, the system prompt and the appliance docs use the real Appliance tab names (#4334).
