### Fixed

- The supervisor's state on the appliance's STATE partition was owned by ids (uid 100 / gid 101) that belong to host system accounts. The supervisor now runs as dedicated ids (10001:10001), existing state is re-owned on the first start after upgrade, and the host trigger guard and capture directory use the new ids.
