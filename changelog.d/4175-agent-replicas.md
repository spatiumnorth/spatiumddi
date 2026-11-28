### Added

- Helm chart: a DNS agent entry in `dnsAgents.servers[]` takes `replicas: N` to run N agents from one StatefulSet, each registering as its own server, rolled one at a time. New per-entry knobs `requiredAntiAffinity`, `topologySpreadConstraints`, `podDisruptionBudget` and `groupLabel` (also on DHCP entries, which stay at one replica because Kea HA needs exactly two explicit peers). `replicas` defaults to 1 and renders exactly what earlier releases did.
