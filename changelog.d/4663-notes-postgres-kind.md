### Fixed

- The Helm chart's post-install notes now describe the Postgres the release actually uses (CloudNativePG, the in-chart StatefulSet or an external database) and the right Secret for its password, instead of always saying "Bitnami-managed".
