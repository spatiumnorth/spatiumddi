### Fixed

- An InfluxDB export target now keeps only the secret its version uses: the v1 password or the v2/v3 token. Every create and edit drops the other one, which the form neither showed nor could clear. That covers a version switch, an Add that carried both, and a target saved before this release, which is cleaned on its next save. A changed Base URL asks only for the secret in use. ([#4889](https://github.com/spatiumnorth/spatiumddi/issues/4889))
