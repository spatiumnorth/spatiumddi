### Fixed

- The Operator Copilot's `ping_host` tool now refuses targets inside a do-not-probe space, block or subnet (#722) like every other network tool, and is switched off with the Network tools feature module. `tls_cert_check` follows the same module gate.
