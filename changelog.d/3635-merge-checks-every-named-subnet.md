### Fixed

- Subnet merge preview and commit now require write permission, and any API token resource binding, on every subnet named in the request, not only the one in the URL; a subnet that is missing and one the caller may not write get the same refusal.
