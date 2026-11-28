"""phpIPAM one-shot IPAM importer (issue #4734).

A migration tool, not a continuous reconciler: it reads a live phpIPAM
instance through its REST API and builds native IPAM rows through the same
preview -> (stateless round-trip) -> commit machinery the NetBox importer
(#36) uses. The reader half lives here; the canonical IR and the commit
pipeline are the NetBox package's, shared on purpose (the commit stamps the
plan's ``source``, ``phpipam``, on every row it writes).

* :mod:`.client` -- async ``httpx`` client (app-code token or user/password
  auth, envelope handling, bounded responses, retry, TLS verify).
* :mod:`.fetch` -- per-controller pulls.
* :mod:`.mapping` -- pure phpIPAM-shape -> IR mappers.
* :mod:`.preview` -- ``preview_phpipam_import`` (read-only, conflicts flagged).
"""

from __future__ import annotations

from .client import MAX_RESPONSE_BYTES, PULL_CEILING, PhpipamClient, PhpipamClientError
from .preview import preview_phpipam_import

__all__ = [
    "MAX_RESPONSE_BYTES",
    "PULL_CEILING",
    "PhpipamClient",
    "PhpipamClientError",
    "preview_phpipam_import",
]
