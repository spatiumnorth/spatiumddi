"""phpIPAM one-shot IPAM importer endpoints (issue #4734).

Exposes ``/ipam/import/phpipam/{test-connection,preview,commit}``, the sister
of the NetBox importer's surface. See :mod:`app.services.phpipam_import` for
the source reader and :mod:`app.services.netbox_import` for the shared commit.
"""

from __future__ import annotations

from .router import router

__all__ = ["router"]
